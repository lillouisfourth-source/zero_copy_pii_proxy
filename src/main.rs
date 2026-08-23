#![deny(warnings)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use base64::Engine;
use dotenvy::dotenv;
use ed25519_dalek::SigningKey;
use metrics_exporter_prometheus::PrometheusBuilder;
use notify::{recommended_watcher, Event, RecursiveMode, Watcher};
use tokio::sync::Semaphore;
use tower::limit::ConcurrencyLimitLayer;
use tower::ServiceBuilder;

use reqwest::Client;
use zero_copy_pii_proxy::engine::PiiVault;
use zero_copy_pii_proxy::{active_sse_streams, make_metrics_router, make_router, AppState};

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt::init();

    // Build a recorder and install it as the global metrics recorder. Obtain a handle for /metrics
    let recorder = PrometheusBuilder::new().build();
    let handle = recorder.handle();
    metrics::set_boxed_recorder(Box::new(recorder)).expect("failed to set metrics recorder");
    let prometheus_handle = Arc::new(handle);

    // Load 12-factor configuration from environment
    let proxy_port = std::env::var("PROXY_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(3000u16);
    let upstream_url = std::env::var("UPSTREAM_API_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());
    let allowed_origins = std::env::var("ALLOWED_ORIGINS")
        .ok()
        .map(|origins| {
            origins
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let pii_source = std::env::var("PII_CONFIG_PATH")
        .ok()
        .map(PathBuf::from)
        .and_then(|path| {
            std::fs::read_to_string(&path)
                .ok()
                .map(|content| (path, content))
        })
        .map(|(path, content)| {
            tracing::info!(path = %path.display(), "loaded PII rules from config path");
            content
        })
        .unwrap_or_else(|| {
            std::env::var("PII_PATTERNS").unwrap_or_else(|_| "password,secret,ssn".to_string())
        });
    let (pattern_values, replacement_values) = parse_pii_config(&pii_source);
    let patterns_refs: Vec<&str> = pattern_values.iter().map(String::as_str).collect();
    let replacements_refs: Vec<&str> = replacement_values.iter().map(String::as_str).collect();
    let vault = Arc::new(ArcSwap::new(Arc::new(PiiVault::new(
        &patterns_refs,
        &replacements_refs,
    ))));

    let proxy_private_key = std::env::var("PROXY_PRIVATE_KEY")
        .ok()
        .and_then(parse_private_key)
        .unwrap_or_else(|| {
            panic!("PROXY_PRIVATE_KEY must be configured as a valid 32-byte hex or base64 seed")
        });

    // Read API key once and fail closed when it is not configured.
    let api_key = std::env::var("PROXY_API_KEY")
        .ok()
        .filter(|key| !key.is_empty())
        .unwrap_or_else(|| {
            tracing::error!("PROXY_API_KEY is missing or empty; refusing to start");
            panic!("PROXY_API_KEY must be configured")
        });

    let client = Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .expect("failed to build upstream HTTP client");
    let shutdown = shutdown_signal();
    if let Some(config_path) = std::env::var("PII_CONFIG_PATH").ok().map(PathBuf::from) {
        let watch_vault = vault.clone();
        let watch_path = config_path.clone();
        tokio::task::spawn_blocking(move || {
            watch_pii_config(&watch_path, watch_vault);
        });
    }

    let metrics_app = make_metrics_router(prometheus_handle.clone());
    let app = make_router(AppState {
        client,
        vault,
        api_key,
        upstream_url,
        allowed_origins,
        prometheus_handle,
        byte_budget: Arc::new(Semaphore::new(2 * 1024 * 1024)),
        proxy_private_key,
        shutdown: shutdown.clone(),
    });

    // Bind to 0.0.0.0 so Docker/K8s can route to it
    let bind_addr = format!("0.0.0.0:{}", proxy_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    let metrics_listener = tokio::net::TcpListener::bind("0.0.0.0:9090")
        .await
        .expect("failed to bind metrics listener");

    // Build a service with concurrency limit; the app already has the global CORS middleware applied.
    let svc = ServiceBuilder::new()
        .layer(ConcurrencyLimitLayer::new(1000))
        .service(app);

    let mut shutdown = shutdown;
    let mut watchdog_shutdown = shutdown.clone();
    let shutdown_timeout = std::env::var("SHUTDOWN_TIMEOUT_SEC")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(110);
    tokio::spawn(async move {
        let _ = watchdog_shutdown.changed().await;
        tokio::time::sleep(Duration::from_secs(shutdown_timeout)).await;
        let streams = active_sse_streams();
        tracing::error!(
            streams,
            "graceful shutdown watchdog expired; forcing process exit"
        );
        metrics::increment_counter!("proxy_watchdog_force_kills_total");
        tokio::time::sleep(Duration::from_secs(3)).await;
        std::process::exit(0);
    });

    let mut metrics_shutdown = shutdown.clone();
    tokio::spawn(async move {
        axum::serve(metrics_listener, metrics_app)
            .with_graceful_shutdown(async move {
                let _ = metrics_shutdown.changed().await;
            })
            .await
            .expect("metrics server failed");
    });

    axum::serve(listener, svc)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
            tracing::info!("shutdown signal received; draining active connections");
        })
        .await
        .unwrap();
}

fn parse_pii_config(source: &str) -> (Vec<String>, Vec<String>) {
    let mut patterns = Vec::new();
    let mut replacements = Vec::new();
    for raw in source.split(['\n', ',']) {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.split_once(':') {
            Some((pattern, replacement))
                if !pattern.trim().is_empty() && !replacement.trim().is_empty() =>
            {
                patterns.push(pattern.trim().to_string());
                replacements.push(replacement.trim().to_string());
            }
            _ => {
                patterns.push(entry.to_string());
                replacements.push("[REDACTED]".to_string());
            }
        }
    }
    (patterns, replacements)
}

fn parse_private_key(value: String) -> Option<SigningKey> {
    let trimmed = value.trim();
    let raw = if trimmed.len() == 64 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        hex_decode(trimmed)
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .ok()?
    };
    if raw.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw);
    Some(SigningKey::from_bytes(&bytes))
}

fn watch_pii_config(config_path: &Path, vault: Arc<ArcSwap<PiiVault>>) {
    let watch_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = recommended_watcher(move |event: Result<Event, notify::Error>| {
        let _ = tx.send(event);
    })
    .expect("failed to create config watcher");

    watcher
        .watch(&watch_dir, RecursiveMode::NonRecursive)
        .expect("failed to watch config directory");

    let _ = watcher;
    for event in rx {
        let Ok(event) = event else {
            continue;
        };
        let should_reload = event.paths.iter().any(|path| {
            path == config_path || path.file_name().is_some_and(|name| name == "..data")
        });
        if !should_reload {
            continue;
        }
        let mut contents = None;
        for delay in [100, 500, 1_000, 2_000] {
            match std::fs::read_to_string(config_path) {
                Ok(value) => {
                    contents = Some(value);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(delay)),
            }
        }
        let Some(contents) = contents else {
            tracing::error!(path = %config_path.display(), "PII config reload failed after retries; retaining previous vault");
            metrics::increment_counter!("pii_config_reload_errors_total");
            continue;
        };
        let (patterns, replacements) = parse_pii_config(&contents);
        let patterns_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
        let replacements_refs: Vec<&str> = replacements.iter().map(String::as_str).collect();
        let next_vault = Arc::new(PiiVault::new(&patterns_refs, &replacements_refs));
        vault.store(next_vault);
        tracing::info!(path = %config_path.display(), "swapped PII vault after config update");
    }
}

fn hex_decode(value: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars: Vec<u8> = value.as_bytes().to_vec();
    for chunk in chars.chunks(2) {
        let hex = std::str::from_utf8(chunk).unwrap();
        let byte = u8::from_str_radix(hex, 16).unwrap_or(0);
        bytes.push(byte);
    }
    bytes
}

/// Waits for ctrl+c and then returns, used for graceful shutdown registration.
fn shutdown_signal() -> tokio::sync::watch::Receiver<bool> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
        }
        let _ = shutdown_tx.send(true);
    });
    shutdown_rx
}
