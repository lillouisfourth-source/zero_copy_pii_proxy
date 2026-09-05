#[cfg(all(not(debug_assertions), not(feature = "nitro")))]
compile_error!("Release builds MUST enable the 'nitro' feature.");

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;

use arc_swap::ArcSwap;
use base64::Engine;
use dotenvy::dotenv;
use ed25519_dalek::SigningKey;
use metrics_exporter_prometheus::PrometheusBuilder;
use notify::{recommended_watcher, Event, RecursiveMode, Watcher};
use secrecy::ExposeSecret;
use tower::limit::ConcurrencyLimitLayer;
use tower::ServiceBuilder;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::Client;
use zero_copy_pii_proxy::attestation::decrypt_upstream_api_key;
#[cfg(all(debug_assertions, not(feature = "nitro")))]
use zero_copy_pii_proxy::attestation::LocalMockProvider;
#[cfg(feature = "nitro")]
use zero_copy_pii_proxy::attestation::NitroKmsProvider;
use zero_copy_pii_proxy::engine::PiiVault;
use zero_copy_pii_proxy::{active_sse_streams, make_metrics_router, make_router, AppState};

#[deny(warnings)]
#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt::init();

    let recorder = PrometheusBuilder::new().build();
    let recorder_handle = recorder.handle();
    metrics::set_boxed_recorder(Box::new(recorder)).expect("failed to install metrics recorder");
    let prometheus_handle = Arc::new(recorder_handle.clone());

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

    let auth_file = std::env::var("PROXY_AUTH_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| panic!("PROXY_AUTH_FILE must be configured"));
    let mut auth_source = std::fs::read_to_string(&auth_file)
        .unwrap_or_else(|_| panic!("PROXY_AUTH_FILE must be readable"));
    let auth_keyring = Arc::new(ArcSwap::new(Arc::new(hash_keyring(&auth_source))));
    auth_source.zeroize();
    let tenant_budgets = Arc::new(dashmap::DashMap::new());

    let client = build_upstream_client().await;
    let shutdown = shutdown_signal();
    if let Some(config_path) = std::env::var("PII_CONFIG_PATH").ok().map(PathBuf::from) {
        let watch_vault = vault.clone();
        let watch_path = config_path.clone();
        tokio::task::spawn_blocking(move || {
            watch_pii_config(&watch_path, watch_vault);
        });
    }
    let watch_keyring = auth_keyring.clone();
    let watch_auth_path = auth_file.clone();
    let watch_tenant_budgets = tenant_budgets.clone();
    tokio::task::spawn_blocking(move || {
        watch_auth_file(&watch_auth_path, watch_keyring, watch_tenant_budgets)
    });

    let metrics_app = make_metrics_router(prometheus_handle.clone());
    let initial_engine_state = vault.load_full().engine_state.as_ref().clone();
    let app = make_router(AppState {
        client,
        vault,
        engine_state: Arc::new(ArcSwap::from_pointee(initial_engine_state)),
        auth_keyring,
        upstream_url,
        allowed_origins,
        prometheus_handle,
        metrics_handle: recorder_handle,
        proxy_private_key,
        shutdown: shutdown.clone(),
        global_memory: Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)),
        tenant_budgets,
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

async fn build_upstream_client() -> Client {
    #[cfg(all(debug_assertions, not(feature = "nitro")))]
    {
        if std::env::var("LOCALSTACK_ENDPOINT").is_err() {
            panic!("LOCALSTACK_ENDPOINT is required for debug-mode startup");
        }
        let provider = LocalMockProvider::new()
            .await
            .expect("failed to initialize LocalStack KMS provider");
        let ciphertext = read_localstack_ciphertext().await;
        let secret = decrypt_upstream_api_key(Arc::new(provider), ciphertext)
            .await
            .expect("failed to decrypt LocalStack fixture; refusing unauthenticated boot");
        let mut headers = HeaderMap::new();
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {}", secret.expose_secret()))
                .expect("LocalStack API key produced an invalid Authorization header");
        authorization.set_sensitive(true);
        headers.insert(AUTHORIZATION, authorization);
        Client::builder()
            .default_headers(headers)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .expect("failed to build upstream HTTP client");
    }

    #[cfg(feature = "nitro")]
    {
        let provider = NitroKmsProvider::new()
            .await
            .expect("failed to initialize Nitro KMS provider");
        let ciphertext = read_nitro_ciphertext().await;
        let secret = decrypt_upstream_api_key(Arc::new(provider), ciphertext)
            .await
            .expect("failed to decrypt Nitro secret; refusing unauthenticated boot");
        let mut headers = HeaderMap::new();
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {}", secret.expose_secret()))
                .expect("Nitro API key produced an invalid Authorization header");
        authorization.set_sensitive(true);
        headers.insert(AUTHORIZATION, authorization);
        Client::builder()
            .default_headers(headers)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .expect("failed to build upstream HTTP client");
    }
}

#[cfg(all(debug_assertions, not(feature = "nitro")))]
async fn read_localstack_ciphertext() -> Vec<u8> {
    let path = Path::new(".aws-mock/ciphertext.b64");
    for attempt in 1..=10 {
        match tokio::fs::read_to_string(path).await {
            Ok(contents) => {
                let contents = contents.trim();
                return base64::engine::general_purpose::STANDARD
                    .decode(contents)
                    .expect("LocalStack ciphertext fixture is not valid Base64");
            }
            Err(error) if attempt < 10 => {
                tracing::warn!(attempt, %error, "waiting for LocalStack ciphertext fixture");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(error) => {
                panic!("LocalStack ciphertext fixture unavailable after 10 attempts: {error}")
            }
        }
    }
    unreachable!()
}

#[cfg(feature = "nitro")]
async fn read_nitro_ciphertext() -> Vec<u8> {
    let mut contents = tokio::fs::read_to_string("/run/secrets/ciphertext.b64")
        .await
        .expect("Nitro ciphertext fixture is required");
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(contents.trim())
        .expect("Nitro ciphertext fixture is not valid Base64");
    contents.zeroize();
    ciphertext
}

/*
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
    let watch_keyring = auth_keyring.clone();
    let watch_auth_path = auth_file.clone();
    let watch_tenant_budgets = tenant_budgets.clone();
    tokio::task::spawn_blocking(move || {
        watch_auth_file(&watch_auth_path, watch_keyring, watch_tenant_budgets)
    });

    let metrics_app = make_metrics_router(prometheus_handle.clone());
    let initial_engine_state = vault.load_full().engine_state.as_ref().clone();
    let app = make_router(AppState {
        client,
        vault,
        engine_state: Arc::new(ArcSwap::from_pointee(initial_engine_state)),
        auth_keyring,
        upstream_url,
        allowed_origins,
        prometheus_handle,
        metrics_handle: recorder_handle,
        proxy_private_key,
        shutdown: shutdown.clone(),
        global_memory: Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)),
        tenant_budgets,
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
    */

fn hash_keyring(source: &str) -> Vec<[u8; 32]> {
    source
        .lines()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| *blake3::hash(token.as_bytes()).as_bytes())
        .collect()
}

fn watch_auth_file(
    path: &Path,
    keyring: Arc<ArcSwap<Vec<[u8; 32]>>>,
    tenant_budgets: Arc<dashmap::DashMap<[u8; 32], Arc<tokio::sync::Semaphore>>>,
) {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = recommended_watcher(move |event: Result<Event, notify::Error>| {
        let _ = tx.send(event);
    })
    .expect("failed to create auth watcher");
    watcher
        .watch(directory, RecursiveMode::NonRecursive)
        .expect("failed to watch auth directory");
    for event in rx {
        let Ok(event) = event else { continue };
        if !event.paths.iter().any(|event_path| {
            event_path == path || event_path.file_name().is_some_and(|name| name == "..data")
        }) {
            continue;
        }
        for delay in [100, 500, 1_000, 2_000] {
            match std::fs::read_to_string(path) {
                Ok(mut contents) => {
                    let next_keyring = Arc::new(hash_keyring(&contents));
                    contents.zeroize();
                    if next_keyring.is_empty() {
                        tracing::error!("Refusing to load empty auth file");
                        return;
                    }
                    tenant_budgets.clear();
                    keyring.store(next_keyring);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(delay)),
            }
        }
    }
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

    let raw = if trimmed.len() == 64 {
        match hex::decode(trimmed) {
            Ok(bytes) => bytes,
            Err(error) => panic!("PROXY_PRIVATE_KEY contains invalid hexadecimal data: {error}"),
        }
    } else {
        match base64::engine::general_purpose::STANDARD.decode(trimmed) {
            Ok(bytes) => bytes,
            Err(error) => {
                panic!("PROXY_PRIVATE_KEY must be a valid 32-byte hex or base64 seed: {error}")
            }
        }
    };

    if raw.len() != 32 {
        panic!("PROXY_PRIVATE_KEY must decode to exactly 32 bytes");
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
        let Some(mut contents) = contents else {
            tracing::error!(path = %config_path.display(), "PII config reload failed after retries; retaining previous vault");
            metrics::increment_counter!("pii_config_reload_errors_total");
            continue;
        };
        let (patterns, replacements) = parse_pii_config(&contents);
        let patterns_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
        let replacements_refs: Vec<&str> = replacements.iter().map(String::as_str).collect();
        let next_vault = Arc::new(PiiVault::new(&patterns_refs, &replacements_refs));
        contents.zeroize();
        vault.store(next_vault);
        tracing::info!(path = %config_path.display(), "swapped PII vault after config update");
    }
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
