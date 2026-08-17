#![deny(warnings)]

use std::sync::Arc;

use dotenvy::dotenv;
use metrics_exporter_prometheus::PrometheusBuilder;
use tower::limit::ConcurrencyLimitLayer;
use tower::ServiceBuilder;

use zero_copy_pii_proxy::engine::PiiVault;
use zero_copy_pii_proxy::make_router;

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

    // Parse PII_PATTERNS into a Vec<String> and prepare replacements
    let patterns_env =
        std::env::var("PII_PATTERNS").unwrap_or_else(|_| "password,secret,ssn".to_string());
    let patterns_owned: Vec<String> = patterns_env
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut patterns_refs: Vec<&str> = Vec::with_capacity(patterns_owned.len());
    for s in &patterns_owned {
        patterns_refs.push(s.as_str());
    }
    let replacements_owned: Vec<String> = patterns_owned
        .iter()
        .map(|_| "[REDACTED]".to_string())
        .collect();
    let mut replacements_refs: Vec<&str> = Vec::with_capacity(replacements_owned.len());
    for s in &replacements_owned {
        replacements_refs.push(s.as_str());
    }

    let vault = Arc::new(PiiVault::new(&patterns_refs, &replacements_refs));

    // Read API key once and keep in router state
    let api_key =
        std::env::var("PROXY_API_KEY").unwrap_or_else(|_| "change_me_in_production".to_string());

    let app = make_router(
        vault.clone(),
        prometheus_handle.clone(),
        api_key.clone(),
        upstream_url.clone(),
    );

    // Bind to 0.0.0.0 so Docker/K8s can route to it
    let bind_addr = format!("0.0.0.0:{}", proxy_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());

    // Build a service with concurrency limit; the app already has the global CORS middleware applied.
    let svc = ServiceBuilder::new()
        .layer(ConcurrencyLimitLayer::new(1000))
        .service(app);

    axum::serve(listener, svc)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/// Waits for ctrl+c and then returns, used for graceful shutdown registration.
async fn shutdown_signal() {
    // Best-effort: ignore the error if the signal handler fails to install
    let _ = tokio::signal::ctrl_c().await;
}
