use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::Client;
use std::sync::{Arc, OnceLock};
use tokio::net::TcpListener;
use zero_copy_pii_proxy::engine::PiiVault;
use zero_copy_pii_proxy::{make_metrics_router, make_router, AppState};

static METRICS_HANDLE: OnceLock<Arc<metrics_exporter_prometheus::PrometheusHandle>> =
    OnceLock::new();

fn metrics_handle() -> Arc<metrics_exporter_prometheus::PrometheusHandle> {
    METRICS_HANDLE
        .get_or_init(|| {
            let recorder = PrometheusBuilder::new().build();
            let handle = recorder.handle();
            metrics::set_boxed_recorder(Box::new(recorder)).expect("set metrics recorder");
            Arc::new(handle)
        })
        .clone()
}

async fn start_proxy(upstream_url: String) -> (String, String, tokio::task::JoinHandle<()>) {
    let vault = Arc::new(arc_swap::ArcSwap::from_pointee(PiiVault::new(
        &["password"],
        &["[REDACTED]"],
    )));
    let initial_engine_state = vault.load_full().engine_state.as_ref().clone();
    let app_metrics_handle = (*metrics_handle()).clone();
    let router = make_router(AppState {
        client: Client::builder().build().expect("client"),
        vault,
        engine_state: Arc::new(arc_swap::ArcSwap::from_pointee(initial_engine_state)),
        auth_keyring: Arc::new(arc_swap::ArcSwap::from_pointee(vec![*blake3::hash(
            b"test_key",
        )
        .as_bytes()])),
        upstream_url,
        allowed_origins: Vec::new(),
        prometheus_handle: metrics_handle(),
        metrics_handle: app_metrics_handle,
        proxy_private_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        shutdown: tokio::sync::watch::channel(false).1,
        global_memory: Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)),
        tenant_budgets: Arc::new(dashmap::DashMap::new()),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy bind");
    let address = listener.local_addr().expect("proxy address");
    let metrics_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("metrics bind");
    let metrics_address = metrics_listener.local_addr().expect("metrics address");
    let metrics_router = make_metrics_router(metrics_handle());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("proxy server");
    });
    tokio::spawn(async move {
        axum::serve(metrics_listener, metrics_router)
            .await
            .expect("metrics server");
    });
    (
        format!("http://{address}"),
        format!("http://{metrics_address}"),
        task,
    )
}

async fn post_proxy(client: &Client, proxy_url: &str) -> reqwest::Response {
    client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("Authorization", "Bearer test_key")
        .json(&serde_json::json!({"model":"test","messages":[],"stream":true}))
        .send()
        .await
        .expect("proxy request")
}

#[tokio::test]
async fn propagates_upstream_429_body_retry_after_and_metrics() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_address = upstream_listener.local_addr().expect("upstream address");
    let upstream = Router::new().route(
        "/",
        post(|| async {
            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("retry-after", "17")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"error":"rate limited"}"#))
                .expect("upstream response")
        }),
    );
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream)
            .await
            .expect("upstream server");
    });

    let (proxy_url, metrics_url, proxy_task) =
        start_proxy(format!("http://{upstream_address}")).await;
    let client = Client::new();
    let response = post_proxy(&client, &proxy_url).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["retry-after"], "17");
    assert_eq!(
        response.text().await.expect("error body"),
        r#"{"error":"rate limited"}"#
    );

    let metrics = client
        .get(format!("{metrics_url}/metrics"))
        .send()
        .await
        .expect("metrics request")
        .text()
        .await
        .expect("metrics body");
    assert!(metrics.contains("upstream_error_total{status=\"429\"} 1"));
    assert!(!metrics.contains("active_sse_streams 1"));

    proxy_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn upstream_connection_failure_returns_502_and_gateway_metric() {
    let unused_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve port");
    let unused_address = unused_listener.local_addr().expect("unused address");
    drop(unused_listener);

    let (proxy_url, metrics_url, proxy_task) =
        start_proxy(format!("http://{unused_address}")).await;
    let client = Client::new();
    let response = post_proxy(&client, &proxy_url).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let metrics = client
        .get(format!("{metrics_url}/metrics"))
        .send()
        .await
        .expect("metrics request")
        .text()
        .await
        .expect("metrics body");
    assert!(metrics.contains("proxy_gateway_error_total 1"));
    assert!(!metrics.contains("active_sse_streams 1"));

    proxy_task.abort();
}

#[tokio::test]
async fn rejects_payloads_larger_than_two_megabytes() {
    let (proxy_url, _, proxy_task) = start_proxy("http://127.0.0.1:9".to_string()).await;
    let client = Client::new();
    let oversized_body = vec![b'x'; 2 * 1024 * 1024 + 512 * 1024];
    let response = client
        .post(format!("{proxy_url}/v1/chat/completions"))
        .header("Authorization", "Bearer test_key")
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", oversized_body.len())
        .body(oversized_body)
        .send()
        .await;

    match response {
        Ok(response) => assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => {}
    }
    proxy_task.abort();
}

#[test]
fn binary_refuses_to_start_without_proxy_api_key() {
    let binary = env!("CARGO_BIN_EXE_zero_copy_pii_proxy");
    let output = std::process::Command::new(binary)
        .env_remove("PROXY_AUTH_FILE")
        .env_remove("PROXY_PORT")
        .output()
        .expect("execute proxy binary");
    assert!(
        !output.status.success(),
        "proxy started without PROXY_API_KEY"
    );
}
