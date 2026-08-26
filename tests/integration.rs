use futures::StreamExt;
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::Client;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use zero_copy_pii_proxy::engine::PiiVault;
use zero_copy_pii_proxy::{make_metrics_router, make_router, AppState};

#[tokio::test]
async fn drop_guard_prevents_leak_of_active_sse_streams() {
    // Install a fresh prometheus recorder for this test process
    let recorder = PrometheusBuilder::new().build();
    let handle = recorder.handle();
    metrics::set_boxed_recorder(Box::new(recorder)).expect("set recorder");
    let prometheus_handle = Arc::new(handle);

    // Build a simple vault
    let patterns = ["password", "secret"];
    let replacements = ["[REDACTED]", "[REDACTED]"];
    let vault = Arc::new(arc_swap::ArcSwap::from_pointee(PiiVault::new(
        &patterns,
        &replacements,
    )));

    // Start a tiny upstream server that streams a single SSE chunk and then sleeps briefly
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = axum::Router::new().route("/", axum::routing::post(|| async move {
            // return a streaming response with one data chunk
            let stream = async_stream::stream! {
                yield Ok::<_, std::convert::Infallible>(axum::response::sse::Event::default().data("{\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}"));
                // hang briefly to simulate a long-lived stream, but short enough for the test to detect disconnect
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            };
            axum::response::Sse::new(stream)
        }));
        axum::serve(upstream_listener, app).await.unwrap();
    });

    // Build and spawn the proxy app pointing to the upstream server
    let api_key = "test_key".to_string();
    let upstream_url = format!("http://{}", upstream_addr);
    let router = make_router(AppState {
        client: Client::builder()
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .unwrap(),
        vault,
        auth_keyring: Arc::new(arc_swap::ArcSwap::from_pointee(vec![*blake3::hash(
            api_key.as_bytes(),
        )
        .as_bytes()])),
        upstream_url,
        allowed_origins: Vec::new(),
        prometheus_handle: prometheus_handle.clone(),
        proxy_private_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        shutdown: tokio::sync::watch::channel(false).1,
        global_memory: Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)),
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let metrics_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics_addr = metrics_listener.local_addr().unwrap();
    let metrics_router = make_metrics_router(prometheus_handle.clone());
    tokio::spawn(async move {
        axum::serve(proxy_listener, router).await.unwrap();
    });
    tokio::spawn(async move {
        axum::serve(metrics_listener, metrics_router).await.unwrap();
    });

    // Create a client and POST to proxy with stream:true and Authorization header
    let client = Client::new();
    let proxy_url = format!("http://{}/v1/chat/completions", proxy_addr);
    let body = serde_json::json!({"model": "gpt-test", "messages": [{"role":"user","content":"hello"}], "stream": true});

    let resp = client
        .post(&proxy_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&body)
        .send()
        .await
        .expect("request to proxy");

    // Read the first chunk of the streaming body
    let mut body_stream = resp.bytes_stream();
    let first_chunk = body_stream.next().await;
    assert!(first_chunk.is_some(), "expected first chunk");

    // Now drop the stream to simulate disconnect (resp was moved into the stream)
    drop(body_stream);

    // yield to runtime to allow drop guard to run
    sleep(Duration::from_millis(50)).await;

    // Now poll /metrics and assert active_sse_streams 0
    let metrics = client
        .get(format!("http://{}/metrics", metrics_addr))
        .send()
        .await
        .expect("metrics")
        .text()
        .await
        .expect("text");
    assert!(
        metrics.contains("active_sse_streams 0"),
        "metrics did not show zero active streams: {}",
        metrics
    );
}
