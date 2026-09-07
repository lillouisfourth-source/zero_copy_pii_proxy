use axum::{
    body::Body, extract::State, http::StatusCode, response::Response, routing::post, Router,
};
use bytes::Bytes;
use futures::StreamExt;
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::Client;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use zero_copy_pii_proxy::engine::PiiVault;
use zero_copy_pii_proxy::{make_router, AppState};

type UpstreamState = (Arc<AtomicUsize>, Arc<Mutex<Option<oneshot::Receiver<()>>>>);

async fn upstream_handler(State(state): State<UpstreamState>) -> Response<Body> {
    let count = state.0.fetch_add(1, Ordering::SeqCst);
    if count == 0 {
        let release = state.1.lock().await.take();
        let stream = async_stream::stream! {
            yield Ok::<_, std::convert::Infallible>(Bytes::from_static(b"alpha"));
            if let Some(release) = release {
                let _ = release.await;
            }
            yield Ok::<_, std::convert::Infallible>(Bytes::from_static(b"\n"));
        };
        Response::new(Body::from_stream(stream))
    } else {
        Response::new(Body::from(Bytes::from_static(b"beta\n")))
    }
}

#[tokio::test]
async fn active_streams_keep_their_engine_snapshot_during_hot_swap() {
    let (release_first, release_rx) = oneshot::channel::<()>();
    let request_count = Arc::new(AtomicUsize::new(0));
    let upstream_state = (request_count, Arc::new(Mutex::new(Some(release_rx))));
    let upstream = Router::new()
        .route("/", post(upstream_handler))
        .with_state(upstream_state);
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(upstream_listener, upstream).await.unwrap() });

    let recorder = PrometheusBuilder::new().build();
    let prometheus_handle = Arc::new(recorder.handle());
    metrics::set_boxed_recorder(Box::new(recorder)).ok();
    let initial_vault = Arc::new(arc_swap::ArcSwap::from_pointee(PiiVault::new(
        &["alpha"],
        &["[REDACTED]"],
    )));
    let initial_state = initial_vault.load_full().engine_state.as_ref().clone();
    let api_key = "hot-swap-test";
    let state = AppState {
        client: Client::new(),
        vault: initial_vault,
        engine_state: Arc::new(arc_swap::ArcSwap::from_pointee(initial_state)),
        auth_keyring: Arc::new(arc_swap::ArcSwap::from_pointee(vec![*blake3::hash(
            api_key.as_bytes(),
        )
        .as_bytes()])),
        admin_bearer_token_hash: *blake3::hash(b"admin_key").as_bytes(),
        attestation_document: Arc::new(Vec::new()),
        upstream_url: format!("http://{}", upstream_addr),
        allowed_origins: Vec::new(),
        prometheus_handle,
        metrics_handle: PrometheusBuilder::new().build().handle(),
        proxy_private_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        shutdown: tokio::sync::watch::channel(false).1,
        global_memory: Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)),
        tenant_budgets: Arc::new(dashmap::DashMap::new()),
    };
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(proxy_listener, make_router(state))
            .await
            .unwrap()
    });

    let client = Client::new();
    let proxy_url = format!("http://{}/v1/chat/completions", proxy_addr);
    let request = || {
        client
            .post(&proxy_url)
            .header("Authorization", format!("Bearer {api_key}"))
            .body("stream")
    };
    let first_response = request().send().await.unwrap();
    let first = first_response.bytes_stream();

    let control = client
        .post(format!("http://{}/_admin/rules", proxy_addr))
        .header("Authorization", "Bearer admin_key")
        .json(&serde_json::json!({"patterns": ["beta"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(control.status(), StatusCode::OK);

    let tenant_control = client
        .post(format!("http://{}/_admin/rules", proxy_addr))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&serde_json::json!({"patterns": ["gamma"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(tenant_control.status(), StatusCode::FORBIDDEN);

    let second = request().send().await.unwrap().text().await.unwrap();
    assert!(
        second.contains("[REDACTED]"),
        "stream 2 was not redacted: {second}"
    );
    assert!(
        !second.contains("beta"),
        "stream 2 leaked pattern B: {second}"
    );

    release_first.send(()).unwrap();
    let first_body = first.collect::<Vec<_>>().await;
    let first_bytes = first_body
        .into_iter()
        .flat_map(|result| result.unwrap().to_vec())
        .collect::<Vec<_>>();
    let first_text = String::from_utf8(first_bytes).unwrap();
    assert!(
        first_text.contains("[REDACTED]"),
        "stream 1 was not redacted: {first_text}"
    );
    assert!(
        !first_text.contains("alpha"),
        "stream 1 leaked pattern A: {first_text}"
    );
}
