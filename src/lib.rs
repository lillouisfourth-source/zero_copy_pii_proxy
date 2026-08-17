#![deny(warnings)]

pub mod domain;
pub mod engine;

use std::convert::Infallible;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, Method, Request, Response, StatusCode};
use axum::middleware::Next;
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use futures::StreamExt;
use metrics_exporter_prometheus::PrometheusHandle;
use reqwest::Client;
use std::time::Duration;
use tokio::sync::mpsc::unbounded_channel;
use tokio_stream::wrappers::UnboundedReceiverStream;

use engine::PiiVault;

/// Build the axum Router used by main and tests. Exposed publicly for integration tests.
pub fn make_router(
    vault: Arc<PiiVault>,
    prometheus_handle: Arc<PrometheusHandle>,
    api_key: String,
    upstream_url: String,
) -> Router {
    let ph = prometheus_handle.clone();

    Router::new()
        .route(
            "/v1/chat/completions",
            post(move |req| {
                let vault = vault.clone();
                let upstream = upstream_url.clone();
                async move { proxy_with_upstream(req, vault, upstream).await }
            })
            .layer(middleware::from_fn_with_state(
                api_key.clone(),
                require_auth,
            )),
        )
        .route("/health", get(|| async { (StatusCode::OK, "ok") }))
        .route(
            "/metrics",
            get(move || {
                let h = ph.clone();
                async move { (StatusCode::OK, h.render()) }
            }),
        )
        .with_state(api_key.clone())
        // Global body limit to mitigate OOM/memory attacks (2 MiB)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn(cors_middleware))
}

async fn require_auth(
    State(api_key): State<String>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    if let Some(hv) = req.headers().get("authorization") {
        if let Ok(s) = hv.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                if token == api_key {
                    let resp = next.run(req).await;
                    return Ok(resp);
                }
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

// Global CORS middleware to handle OPTIONS preflight and add permissive CORS headers to all responses.
async fn cors_middleware(req: Request<Body>, next: Next) -> Result<Response<Body>, StatusCode> {
    if req.method() == Method::OPTIONS {
        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
        let headers = resp.headers_mut();
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        headers.insert(
            "access-control-allow-headers",
            HeaderValue::from_static("Authorization, Content-Type"),
        );
        headers.insert(
            "access-control-allow-methods",
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        return Ok(resp);
    }

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    headers.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("Authorization, Content-Type"),
    );
    headers.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    Ok(resp)
}

pub async fn proxy_with_upstream(
    req: Request<Body>,
    _vault: Arc<PiiVault>,
    upstream_url: String,
) -> Response<Body> {
    // increment metrics for active SSE streams; spawn background task to forward upstream stream
    metrics::increment_counter!("proxy_requests_total");
    metrics::increment_gauge!("active_sse_streams", 1.0);

    // Read incoming body fully (limit 10 MB)
    let whole = match axum::body::to_bytes(req.into_body(), 10_485_760).await {
        Ok(b) => b,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("failed to read body"))
                .unwrap()
        }
    };

    // Prepare channel
    let (tx, rx) = unbounded_channel::<Result<Bytes, Infallible>>();
    let tx_task = tx.clone();

    // Spawn task to send request upstream and pipe bytes back
    tokio::spawn(async move {
        struct ActiveStreamGuard;
        impl Drop for ActiveStreamGuard {
            fn drop(&mut self) {
                metrics::decrement_gauge!("active_sse_streams", 1.0);
            }
        }
        let _guard = ActiveStreamGuard;

        let client = Client::new();
        let builder = client.post(&upstream_url).body(whole);
        // No auth forwarded here in this simplified path

        match tokio::time::timeout(Duration::from_secs(120), builder.send()).await {
            Ok(Ok(resp)) => {
                let mut stream = resp.bytes_stream();
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(chunk) => {
                            if tx_task.send(Ok(chunk)).is_err() {
                                tracing::info!("downstream disconnected, stopping forward");
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("error reading upstream chunk: {}", e);
                            return;
                        }
                    }
                }
            }
            Ok(Err(e)) => tracing::error!("upstream request failed: {}", e),
            Err(_) => tracing::warn!("upstream request timed out"),
        }

        // dropping tx_task and _guard will decrement the gauge
    });

    drop(tx);
    let body_stream = UnboundedReceiverStream::new(rx);
    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(body_stream))
        .unwrap()
}
