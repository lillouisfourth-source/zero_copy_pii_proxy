#![deny(warnings)]

pub mod domain;
pub mod engine;

use std::convert::Infallible;
use std::sync::Arc;

use axum::body::{Body, BodyDataStream};
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
use subtle::ConstantTimeEq;
use tokio::sync::mpsc::channel;
use tokio::sync::Semaphore;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::request_id::{
    MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::trace::TraceLayer;
use tracing::{info_span, Instrument, Span};

use engine::{PiiVault, StreamRedactor};

const MAX_ACTIVE_UPSTREAM_STREAMS: usize = 1000;
static UPSTREAM_STREAM_LIMIT: Semaphore = Semaphore::const_new(MAX_ACTIVE_UPSTREAM_STREAMS);

#[derive(Clone)]
pub struct AppState {
    pub client: Client,
    pub vault: Arc<PiiVault>,
    pub api_key: String,
    pub upstream_url: String,
    pub allowed_origins: Vec<String>,
    pub prometheus_handle: Arc<PrometheusHandle>,
}

pub const MAX_BODY_SIZE: usize = 2 * 1024 * 1024;

/// Build the axum Router used by main and tests. Exposed publicly for integration tests.
pub fn make_router(state: AppState) -> Router {
    let ph = state.prometheus_handle.clone();
    let request_id_header = axum::http::HeaderName::from_static("x-request-id");

    Router::new()
        .route(
            "/v1/chat/completions",
            post(proxy_handler).layer(middleware::from_fn_with_state(state.clone(), require_auth)),
        )
        .route("/health", get(|| async { (StatusCode::OK, "ok") }))
        .route(
            "/metrics",
            get(move || {
                let h = ph.clone();
                async move { (StatusCode::OK, h.render()) }
            }),
        )
        .with_state(state.clone())
        // Global body limit to mitigate OOM/memory attacks (2 MiB)
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            cors_middleware,
        ))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                let request_id = request
                    .extensions()
                    .get::<RequestId>()
                    .and_then(|id| id.header_value().to_str().ok())
                    .unwrap_or("missing");
                info_span!("http_request", request_id = %request_id)
            }),
        )
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
}

async fn proxy_handler(State(state): State<AppState>, req: Request<Body>) -> Response<Body> {
    proxy_with_upstream(req, state).await
}

async fn require_auth(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    if let Some(hv) = req.headers().get("authorization") {
        if let Ok(s) = hv.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                if token.as_bytes().ct_eq(state.api_key.as_bytes()).into() {
                    let resp = next.run(req).await;
                    return Ok(resp);
                }
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

// CORS middleware permits only configured origins and rejects all origins when unset.
async fn cors_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let origin = req
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let allowed_origin = origin
        .as_deref()
        .filter(|value| state.allowed_origins.iter().any(|allowed| allowed == value))
        .map(str::to_string);

    if origin.is_some() && allowed_origin.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }

    if req.method() == Method::OPTIONS {
        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
        let headers = resp.headers_mut();
        if let Some(origin) = allowed_origin.as_deref() {
            if let Ok(value) = HeaderValue::from_str(origin) {
                headers.insert("access-control-allow-origin", value);
            }
        }
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
    if let Some(origin) = allowed_origin.as_deref() {
        if let Ok(value) = HeaderValue::from_str(origin) {
            headers.insert("access-control-allow-origin", value);
        }
    }
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

pub async fn proxy_with_upstream(req: Request<Body>, state: AppState) -> Response<Body> {
    // Count requests independently from streams; a stream exists only after upstream success.
    metrics::increment_counter!("proxy_requests_total");
    let request_span = Span::current();

    let body_stream: BodyDataStream = req.into_body().into_data_stream();
    let request_body = reqwest::Body::wrap_stream(body_stream);
    let stream_permit = match UPSTREAM_STREAM_LIMIT.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            metrics::decrement_gauge!("active_sse_streams", 1.0);
            tracing::error!("upstream stream semaphore closed");
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::empty())
                .unwrap();
        }
    };

    let upstream_response = match tokio::time::timeout(
        Duration::from_secs(120),
        state
            .client
            .post(&state.upstream_url)
            .body(request_body)
            .send(),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            metrics::increment_counter!("proxy_gateway_error_total");
            tracing::error!(error = %error, "upstream request failed");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .unwrap();
        }
        Err(_) => {
            metrics::increment_counter!("proxy_gateway_error_total");
            tracing::warn!("upstream request timed out");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .unwrap();
        }
    };

    if !upstream_response.status().is_success() {
        let status = StatusCode::from_u16(upstream_response.status().as_u16())
            .unwrap_or(StatusCode::BAD_GATEWAY);
        let retry_after = upstream_response.headers().get("retry-after").cloned();
        let content_type = upstream_response.headers().get("content-type").cloned();
        let body = upstream_response.bytes().await.unwrap_or_default();
        let status_label = status.as_u16().to_string();
        metrics::increment_counter!(
            "upstream_error_total",
            "status" => status_label
        );
        let mut response = Response::builder().status(status);
        if let Some(value) = retry_after {
            response = response.header("retry-after", value);
        }
        if let Some(value) = content_type {
            response = response.header("content-type", value);
        }
        return response.body(Body::from(body)).unwrap();
    }

    metrics::increment_gauge!("active_sse_streams", 1.0);
    let (tx, rx) = channel::<Result<Bytes, Infallible>>(32);
    let tx_task = tx.clone();
    tokio::spawn(async move {
        struct ActiveStreamGuard;
        impl Drop for ActiveStreamGuard {
            fn drop(&mut self) {
                metrics::decrement_gauge!("active_sse_streams", 1.0);
            }
        }
        let _guard = ActiveStreamGuard;
        let _stream_permit = stream_permit;
        let mut stream = upstream_response.bytes_stream();
        let mut redactor = StreamRedactor::new(&state.vault);
        loop {
            let item = match tokio::time::timeout(Duration::from_secs(15), stream.next()).await {
                Ok(item) => item,
                Err(_) => {
                    tracing::warn!("upstream stream idle timeout");
                    return;
                }
            };
            let Some(item) = item else {
                break;
            };
            match item {
                Ok(chunk) => match redactor.push(&chunk) {
                    Ok(outputs) => {
                        for output in outputs {
                            if tx_task.send(Ok(output)).await.is_err() {
                                tracing::warn!("downstream send failed: receiver dropped; aborting upstream stream");
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!("upstream stream rejected: {:?}", error);
                        return;
                    }
                },
                Err(error) => {
                    tracing::warn!(error = %error, "error reading upstream chunk");
                    return;
                }
            }
        }
        match redactor.finish() {
            Ok(outputs) => {
                for output in outputs {
                    if tx_task.send(Ok(output)).await.is_err() {
                        tracing::warn!("downstream send failed: receiver dropped; aborting upstream stream");
                        return;
                    }
                }
            }
            Err(error) => tracing::warn!("upstream stream rejected at end: {:?}", error),
        }
    }.instrument(request_span));

    drop(tx);
    let body_stream = ReceiverStream::new(rx);
    Response::builder()
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(body_stream))
        .unwrap()
}
