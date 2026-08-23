#![deny(warnings)]

pub mod budget_queue;
pub mod domain;
pub mod engine;

use crate::budget_queue::{channel, enqueue, BudgetedBody, ByteBudget};
use crate::engine::{OutputSegment, PiiVault, StreamRedactor};
use base64::engine::general_purpose::STANDARD as B64Std;
use base64::Engine;
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashSet;
use std::error::Error;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::body::{Body, BodyDataStream};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, Method, Request, Response, StatusCode};
use axum::middleware::Next;
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use bytes::BytesMut;
use futures::StreamExt;
use metrics_exporter_prometheus::PrometheusHandle;
use reqwest::Client;
use std::time::Duration;
use tokio::sync::Semaphore;
use tower_http::request_id::{
    MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::trace::TraceLayer;
use tracing::{info_span, Instrument, Span};

const MAX_ACTIVE_UPSTREAM_STREAMS: usize = 1000;
static UPSTREAM_STREAM_LIMIT: Semaphore = Semaphore::const_new(MAX_ACTIVE_UPSTREAM_STREAMS);
static ACTIVE_SSE_STREAMS: AtomicUsize = AtomicUsize::new(0);
pub const OUTPUT_BYTE_BUDGET: usize = 2 * 1024 * 1024;
pub const SSE_DONE_MARKER: &[u8] = b"data: [DONE]";

pub type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
pub enum RequestBodyError {
    LimitExceeded { limit: usize },
    Upstream(BoxError),
}

impl std::fmt::Display for RequestBodyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LimitExceeded { limit } => {
                write!(formatter, "request body exceeded {limit} bytes")
            }
            Self::Upstream(error) => write!(formatter, "request body stream failed: {error}"),
        }
    }
}

impl Error for RequestBodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LimitExceeded { .. } => None,
            Self::Upstream(error) => Some(&**error),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub client: Client,
    pub vault: Arc<arc_swap::ArcSwap<PiiVault>>,
    pub auth_keyring: Arc<arc_swap::ArcSwap<HashSet<[u8; 32]>>>,
    pub upstream_url: String,
    pub allowed_origins: Vec<String>,
    pub prometheus_handle: Arc<PrometheusHandle>,
    pub byte_budget: Arc<Semaphore>,
    pub proxy_private_key: SigningKey,
    pub shutdown: tokio::sync::watch::Receiver<bool>,
}

pub const MAX_BODY_SIZE: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Data(Bytes),
    AuditReceipt(Bytes),
    DoneMarker(Bytes),
}

pub fn active_sse_streams() -> usize {
    ACTIVE_SSE_STREAMS.load(Ordering::Relaxed)
}

fn increment_active_sse_streams() {
    ACTIVE_SSE_STREAMS.fetch_add(1, Ordering::Relaxed);
    metrics::gauge!("active_sse_streams", active_sse_streams() as f64);
}

fn decrement_active_sse_streams() {
    let current = ACTIVE_SSE_STREAMS.fetch_sub(1, Ordering::Relaxed) - 1;
    metrics::gauge!("active_sse_streams", current as f64);
}

/// Build the axum Router used by main and tests. Exposed publicly for integration tests.
pub fn make_router(state: AppState) -> Router {
    let request_id_header = axum::http::HeaderName::from_static("x-request-id");

    Router::new()
        .route(
            "/v1/chat/completions",
            post(proxy_handler).layer(middleware::from_fn_with_state(state.clone(), require_auth)),
        )
        .with_state(state.clone())
        // Global body limit to mitigate OOM/memory attacks (2 MiB)
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(middleware::from_fn(enforce_body_limit))
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

pub fn make_metrics_router(prometheus_handle: Arc<PrometheusHandle>) -> Router {
    Router::new()
        .route("/health", get(|| async { (StatusCode::OK, "ok") }))
        .route(
            "/metrics",
            get(move || {
                let handle = prometheus_handle.clone();
                async move { (StatusCode::OK, handle.render()) }
            }),
        )
}

async fn enforce_body_limit(req: Request<Body>, next: Next) -> Result<Response<Body>, StatusCode> {
    if req
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_BODY_SIZE)
    {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let (parts, body) = req.into_parts();
    let limited_stream = futures::stream::unfold(
        (body.into_data_stream(), 0usize),
        |(mut stream, total)| async move {
            match stream.next().await {
                Some(Ok(bytes)) => {
                    let next_total = total.saturating_add(bytes.len());
                    if next_total > MAX_BODY_SIZE {
                        Some((
                            Err(RequestBodyError::LimitExceeded {
                                limit: MAX_BODY_SIZE,
                            }),
                            (stream, next_total),
                        ))
                    } else {
                        Some((Ok(bytes), (stream, next_total)))
                    }
                }
                Some(Err(error)) => Some((
                    Err(RequestBodyError::Upstream(Box::new(error))),
                    (stream, total),
                )),
                None => None,
            }
        },
    );
    Ok(next
        .run(Request::from_parts(
            parts,
            Body::from_stream(limited_stream),
        ))
        .await)
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
                let token_hash = *blake3::hash(token.as_bytes()).as_bytes();
                if state.auth_keyring.load().contains(&token_hash) {
                    let resp = next.run(req).await;
                    return Ok(resp);
                }
            }
        }
    }
    metrics::increment_counter!("proxy_auth_failures_total");
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
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|id| id.header_value().clone())
        .or_else(|| req.headers().get("x-request-id").cloned());

    let request_content_type = req.headers().get("content-type").cloned();
    let body_stream: BodyDataStream = req.into_body().into_data_stream();
    let request_body = reqwest::Body::wrap_stream(body_stream);
    let stream_permit = match UPSTREAM_STREAM_LIMIT.acquire().await {
        Ok(permit) => permit,
        Err(_) => {
            tracing::error!("upstream stream semaphore closed");
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::empty())
                .unwrap();
        }
    };

    let mut upstream_request = state.client.post(&state.upstream_url).body(request_body);
    if let Some(content_type) = request_content_type {
        upstream_request = upstream_request.header("content-type", content_type);
    }
    if let Some(request_id) = request_id {
        upstream_request = upstream_request.header("x-request-id", request_id);
    }

    let upstream_response =
        match tokio::time::timeout(Duration::from_secs(120), upstream_request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                if contains_body_limit_error(&error) {
                    return Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Body::empty())
                        .unwrap();
                }
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
        let mut body_stream = upstream_response.bytes_stream();
        let mut body = BytesMut::with_capacity(8 * 1024);
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let Ok(Some(chunk)) =
                    tokio::time::timeout(Duration::from_secs(3), body_stream.next()).await
                else {
                    break;
                };
                let Ok(chunk) = chunk else {
                    break;
                };
                let remaining = 8 * 1024 - body.len();
                if remaining == 0 {
                    break;
                }
                let take = chunk.len().min(remaining);
                body.extend_from_slice(&chunk[..take]);
                if take == remaining {
                    break;
                }
            }
        })
        .await;
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
        return response.body(Body::from(body.freeze())).unwrap();
    }

    let upstream_content_type = upstream_response.headers().get("content-type").cloned();
    let is_sse = upstream_content_type
        .as_ref()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("text/event-stream"));
    if is_sse {
        increment_active_sse_streams();
    }
    let (tx, rx) = channel(32);
    let tx_task = tx.clone();
    let byte_budget = ByteBudget::from_shared(state.byte_budget.clone(), OUTPUT_BYTE_BUDGET);
    let private_key = state.proxy_private_key.clone();
    let mut stream_shutdown = state.shutdown.clone();
    let active_vault = state.vault.load_full();
    tokio::spawn(async move {
        struct ActiveStreamGuard {
            active_sse: bool,
        }
        impl Drop for ActiveStreamGuard {
            fn drop(&mut self) {
                if self.active_sse {
                    decrement_active_sse_streams();
                }
            }
        }
        let _guard = ActiveStreamGuard { active_sse: is_sse };
        let _stream_permit = stream_permit;
        let mut stream = upstream_response.bytes_stream();
        let mut redactor = StreamRedactor::new(active_vault.as_ref());
        let mut hasher = blake3::Hasher::new();
        let mut done_detector = DoneDetector::default();
        let reached_eof = loop {
            let item = match tokio::select! {
                _ = stream_shutdown.changed() => {
                    if *stream_shutdown.borrow() {
                        let events = done_detector.shutdown_events(&private_key, &mut hasher);
                        if forward_stream_events(events, &tx_task, &byte_budget).await.is_err() {
                            return;
                        }
                        break false;
                    }
                    continue;
                }
                item = tokio::time::timeout(Duration::from_secs(15), stream.next()) => item,
            } {
                Ok(item) => item,
                Err(_) => {
                    tracing::warn!("upstream stream idle timeout");
                    return;
                }
            };
            let Some(item) = item else {
                break true;
            };
            match item {
                Ok(chunk) => match redactor.push(chunk) {
                    Ok(outputs) => {
                        for output in outputs {
                            let bytes = match output {
                                OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => bytes,
                            };
                            if is_sse {
                                if forward_stream_events(
                                    done_detector.inspect(bytes, &private_key, &mut hasher),
                                    &tx_task,
                                    &byte_budget,
                                )
                                .await
                                .is_err()
                                {
                                    tracing::warn!("downstream send failed: receiver dropped; aborting upstream stream");
                                    return;
                                }
                            } else {
                                hasher.update(&bytes);
                                if enqueue(&tx_task, &byte_budget, bytes).await.is_err() {
                                    tracing::warn!("downstream send failed: receiver dropped; aborting upstream stream");
                                    return;
                                }
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
        };
        match redactor.finish() {
            Ok(outputs) => {
                for output in outputs {
                    let bytes = match output {
                        OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => bytes,
                    };
                    if is_sse {
                        if forward_stream_events(
                            done_detector.inspect(bytes, &private_key, &mut hasher),
                            &tx_task,
                            &byte_budget,
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                    } else {
                        hasher.update(&bytes);
                        if enqueue(&tx_task, &byte_budget, bytes).await.is_err() {
                            tracing::warn!("downstream send failed: receiver dropped; aborting upstream stream");
                            return;
                        }
                    }
                }
            }
            Err(error) => tracing::warn!("upstream stream rejected at end: {:?}", error),
        }
        if is_sse
            && forward_stream_events(
                done_detector.finish(&mut hasher),
                &tx_task,
                &byte_budget,
            )
            .await
            .is_err()
        {
            return;
        }
        if reached_eof {
            tracing::info!(
                redaction_receipt = %hasher.finalize().to_hex(),
                "Redaction stream completed successfully"
            );
        }
    }.instrument(request_span));

    drop(tx);
    let mut response = Response::builder();
    if let Some(content_type) = upstream_content_type {
        response = response.header("content-type", content_type);
    }
    response.body(Body::new(BudgetedBody::new(rx))).unwrap()
}

fn contains_body_limit_error(error: &(dyn Error + 'static)) -> bool {
    if error
        .downcast_ref::<RequestBodyError>()
        .is_some_and(|error| matches!(error, RequestBodyError::LimitExceeded { .. }))
    {
        return true;
    }
    error.source().is_some_and(contains_body_limit_error)
}

fn build_proxy_audit_frame(receipt: &str, signature: &str) -> Bytes {
    let body = format!(
        "\nevent: proxy_audit\ndata: {{\"receipt\": \"{}\", \"signature\": \"{}\"}}\n\n",
        receipt, signature
    );
    Bytes::copy_from_slice(body.as_bytes())
}

async fn forward_stream_events(
    events: Vec<StreamEvent>,
    sender: &crate::budget_queue::SegmentSender,
    budget: &ByteBudget,
) -> Result<(), ()> {
    for event in events {
        let bytes = match event {
            StreamEvent::Data(bytes)
            | StreamEvent::AuditReceipt(bytes)
            | StreamEvent::DoneMarker(bytes) => bytes,
        };
        enqueue(sender, budget, bytes).await.map_err(|_| ())?;
    }
    Ok(())
}

#[derive(Default)]
pub struct DoneDetector {
    trailing: BytesMut,
    completed: bool,
}

impl DoneDetector {
    pub fn inspect(
        &mut self,
        bytes: Bytes,
        private_key: &SigningKey,
        hasher: &mut blake3::Hasher,
    ) -> Vec<StreamEvent> {
        if self.completed {
            return vec![StreamEvent::Data(bytes)];
        }
        let marker_len = SSE_DONE_MARKER.len();
        if let Some(start) = bytes
            .windows(marker_len)
            .position(|window| window == SSE_DONE_MARKER)
        {
            let mut events = Vec::new();
            if !self.trailing.is_empty() {
                let trailing = self.trailing.split().freeze();
                hasher.update(&trailing);
                events.push(StreamEvent::Data(trailing));
            }
            let before_done = bytes.slice(..start);
            if !before_done.is_empty() {
                hasher.update(&before_done);
                events.push(StreamEvent::Data(before_done));
            }
            events.extend(self.receipt_events(bytes.slice(start..), private_key, hasher));
            return events;
        }

        let probe_len = bytes.len().min(marker_len - 1);
        if !self.trailing.is_empty() {
            let mut probe = [0u8; SSE_DONE_MARKER.len() * 2];
            let trailing_len = self.trailing.len();
            probe[..trailing_len].copy_from_slice(&self.trailing);
            probe[trailing_len..trailing_len + probe_len].copy_from_slice(&bytes[..probe_len]);
            if let Some(start) = probe[..trailing_len + probe_len]
                .windows(marker_len)
                .position(|window| window == SSE_DONE_MARKER)
            {
                let current_start = marker_len - (trailing_len - start);
                let before = self.trailing.split_to(start).freeze();
                self.trailing.clear();
                let mut marker = BytesMut::with_capacity(marker_len);
                marker.extend_from_slice(&probe[start..start + marker_len]);
                let mut events = Vec::new();
                if !before.is_empty() {
                    hasher.update(&before);
                    events.push(StreamEvent::Data(before));
                }
                let done = marker.freeze();
                events.extend(self.receipt_events(done, private_key, hasher));
                if current_start < bytes.len() {
                    events.push(StreamEvent::Data(bytes.slice(current_start..)));
                }
                return events;
            }
        }

        let retain_len = marker_len - 1;
        if bytes.len() >= retain_len {
            if !self.trailing.is_empty() {
                let trailing = self.trailing.split().freeze();
                hasher.update(&trailing);
            }
            let emit_len = bytes.len() - retain_len;
            let data = bytes.slice(..emit_len);
            if !data.is_empty() {
                hasher.update(&data);
            }
            self.trailing.extend_from_slice(&bytes[emit_len..]);
            if data.is_empty() {
                Vec::new()
            } else {
                vec![StreamEvent::Data(data)]
            }
        } else {
            let mut held = BytesMut::with_capacity(self.trailing.len() + bytes.len());
            held.extend_from_slice(&self.trailing);
            held.extend_from_slice(&bytes);
            self.trailing.clear();
            let emit_len = held.len().saturating_sub(retain_len);
            let held = held.freeze();
            if emit_len == 0 {
                self.trailing.extend_from_slice(&held);
                Vec::new()
            } else {
                let data = held.slice(..emit_len);
                hasher.update(&data);
                self.trailing.extend_from_slice(&held[emit_len..]);
                vec![StreamEvent::Data(data)]
            }
        }
    }

    fn receipt_events(
        &mut self,
        done: Bytes,
        private_key: &SigningKey,
        hasher: &mut blake3::Hasher,
    ) -> Vec<StreamEvent> {
        let digest = hasher.finalize().to_hex().to_string();
        let signature = private_key.sign(digest.as_bytes());
        let audit = build_proxy_audit_frame(&digest, &B64Std.encode(signature.to_bytes()));
        self.completed = true;
        vec![
            StreamEvent::AuditReceipt(audit),
            StreamEvent::DoneMarker(done),
        ]
    }

    pub fn finish(&mut self, hasher: &mut blake3::Hasher) -> Vec<StreamEvent> {
        if self.trailing.is_empty() {
            return Vec::new();
        }
        let trailing = self.trailing.split().freeze();
        hasher.update(&trailing);
        vec![StreamEvent::Data(trailing)]
    }

    fn shutdown_events(
        &mut self,
        private_key: &SigningKey,
        hasher: &mut blake3::Hasher,
    ) -> Vec<StreamEvent> {
        if self.completed {
            return Vec::new();
        }
        let mut events = Vec::new();
        if !self.trailing.is_empty() {
            let trailing = self.trailing.split().freeze();
            hasher.update(&trailing);
            events.push(StreamEvent::Data(trailing));
        }
        events.extend(self.receipt_events(
            Bytes::from_static(b"data: [ERROR: KILLED BY SHUTDOWN]\n\n"),
            private_key,
            hasher,
        ));
        events
    }
}
#[test]
fn proxy_audit_frame_is_emitted_before_done_event_and_signature_checks() {
    use base64::engine::general_purpose::STANDARD as StdBase64;
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier};

    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let receipt_hash = "9f3d74c42bb0c3d4d908a3d77dcb75a6c4df9c1d89b24fd9ba3c4405d5a2dc81";
    let signature = key.sign(receipt_hash.as_bytes());
    let signature_b64 = StdBase64.encode(signature.to_bytes());
    let frame = build_proxy_audit_frame(receipt_hash, &signature_b64);
    let done = Bytes::from_static(b"data: [DONE]\n\n");
    let combined = [frame.as_ref(), done.as_ref()].concat();

    let frame_index = combined
        .windows(frame.len())
        .position(|window| window == frame.as_ref())
        .expect("proxy_audit frame should be emitted before [DONE]");
    let done_index = combined
        .windows(done.len())
        .position(|window| window == done.as_ref())
        .expect("final [DONE] signal should be present");

    assert!(frame_index < done_index, "proxy_audit must precede [DONE]");

    let signature_bytes = StdBase64.decode(signature_b64.as_bytes()).unwrap();
    let signature = Signature::from_slice(&signature_bytes).unwrap();
    key.verifying_key()
        .verify(receipt_hash.as_bytes(), &signature)
        .unwrap();
}

#[test]
fn fragmented_done_marker_emits_audit_receipt() {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut detector = DoneDetector::default();
    let mut hasher = blake3::Hasher::new();
    let mut output = Vec::new();

    for byte in b"data: {\"content\":\"safe\"}\n\ndata: [DONE]\n\n" {
        let events = detector.inspect(
            Bytes::copy_from_slice(std::slice::from_ref(byte)),
            &key,
            &mut hasher,
        );
        output.extend(events.into_iter().map(|event| match event {
            StreamEvent::Data(bytes)
            | StreamEvent::AuditReceipt(bytes)
            | StreamEvent::DoneMarker(bytes) => bytes,
        }));
    }

    let rendered = output
        .iter()
        .flat_map(|segment| segment.iter().copied())
        .collect::<Vec<_>>();
    let audit_index = rendered
        .windows(b"event: proxy_audit".len())
        .position(|window| window == b"event: proxy_audit")
        .expect("fragmented marker must emit an audit event");
    let done_index = rendered
        .windows(SSE_DONE_MARKER.len())
        .position(|window| window == SSE_DONE_MARKER)
        .expect("fragmented marker must be preserved");
    assert!(audit_index < done_index);
}

#[test]
fn fragmented_done_marker_preserves_bytes_and_hashes_payload_once() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let input = b"data: safe\n\ndata: [DONE]\n\n";
    let marker_start = input
        .windows(SSE_DONE_MARKER.len())
        .position(|window| window == SSE_DONE_MARKER)
        .unwrap();
    let expected_payload = &input[..marker_start];
    let expected_digest = blake3::hash(expected_payload).to_hex().to_string();
    let mut detector = DoneDetector::default();
    let mut hasher = blake3::Hasher::new();
    let mut output = Vec::new();

    for byte in input {
        let events = detector.inspect(
            Bytes::copy_from_slice(std::slice::from_ref(byte)),
            &key,
            &mut hasher,
        );
        output.extend(events.into_iter().map(|event| match event {
            StreamEvent::Data(bytes)
            | StreamEvent::AuditReceipt(bytes)
            | StreamEvent::DoneMarker(bytes) => bytes,
        }));
    }

    let rendered = output
        .iter()
        .flat_map(|segment| segment.iter().copied())
        .collect::<Vec<_>>();
    let audit_start = rendered
        .windows(b"event: proxy_audit".len())
        .position(|window| window == b"event: proxy_audit")
        .unwrap();
    let audit_start = rendered[..audit_start]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap();
    let audit_end = rendered[audit_start..]
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|offset| audit_start + offset + 2)
        .unwrap();
    let mut without_audit = rendered[..audit_start].to_vec();
    without_audit.extend_from_slice(&rendered[audit_end..]);

    assert_eq!(without_audit, input);
    assert_eq!(&rendered[..audit_start], expected_payload);
    assert!(String::from_utf8_lossy(&rendered[audit_start..audit_end]).contains(&expected_digest));
}
