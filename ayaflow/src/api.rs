use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        ConnectInfo, Query, State, WebSocketUpgrade,
    },
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use ipnet::IpNet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};

use crate::config::RuntimeSettings;
use crate::state::TrafficState;
use crate::storage::{HistoryPage, HistoryQuery, HistoryRowType, Storage};

pub struct AppState {
    pub traffic: Arc<TrafficState>,
    pub storage: Arc<Storage>,
    pub start_time: Instant,
    pub runtime: RuntimeSettings,
}

struct Metrics {
    registry: Registry,
    packets_total: Counter,
    bytes_total: Counter,
    active_connections: Gauge,
    deep_inspect_packets_total: Counter,
    domains_resolved_total: Counter,
}

impl Metrics {
    fn new() -> Self {
        let mut registry = Registry::default();
        let packets_total = Counter::default();
        let bytes_total = Counter::default();
        let active_connections = Gauge::default();
        let deep_inspect_packets_total = Counter::default();
        let domains_resolved_total = Counter::default();

        registry.register(
            "ayaflow_packets",
            "Total number of observed packets",
            packets_total.clone(),
        );
        registry.register("ayaflow_bytes", "Total bytes observed", bytes_total.clone());
        registry.register(
            "ayaflow_active_connections",
            "Currently active connections",
            active_connections.clone(),
        );
        registry.register(
            "ayaflow_deep_inspect_packets",
            "Total L7 payload events processed by deep inspection",
            deep_inspect_packets_total.clone(),
        );
        registry.register(
            "ayaflow_domains_resolved",
            "Total domains resolved from DNS queries and TLS SNI",
            domains_resolved_total.clone(),
        );

        Self {
            registry,
            packets_total,
            bytes_total,
            active_connections,
            deep_inspect_packets_total,
            domains_resolved_total,
        }
    }
}

#[derive(Serialize)]
pub struct HealthResponse {
    status: String,
    active_connections: usize,
    total_packets: u64,
    runtime: RuntimeSettings,
}

#[derive(Serialize)]
pub struct StatsResponse {
    uptime_seconds: u64,
    total_packets: u64,
    total_bytes: u64,
    active_connections: usize,
    packets_per_second: f64,
    bytes_per_second: f64,
    runtime: RuntimeSettings,
}

#[derive(Debug, Deserialize, Default)]
pub struct RawHistoryParams {
    limit: Option<String>,
    offset: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
    protocol: Option<String>,
    ip: Option<String>,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    port: Option<String>,
    src_port: Option<String>,
    dst_port: Option<String>,
    direction: Option<String>,
    domain: Option<String>,
    row_type: Option<String>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorPayload,
}

#[derive(Serialize)]
struct ErrorPayload {
    code: &'static str,
    message: String,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: ErrorPayload {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

pub fn router(state: Arc<AppState>, allowed_ips: &[String]) -> Router {
    let metrics = Arc::new(Metrics::new());

    let mut app = Router::new()
        .route("/api/live", get(get_live_stats))
        .route("/api/history", get(get_history))
        .route("/api/health", get(get_health))
        .route("/api/stats", get(get_stats))
        .route("/api/stream", get(ws_handler))
        .route(
            "/metrics",
            get({
                let metrics = metrics.clone();
                let state = state.clone();
                move || get_metrics(state.clone(), metrics.clone())
            }),
        );

    if !allowed_ips.is_empty() {
        let nets: Arc<Vec<IpNet>> = Arc::new(
            allowed_ips
                .iter()
                .filter_map(|value| value.parse::<IpNet>().ok())
                .collect(),
        );
        app = app.layer(middleware::from_fn(move |req, next| {
            let nets = nets.clone();
            ip_allowlist(req, next, nets)
        }));
    }

    app.with_state(state)
}

async fn ip_allowlist(
    req: axum::extract::Request,
    next: middleware::Next,
    allowed: Arc<Vec<IpNet>>,
) -> Response {
    if let Some(connect_info) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        let ip = connect_info.0.ip();
        if allowed.iter().any(|net| net.contains(&ip)) {
            return next.run(req).await.into_response();
        }
        return ApiError::forbidden(format!("access denied for source IP {}", ip)).into_response();
    }

    next.run(req).await.into_response()
}

async fn get_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        active_connections: state.traffic.active_connections.load(Ordering::Relaxed),
        total_packets: state.traffic.total_packets.load(Ordering::Relaxed),
        runtime: state.runtime.clone(),
    })
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let uptime = state.start_time.elapsed().as_secs();
    let total_packets = state.traffic.total_packets.load(Ordering::Relaxed);
    let total_bytes = state.traffic.total_bytes.load(Ordering::Relaxed);
    let active_connections = state.traffic.active_connections.load(Ordering::Relaxed);

    Json(StatsResponse {
        uptime_seconds: uptime,
        total_packets,
        total_bytes,
        active_connections,
        packets_per_second: if uptime > 0 {
            total_packets as f64 / uptime as f64
        } else {
            0.0
        },
        bytes_per_second: if uptime > 0 {
            total_bytes as f64 / uptime as f64
        } else {
            0.0
        },
        runtime: state.runtime.clone(),
    })
}

async fn get_live_stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut connections: Vec<_> = state
        .traffic
        .connections
        .iter()
        .map(|entry| {
            let (key, stats) = entry.pair();
            serde_json::json!({
                "connection": key,
                "stats": stats
            })
        })
        .collect();

    connections.sort_by(|a, b| {
        let count_a = a["stats"]["packets_count"].as_u64().unwrap_or(0);
        let count_b = b["stats"]["packets_count"].as_u64().unwrap_or(0);
        count_b.cmp(&count_a)
    });
    connections.truncate(50);

    Json(serde_json::json!({
        "connections": connections,
        "total_packets": state.traffic.total_packets.load(Ordering::Relaxed),
        "total_bytes": state.traffic.total_bytes.load(Ordering::Relaxed),
    }))
}

async fn get_history(
    State(state): State<Arc<AppState>>,
    Query(raw): Query<RawHistoryParams>,
) -> Result<Json<HistoryPage>, ApiError> {
    let query = parse_history_query(raw)?;
    state
        .storage
        .query_history(&query)
        .map(Json)
        .map_err(|e| ApiError::internal(format!("failed to query history: {}", e)))
}

fn parse_history_query(raw: RawHistoryParams) -> Result<HistoryQuery, ApiError> {
    let limit = parse_usize(raw.limit.as_deref(), "limit")?
        .unwrap_or(100)
        .min(1000);
    let offset = parse_usize(raw.offset.as_deref(), "offset")?.unwrap_or(0);
    let start_time = parse_i64(raw.start_time.as_deref(), "start_time")?;
    let end_time = parse_i64(raw.end_time.as_deref(), "end_time")?;
    let port = parse_u16(raw.port.as_deref(), "port")?;
    let src_port = parse_u16(raw.src_port.as_deref(), "src_port")?;
    let dst_port = parse_u16(raw.dst_port.as_deref(), "dst_port")?;

    if let (Some(start), Some(end)) = (start_time, end_time) {
        if start > end {
            return Err(ApiError::bad_request(
                "`start_time` must be less than or equal to `end_time`",
            ));
        }
    }

    let row_type = match raw.row_type.as_deref() {
        Some("raw") => Some(HistoryRowType::Raw),
        Some("aggregated") => Some(HistoryRowType::Aggregated),
        Some(other) => {
            return Err(ApiError::bad_request(format!(
                "invalid row_type `{}`; expected `raw` or `aggregated`",
                other
            )))
        }
        None => None,
    };

    Ok(HistoryQuery {
        limit,
        offset,
        start_time,
        end_time,
        protocol: raw.protocol,
        ip: raw.ip,
        src_ip: raw.src_ip,
        dst_ip: raw.dst_ip,
        port,
        src_port,
        dst_port,
        direction: raw.direction,
        domain: raw.domain,
        row_type,
    })
}

fn parse_usize(value: Option<&str>, field: &str) -> Result<Option<usize>, ApiError> {
    value
        .map(|value| {
            value.parse::<usize>().map_err(|_| {
                ApiError::bad_request(format!("invalid `{}` value `{}`", field, value))
            })
        })
        .transpose()
}

fn parse_i64(value: Option<&str>, field: &str) -> Result<Option<i64>, ApiError> {
    value
        .map(|value| {
            value.parse::<i64>().map_err(|_| {
                ApiError::bad_request(format!("invalid `{}` value `{}`", field, value))
            })
        })
        .transpose()
}

fn parse_u16(value: Option<&str>, field: &str) -> Result<Option<u16>, ApiError> {
    value
        .map(|value| {
            value.parse::<u16>().map_err(|_| {
                ApiError::bad_request(format!("invalid `{}` value `{}`", field, value))
            })
        })
        .transpose()
}

async fn get_metrics(state: Arc<AppState>, metrics: Arc<Metrics>) -> impl IntoResponse {
    let total_packets = state.traffic.total_packets.load(Ordering::Relaxed);
    let total_bytes = state.traffic.total_bytes.load(Ordering::Relaxed);
    let active = state.traffic.active_connections.load(Ordering::Relaxed);

    let current_packets = metrics.packets_total.get();
    if total_packets > current_packets {
        metrics
            .packets_total
            .inc_by(total_packets - current_packets);
    }
    let current_bytes = metrics.bytes_total.get();
    if total_bytes > current_bytes {
        metrics.bytes_total.inc_by(total_bytes - current_bytes);
    }
    metrics.active_connections.set(active as i64);

    let deep_packets = state.traffic.deep_inspect_packets.load(Ordering::Relaxed);
    let current_deep = metrics.deep_inspect_packets_total.get();
    if deep_packets > current_deep {
        metrics
            .deep_inspect_packets_total
            .inc_by(deep_packets - current_deep);
    }

    let domains = state.traffic.domains_resolved.load(Ordering::Relaxed);
    let current_domains = metrics.domains_resolved_total.get();
    if domains > current_domains {
        metrics
            .domains_resolved_total
            .inc_by(domains - current_domains);
    }

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        buf,
    )
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

    loop {
        interval.tick().await;

        let stats = serde_json::json!({
            "total_packets": state.traffic.total_packets.load(Ordering::Relaxed),
            "total_bytes": state.traffic.total_bytes.load(Ordering::Relaxed),
            "active_connections": state.traffic.active_connections.load(Ordering::Relaxed),
        });

        if socket.send(Message::Text(stats.to_string())).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    use crate::state::{PacketMetadata, TrafficState};

    fn test_runtime() -> RuntimeSettings {
        RuntimeSettings {
            interface: "eth0".to_string(),
            port: 3000,
            db_path: ":memory:".to_string(),
            connection_timeout: 60,
            data_retention_seconds: Some(60),
            aggregation_window_seconds: 0,
            resolve_dns: true,
            deep_inspect: true,
            enable_ipv6: true,
            allowed_ips: vec!["127.0.0.1/32".to_string()],
        }
    }

    fn sample_packet() -> PacketMetadata {
        PacketMetadata {
            timestamp: 123,
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "1.1.1.1".to_string(),
            src_port: 4040,
            dst_port: 443,
            protocol: "TCP".to_string(),
            length: 256,
            direction: "egress".to_string(),
            src_hostname: None,
            dst_hostname: None,
            domain: Some("example.com".to_string()),
        }
    }

    fn test_app(allowed_ips: &[String]) -> Router {
        let traffic = Arc::new(TrafficState::new());
        let packet = sample_packet();
        traffic.update(&packet);
        traffic.deep_inspect_packets.store(2, Ordering::Relaxed);
        traffic.domains_resolved.store(1, Ordering::Relaxed);

        let storage = Arc::new(Storage::new(":memory:").unwrap());
        storage.insert_packet(&packet).unwrap();

        let state = Arc::new(AppState {
            traffic,
            storage,
            start_time: Instant::now(),
            runtime: test_runtime(),
        });

        router(state, allowed_ips)
    }

    async fn response_json(response: Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn health_includes_runtime_configuration() {
        let response = test_app(&[])
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["runtime"]["interface"], "eth0");
        assert_eq!(body["runtime"]["deep_inspect"], true);
    }

    #[tokio::test]
    async fn history_supports_filters_and_pagination_metadata() {
        let response = test_app(&[])
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/history?limit=1&offset=0&domain=example.com&row_type=raw")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["returned"], 1);
        assert_eq!(body["items"][0]["row_type"], "raw");
        assert_eq!(body["items"][0]["packet_count"], 1);
    }

    #[tokio::test]
    async fn allowlist_returns_structured_forbidden_response() {
        let app = test_app(&["127.0.0.1/32".to_string()]);
        let request = axum::http::Request::builder()
            .uri("/api/health")
            .extension(ConnectInfo(SocketAddr::from(([192, 168, 1, 25], 12345))))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response_json(response).await;
        assert_eq!(body["error"]["code"], "forbidden");
    }

    #[tokio::test]
    async fn metrics_endpoint_exposes_prometheus_counters() {
        let response = test_app(&[])
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(text.contains("ayaflow_packets_total"));
        assert!(text.contains("ayaflow_active_connections"));
        assert!(text.contains("ayaflow_domains_resolved_total"));
    }

    #[tokio::test]
    async fn invalid_history_query_returns_structured_error() {
        let response = test_app(&[])
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/history?limit=not-a-number")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await;
        assert_eq!(body["error"]["code"], "bad_request");
    }
}
