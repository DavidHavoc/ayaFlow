use crate::state::TrafficState;
use crate::storage::Storage;
use axum::{
    extract::{ConnectInfo, Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use ipnet::IpNet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

pub struct AppState {
    pub traffic: Arc<TrafficState>,
    pub storage: Arc<Storage>,
    pub start_time: Instant,
}

// ── Prometheus Metrics ────────────────────────────────────────────────────────

struct Metrics {
    registry: Registry,
    packets_total: Counter,
    bytes_total: Counter,
    active_connections: Gauge,
}

impl Metrics {
    fn new() -> Self {
        let mut registry = Registry::default();
        let packets_total = Counter::default();
        let bytes_total = Counter::default();
        let active_connections = Gauge::default();

        registry.register(
            "ayaflow_packets_total",
            "Total number of observed packets",
            packets_total.clone(),
        );
        registry.register(
            "ayaflow_bytes_total",
            "Total bytes observed",
            bytes_total.clone(),
        );
        registry.register(
            "ayaflow_active_connections",
            "Currently active connections",
            active_connections.clone(),
        );

        Self {
            registry,
            packets_total,
            bytes_total,
            active_connections,
        }
    }
}

// ── Response Types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HealthResponse {
    status: String,
    active_connections: usize,
    total_packets: u64,
}

#[derive(Serialize)]
pub struct StatsResponse {
    uptime_seconds: u64,
    total_packets: u64,
    total_bytes: u64,
    active_connections: usize,
    packets_per_second: f64,
    bytes_per_second: f64,
}

#[derive(Deserialize)]
pub struct HistoryParams {
    limit: Option<usize>,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: Arc<AppState>, allowed_ips: &[String]) -> Router {
    let metrics = Arc::new(Metrics::new());

    let mut app = Router::new()
        .route("/api/live", get(get_live_stats))
        .route("/api/history", get(get_history))
        .route("/api/health", get(get_health))
        .route("/api/stats", get(get_stats))
        .route("/api/stream", get(ws_handler))
        .route("/metrics", get({
            let m = metrics.clone();
            let s = state.clone();
            move || get_metrics(s.clone(), m.clone())
        }));

    // Apply IP allowlist middleware if configured.
    if !allowed_ips.is_empty() {
        let nets: Arc<Vec<IpNet>> = Arc::new(
            allowed_ips
                .iter()
                .filter_map(|s| s.parse::<IpNet>().ok())
                .collect(),
        );
        app = app.layer(middleware::from_fn(move |req, next| {
            let nets = nets.clone();
            ip_allowlist(req, next, nets)
        }));
    }

    app.with_state(state)
}

// ── IP Allowlist Middleware ────────────────────────────────────────────────────

async fn ip_allowlist(
    req: axum::extract::Request,
    next: middleware::Next,
    allowed: Arc<Vec<IpNet>>,
) -> impl IntoResponse {
    if let Some(connect_info) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        let ip = connect_info.0.ip();
        if allowed.iter().any(|net| net.contains(&ip)) {
            return next.run(req).await.into_response();
        }
        return StatusCode::FORBIDDEN.into_response();
    }
    // If there is no ConnectInfo, allow (should not happen with into_make_service_with_connect_info).
    next.run(req).await.into_response()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn get_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        active_connections: state.traffic.active_connections.load(Ordering::Relaxed),
        total_packets: state.traffic.total_packets.load(Ordering::Relaxed),
    })
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let uptime = state.start_time.elapsed().as_secs();
    let total_packets = state.traffic.total_packets.load(Ordering::Relaxed);
    let total_bytes = state.traffic.total_bytes.load(Ordering::Relaxed);
    let active_connections = state.traffic.active_connections.load(Ordering::Relaxed);

    let packets_per_second = if uptime > 0 {
        total_packets as f64 / uptime as f64
    } else {
        0.0
    };
    let bytes_per_second = if uptime > 0 {
        total_bytes as f64 / uptime as f64
    } else {
        0.0
    };

    Json(StatsResponse {
        uptime_seconds: uptime,
        total_packets,
        total_bytes,
        active_connections,
        packets_per_second,
        bytes_per_second,
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
    Query(params): Query<HistoryParams>,
) -> Json<serde_json::Value> {
    let limit = params.limit.unwrap_or(100).min(1000);
    match state.storage.query_history(limit) {
        Ok(data) => Json(serde_json::json!(data)),
        Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
    }
}

async fn get_metrics(state: Arc<AppState>, metrics: Arc<Metrics>) -> impl IntoResponse {
    // Sync counters from atomic state into prometheus gauges/counters.
    let total_pkts = state.traffic.total_packets.load(Ordering::Relaxed);
    let total_b = state.traffic.total_bytes.load(Ordering::Relaxed);
    let active = state.traffic.active_connections.load(Ordering::Relaxed);

    // Counter::inner() returns the current value; we need to set to the absolute value.
    // prometheus-client Counters are monotonic so we increment by the delta.
    let current_pkts = metrics.packets_total.get();
    if total_pkts > current_pkts {
        metrics.packets_total.inc_by(total_pkts - current_pkts);
    }
    let current_b = metrics.bytes_total.get();
    if total_b > current_b {
        metrics.bytes_total.inc_by(total_b - current_b);
    }
    metrics.active_connections.set(active as i64);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        buf,
    )
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
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

        if socket
            .send(Message::Text(stats.to_string().into()))
            .await
            .is_err()
        {
            break;
        }
    }
}
