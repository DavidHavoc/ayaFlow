use crate::state::TrafficState;
use crate::storage::Storage;
use axum::{
    extract::{Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

pub struct AppState {
    pub traffic: Arc<TrafficState>,
    pub storage: Arc<Storage>,
    pub start_time: Instant,
}

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

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/live", get(get_live_stats))
        .route("/api/history", get(get_history))
        .route("/api/health", get(get_health))
        .route("/api/stats", get(get_stats))
        .route("/api/stream", get(ws_handler))
        .with_state(state)
}

async fn get_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        active_connections: state.traffic.active_connections.load(std::sync::atomic::Ordering::Relaxed),
        total_packets: state.traffic.total_packets.load(std::sync::atomic::Ordering::Relaxed),
    })
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let uptime = state.start_time.elapsed().as_secs();
    let total_packets = state.traffic.total_packets.load(std::sync::atomic::Ordering::Relaxed);
    let total_bytes = state.traffic.total_bytes.load(std::sync::atomic::Ordering::Relaxed);
    let active_connections = state.traffic.active_connections.load(std::sync::atomic::Ordering::Relaxed);

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
    // Return a snapshot of current connections
    // Limiting to top 50 for performance
    let mut connections: Vec<_> = state.traffic.connections
        .iter()
        .map(|entry| {
            let (key, stats) = entry.pair();
            serde_json::json!({
                "connection": key,
                "stats": stats
            })
        })
        .collect();

    // Sort by recent activity/packets (naive sort)
    connections.sort_by(|a, b| {
        let count_a = a["stats"]["packets_count"].as_u64().unwrap_or(0);
        let count_b = b["stats"]["packets_count"].as_u64().unwrap_or(0);
        count_b.cmp(&count_a)
    });

    connections.truncate(50);

    Json(serde_json::json!({
        "connections": connections,
        "total_packets": state.traffic.total_packets.load(std::sync::atomic::Ordering::Relaxed),
        "total_bytes": state.traffic.total_bytes.load(std::sync::atomic::Ordering::Relaxed),
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

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    // Simple polling implementation - sends stats every second
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

    loop {
        interval.tick().await;

        let stats = serde_json::json!({
            "total_packets": state.traffic.total_packets.load(std::sync::atomic::Ordering::Relaxed),
            "total_bytes": state.traffic.total_bytes.load(std::sync::atomic::Ordering::Relaxed),
            "active_connections": state.traffic.active_connections.load(std::sync::atomic::Ordering::Relaxed),
        });

        if socket.send(Message::Text(stats.to_string().into())).await.is_err() {
            break;
        }
    }
}
