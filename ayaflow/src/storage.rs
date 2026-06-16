use std::collections::HashMap;
use std::sync::Arc;

use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, Result};
use serde::Serialize;
use tokio::sync::mpsc::Receiver;
use tokio::time::{interval, Duration};

use crate::state::{AggregatedBucket, PacketMetadata};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoryRowType {
    Raw,
    Aggregated,
}

impl HistoryRowType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Aggregated => "aggregated",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryRecord {
    pub timestamp: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
    pub direction: String,
    pub src_hostname: Option<String>,
    pub dst_hostname: Option<String>,
    pub domain: Option<String>,
    pub row_type: String,
    pub packet_count: u64,
}

#[derive(Debug, Clone, Default)]
pub struct HistoryQuery {
    pub limit: usize,
    pub offset: usize,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub protocol: Option<String>,
    pub ip: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub port: Option<u16>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub direction: Option<String>,
    pub domain: Option<String>,
    pub row_type: Option<HistoryRowType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryPage {
    pub items: Vec<HistoryRecord>,
    pub limit: usize,
    pub offset: usize,
    pub returned: usize,
    pub total: usize,
    pub has_more: bool,
}

#[derive(Clone)]
pub struct Storage {
    conn: Arc<std::sync::Mutex<Connection>>,
}

impl Storage {
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;

        let _: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |row| row.get(0))?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER,
                direction TEXT,
                src_hostname TEXT,
                dst_hostname TEXT,
                domain TEXT,
                row_type TEXT NOT NULL DEFAULT 'raw',
                packet_count INTEGER NOT NULL DEFAULT 1
            )",
            [],
        )?;

        let _ = conn.execute("ALTER TABLE packets ADD COLUMN src_hostname TEXT", []);
        let _ = conn.execute("ALTER TABLE packets ADD COLUMN dst_hostname TEXT", []);
        let _ = conn.execute("ALTER TABLE packets ADD COLUMN domain TEXT", []);
        let _ = conn.execute("ALTER TABLE packets ADD COLUMN direction TEXT", []);
        let _ = conn.execute(
            "ALTER TABLE packets ADD COLUMN row_type TEXT NOT NULL DEFAULT 'raw'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE packets ADD COLUMN packet_count INTEGER NOT NULL DEFAULT 1",
            [],
        );

        conn.execute(
            "UPDATE packets SET row_type = 'raw' WHERE row_type IS NULL OR row_type = ''",
            [],
        )?;
        conn.execute(
            "UPDATE packets SET packet_count = 1 WHERE packet_count IS NULL OR packet_count < 1",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_history_filters ON packets(timestamp, protocol, direction, domain, row_type)",
            [],
        )?;

        Ok(Self {
            conn: Arc::new(std::sync::Mutex::new(conn)),
        })
    }

    pub async fn run_writer(&self, rx: Receiver<PacketMetadata>, aggregation_window_seconds: u64) {
        if aggregation_window_seconds == 0 {
            self.run_writer_raw(rx).await;
        } else {
            self.run_writer_aggregated(rx, aggregation_window_seconds)
                .await;
        }
    }

    pub fn insert_packet(&self, packet: &PacketMetadata) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        Self::insert_raw_packets(&tx, std::slice::from_ref(packet))?;
        tx.commit()?;
        Ok(())
    }

    async fn run_writer_raw(&self, mut rx: Receiver<PacketMetadata>) {
        let mut buffer = Vec::new();
        let mut ticker = interval(Duration::from_secs(2));

        loop {
            tokio::select! {
                message = rx.recv() => {
                    match message {
                        Some(packet) => {
                            buffer.push(packet);
                            if buffer.len() >= 1000 {
                                self.flush(&mut buffer);
                            }
                        }
                        None => {
                            if !buffer.is_empty() {
                                self.flush(&mut buffer);
                            }
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if !buffer.is_empty() {
                        self.flush(&mut buffer);
                    }
                }
            }
        }
    }

    async fn run_writer_aggregated(&self, mut rx: Receiver<PacketMetadata>, window_secs: u64) {
        let mut buckets: HashMap<String, AggregatedBucket> = HashMap::new();
        let mut ticker = interval(Duration::from_secs(window_secs));

        loop {
            tokio::select! {
                message = rx.recv() => {
                    match message {
                        Some(packet) => {
                            let key = format!(
                                "{}:{} -> {}:{}",
                                packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port
                            );
                            buckets
                                .entry(key)
                                .and_modify(|bucket| bucket.merge(&packet))
                                .or_insert_with(|| AggregatedBucket::from_packet(&packet));
                        }
                        None => {
                            if !buckets.is_empty() {
                                self.flush_aggregated(&mut buckets);
                            }
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if !buckets.is_empty() {
                        self.flush_aggregated(&mut buckets);
                    }
                }
            }
        }
    }

    fn flush(&self, buffer: &mut Vec<PacketMetadata>) {
        let mut conn = self.conn.lock().unwrap();
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Failed to start transaction: {}", e);
                return;
            }
        };

        if let Err(e) = Self::insert_raw_packets(&tx, buffer) {
            eprintln!("Failed to insert packet batch: {}", e);
            return;
        }

        if let Err(e) = tx.commit() {
            eprintln!("Failed to commit transaction: {}", e);
        } else {
            buffer.clear();
        }
    }

    fn flush_aggregated(&self, buckets: &mut HashMap<String, AggregatedBucket>) {
        let mut conn = self.conn.lock().unwrap();
        let tx = match conn.transaction() {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Failed to start transaction: {}", e);
                return;
            }
        };

        if let Err(e) = Self::insert_aggregated_buckets(&tx, buckets) {
            eprintln!("Failed to insert aggregated rows: {}", e);
            return;
        }

        if let Err(e) = tx.commit() {
            eprintln!("Failed to commit transaction: {}", e);
        } else {
            buckets.clear();
        }
    }

    fn insert_raw_packets(tx: &rusqlite::Transaction<'_>, buffer: &[PacketMetadata]) -> Result<()> {
        let mut stmt = tx.prepare(
            "INSERT INTO packets (
                timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length,
                direction, src_hostname, dst_hostname, domain, row_type, packet_count
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'raw', 1)",
        )?;

        for packet in buffer {
            stmt.execute(params![
                packet.timestamp,
                packet.src_ip,
                packet.dst_ip,
                packet.src_port,
                packet.dst_port,
                packet.protocol,
                packet.length,
                packet.direction,
                packet.src_hostname,
                packet.dst_hostname,
                packet.domain
            ])?;
        }

        Ok(())
    }

    fn insert_aggregated_buckets(
        tx: &rusqlite::Transaction<'_>,
        buckets: &HashMap<String, AggregatedBucket>,
    ) -> Result<()> {
        let mut stmt = tx.prepare(
            "INSERT INTO packets (
                timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length,
                direction, src_hostname, dst_hostname, domain, row_type, packet_count
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'aggregated', ?12)",
        )?;

        for bucket in buckets.values() {
            stmt.execute(params![
                bucket.first_timestamp,
                bucket.src_ip,
                bucket.dst_ip,
                bucket.src_port,
                bucket.dst_port,
                bucket.protocol,
                bucket.total_bytes as i64,
                bucket.direction,
                bucket.src_hostname,
                bucket.dst_hostname,
                bucket.domain,
                bucket.packet_count
            ])?;
        }

        Ok(())
    }

    pub fn query_history(&self, query: &HistoryQuery) -> Result<HistoryPage> {
        let (where_sql, params) = build_history_where_clause(query);
        let count_sql = format!("SELECT COUNT(*) FROM packets{where_sql}");
        let select_sql = format!(
            "SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, direction,
                    src_hostname, dst_hostname, domain, row_type, packet_count
             FROM packets{where_sql}
             ORDER BY timestamp DESC
             LIMIT ? OFFSET ?"
        );

        let conn = self.conn.lock().unwrap();
        let total: usize = conn.query_row(&count_sql, params_from_iter(params.iter()), |row| {
            row.get(0)
        })?;

        let mut select_params = params.clone();
        select_params.push(Value::Integer(query.limit as i64));
        select_params.push(Value::Integer(query.offset as i64));

        let mut stmt = conn.prepare(&select_sql)?;
        let rows = stmt.query_map(params_from_iter(select_params.iter()), |row| {
            Ok(HistoryRecord {
                timestamp: row.get(0)?,
                src_ip: row.get(1)?,
                dst_ip: row.get(2)?,
                src_port: row.get(3)?,
                dst_port: row.get(4)?,
                protocol: row.get(5)?,
                length: row.get(6)?,
                direction: row
                    .get::<_, Option<String>>(7)?
                    .unwrap_or_else(|| "ingress".to_string()),
                src_hostname: row.get(8)?,
                dst_hostname: row.get(9)?,
                domain: row.get(10)?,
                row_type: row
                    .get::<_, Option<String>>(11)?
                    .unwrap_or_else(|| HistoryRowType::Raw.as_str().to_string()),
                packet_count: row.get::<_, Option<u64>>(12)?.unwrap_or(1),
            })
        })?;

        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }

        Ok(HistoryPage {
            returned: items.len(),
            has_more: query.offset + items.len() < total,
            items,
            limit: query.limit,
            offset: query.offset,
            total,
        })
    }

    pub fn delete_old_data(&self, older_than_seconds: u64) -> Result<usize> {
        let cutoff_ms = chrono::Utc::now().timestamp_millis() - (older_than_seconds as i64 * 1000);
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM packets WHERE timestamp < ?1",
            params![cutoff_ms],
        )?;
        Ok(deleted)
    }
}

fn build_history_where_clause(query: &HistoryQuery) -> (String, Vec<Value>) {
    let mut clauses = Vec::new();
    let mut params = Vec::new();

    if let Some(start_time) = query.start_time {
        clauses.push("timestamp >= ?".to_string());
        params.push(Value::Integer(start_time));
    }
    if let Some(end_time) = query.end_time {
        clauses.push("timestamp <= ?".to_string());
        params.push(Value::Integer(end_time));
    }
    if let Some(protocol) = &query.protocol {
        clauses.push("LOWER(protocol) = LOWER(?)".to_string());
        params.push(Value::Text(protocol.clone()));
    }
    if let Some(ip) = &query.ip {
        clauses.push("(src_ip = ? OR dst_ip = ?)".to_string());
        params.push(Value::Text(ip.clone()));
        params.push(Value::Text(ip.clone()));
    }
    if let Some(src_ip) = &query.src_ip {
        clauses.push("src_ip = ?".to_string());
        params.push(Value::Text(src_ip.clone()));
    }
    if let Some(dst_ip) = &query.dst_ip {
        clauses.push("dst_ip = ?".to_string());
        params.push(Value::Text(dst_ip.clone()));
    }
    if let Some(port) = query.port {
        clauses.push("(src_port = ? OR dst_port = ?)".to_string());
        params.push(Value::Integer(i64::from(port)));
        params.push(Value::Integer(i64::from(port)));
    }
    if let Some(src_port) = query.src_port {
        clauses.push("src_port = ?".to_string());
        params.push(Value::Integer(i64::from(src_port)));
    }
    if let Some(dst_port) = query.dst_port {
        clauses.push("dst_port = ?".to_string());
        params.push(Value::Integer(i64::from(dst_port)));
    }
    if let Some(direction) = &query.direction {
        clauses.push("LOWER(direction) = LOWER(?)".to_string());
        params.push(Value::Text(direction.clone()));
    }
    if let Some(domain) = &query.domain {
        clauses.push("domain = ?".to_string());
        params.push(Value::Text(domain.clone()));
    }
    if let Some(row_type) = &query.row_type {
        clauses.push("row_type = ?".to_string());
        params.push(Value::Text(row_type.as_str().to_string()));
    }

    if clauses.is_empty() {
        (String::new(), params)
    } else {
        (format!(" WHERE {}", clauses.join(" AND ")), params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn sample_packet(timestamp: i64, domain: Option<&str>) -> PacketMetadata {
        PacketMetadata {
            timestamp,
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "1.1.1.1".to_string(),
            src_port: 4242,
            dst_port: 443,
            protocol: "TCP".to_string(),
            length: 512,
            direction: "egress".to_string(),
            src_hostname: Some("client.local".to_string()),
            dst_hostname: Some("one.one.one.one".to_string()),
            domain: domain.map(ToString::to_string),
        }
    }

    #[test]
    fn migrates_existing_database_and_backfills_history_metadata() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();
        drop(temp);

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "CREATE TABLE packets (
                id INTEGER PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length)
             VALUES (1, '10.0.0.1', '8.8.8.8', 1000, 53, 'UDP', 64)",
            [],
        )
        .unwrap();
        drop(conn);

        let storage = Storage::new(path.to_str().unwrap()).unwrap();
        let page = storage
            .query_history(&HistoryQuery {
                limit: 10,
                offset: 0,
                ..HistoryQuery::default()
            })
            .unwrap();

        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].row_type, "raw");
        assert_eq!(page.items[0].packet_count, 1);
    }

    #[test]
    fn query_history_applies_filters_and_pagination() {
        let storage = Storage::new(":memory:").unwrap();
        let older = sample_packet(100, Some("example.com"));
        let mut newer = sample_packet(200, Some("api.example.com"));
        newer.src_ip = "10.0.0.2".to_string();
        newer.src_port = 5555;

        storage.insert_packet(&older).unwrap();
        storage.insert_packet(&newer).unwrap();

        let page = storage
            .query_history(&HistoryQuery {
                limit: 1,
                offset: 0,
                src_ip: Some("10.0.0.2".to_string()),
                domain: Some("api.example.com".to_string()),
                ..HistoryQuery::default()
            })
            .unwrap();

        assert_eq!(page.total, 1);
        assert_eq!(page.returned, 1);
        assert!(!page.has_more);
        assert_eq!(page.items[0].src_ip, "10.0.0.2");
        assert_eq!(page.items[0].domain.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn delete_old_data_removes_stale_rows() {
        let storage = Storage::new(":memory:").unwrap();
        let old_timestamp = chrono::Utc::now().timestamp_millis() - 10_000;
        storage
            .insert_packet(&sample_packet(old_timestamp, None))
            .unwrap();

        let deleted = storage.delete_old_data(1).unwrap();

        assert_eq!(deleted, 1);
        let page = storage
            .query_history(&HistoryQuery {
                limit: 10,
                offset: 0,
                ..HistoryQuery::default()
            })
            .unwrap();
        assert_eq!(page.total, 0);
    }
}
