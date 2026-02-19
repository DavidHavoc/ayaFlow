use crate::state::{AggregatedBucket, PacketMetadata};
use chrono;
use rusqlite::{params, Connection, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::time::{interval, Duration};

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
                src_hostname TEXT,
                dst_hostname TEXT
            )",
            [],
        )?;

        // Migrate existing databases: add hostname columns if missing.
        // ALTER TABLE ... ADD COLUMN is a no-op when the column already exists
        // in SQLite >= 3.35, but older versions error. We ignore errors here.
        let _ = conn.execute("ALTER TABLE packets ADD COLUMN src_hostname TEXT", []);
        let _ = conn.execute("ALTER TABLE packets ADD COLUMN dst_hostname TEXT", []);

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)",
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

    async fn run_writer_raw(&self, mut rx: Receiver<PacketMetadata>) {
        let mut buffer = Vec::new();
        let mut ticker = interval(Duration::from_secs(2));

        loop {
            tokio::select! {
                Some(packet) = rx.recv() => {
                    buffer.push(packet);
                    if buffer.len() >= 1000 {
                         self.flush(&mut buffer);
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

    async fn run_writer_aggregated(
        &self,
        mut rx: Receiver<PacketMetadata>,
        window_secs: u64,
    ) {
        let mut buckets: HashMap<String, AggregatedBucket> = HashMap::new();
        let mut ticker = interval(Duration::from_secs(window_secs));

        loop {
            tokio::select! {
                Some(packet) = rx.recv() => {
                    let key = format!(
                        "{}:{} -> {}:{}",
                        packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port
                    );
                    buckets
                        .entry(key)
                        .and_modify(|b| b.merge(&packet))
                        .or_insert_with(|| AggregatedBucket::from_packet(&packet));
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

        {
            let mut stmt = match tx.prepare(
                "INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, src_hostname, dst_hostname)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    eprintln!("Failed to prepare statement: {}", e);
                    return;
                }
            };

            for packet in buffer.iter() {
                if let Err(e) = stmt.execute(params![
                    packet.timestamp,
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    packet.protocol,
                    packet.length,
                    packet.src_hostname,
                    packet.dst_hostname
                ]) {
                    eprintln!("Failed to insert packet: {}", e);
                }
            }
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

        {
            let mut stmt = match tx.prepare(
                "INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, src_hostname, dst_hostname)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            ) {
                Ok(stmt) => stmt,
                Err(e) => {
                    eprintln!("Failed to prepare statement: {}", e);
                    return;
                }
            };

            for bucket in buckets.values() {
                if let Err(e) = stmt.execute(params![
                    bucket.first_timestamp,
                    bucket.src_ip,
                    bucket.dst_ip,
                    bucket.src_port,
                    bucket.dst_port,
                    bucket.protocol,
                    bucket.total_bytes as i64,
                    bucket.src_hostname,
                    bucket.dst_hostname
                ]) {
                    eprintln!("Failed to insert aggregated row: {}", e);
                }
            }
        }

        if let Err(e) = tx.commit() {
            eprintln!("Failed to commit transaction: {}", e);
        } else {
            buckets.clear();
        }
    }

    pub fn query_history(&self, limit: usize) -> Result<Vec<PacketMetadata>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, src_hostname, dst_hostname
             FROM packets ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
            Ok(PacketMetadata {
                timestamp: row.get(0)?,
                src_ip: row.get(1)?,
                dst_ip: row.get(2)?,
                src_port: row.get(3)?,
                dst_port: row.get(4)?,
                protocol: row.get(5)?,
                length: row.get(6)?,
                src_hostname: row.get(7)?,
                dst_hostname: row.get(8)?,
            })
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn delete_old_data(&self, older_than_seconds: u64) -> Result<usize> {
        let cutoff_ms =
            chrono::Utc::now().timestamp_millis() - (older_than_seconds as i64 * 1000);
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute("DELETE FROM packets WHERE timestamp < ?1", params![cutoff_ms])?;
        Ok(deleted)
    }
}
