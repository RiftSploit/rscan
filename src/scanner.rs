use calamine::{Reader, open_workbook_auto};
use chrono::Local;
use crate::protocol_detector::ProtocolDetector;
use futures::future::join_all;
use rust_xlsxwriter::Workbook;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};
use rusqlite::{Connection, params};

pub const RESUME_STATE_FILE: &str = "rscan.resume.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Text,
    Json,
    Xlsx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub target: String,
    #[serde(default)]
    pub time: String,
    pub protocol: String,
    pub version: Option<String>,
    pub details: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeConfig {
    pub output_path: Option<PathBuf>,
    pub output_format: OutputFormat,
    pub concurrency: usize,
    #[serde(default = "default_initial_timeout_ms")]
    pub initial_timeout_ms: u64,
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,
    #[serde(default = "default_connect_retries")]
    pub connect_retries: usize,
    pub assets: Vec<String>,
    pub ports: Vec<u16>,
    pub silent: bool,
    pub debug_log_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetStatus {
    Pending,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetState {
    pub target: String,
    pub status: TargetStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeState {
    pub config: ResumeConfig,
    pub targets: Vec<TargetState>,
    pub records: Vec<ScanRecord>,
}

#[derive(Debug)]
struct ProgressState {
    completed_targets: usize,
    total_targets: usize,
    last_percent: usize,
    started_at: Instant,
    last_render_at: Instant,
    progress_line_active: bool,
}

#[derive(Debug)]
struct PersistState {
    pending_changes: usize,
    last_persist_at: Instant,
    persist_count: u32,
    last_persist_time: Instant,
}

#[derive(Debug)]
struct DebugLogState {
    write_count: usize,
    last_flush_at: Instant,
}

impl DebugLogState {
    fn new() -> Self {
        Self {
            write_count: 0,
            last_flush_at: Instant::now(),
        }
    }

    fn should_flush(&self) -> bool {
        self.write_count >= 100 || self.last_flush_at.elapsed() >= Duration::from_secs(1)
    }

    fn reset(&mut self) {
        self.write_count = 0;
        self.last_flush_at = Instant::now();
    }
}

#[derive(Debug)]
struct PagingManager {
    db_path: Option<PathBuf>,
    buffer: Vec<ScanRecord>,
    buffer_size: usize,
}

impl PagingManager {
    fn new(buffer_size: usize) -> Self {
        Self {
            db_path: None,
            buffer: Vec::with_capacity(buffer_size),
            buffer_size,
        }
    }

    fn init_db(&mut self) -> io::Result<()> {
        let tmpdir = std::env::temp_dir();
        let db_path = tmpdir.join(format!("rscan_scan_{}.db", uuid_string()));
        
        let conn = Connection::open(&db_path)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY,
                ip TEXT NOT NULL,
                port INTEGER,
                protocol TEXT NOT NULL,
                data TEXT
            )",
            [],
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        self.db_path = Some(db_path);
        Ok(())
    }

    fn add_record(&mut self, record: ScanRecord) -> io::Result<()> {
        self.buffer.push(record);
        if self.buffer.len() >= self.buffer_size {
            self.flush_to_db()?;
        }
        Ok(())
    }

    fn flush_to_db(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let db_path = match &self.db_path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        let mut conn = Connection::open(&db_path)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let tx = conn.transaction()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        for record in self.buffer.drain(..) {
            tx.execute(
                "INSERT INTO scan_results (ip, protocol, data) VALUES (?1, ?2, ?3)",
                params![
                    &record.target,
                    &record.protocol,
                    serde_json::to_string(&record).unwrap_or_default(),
                ],
            ).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        Ok(())
    }

    fn retrieve_all(&mut self) -> io::Result<Vec<ScanRecord>> {
        let mut records = Vec::new();

        for record in self.buffer.drain(..) {
            records.push(record);
        }

        if let Some(db_path) = &self.db_path {
            let conn = Connection::open(db_path)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let mut stmt = conn.prepare("SELECT data FROM scan_results")
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let record_iter = stmt.query_map([], |row| {
                let json_str: String = row.get(0)?;
                Ok(serde_json::from_str(&json_str).unwrap_or_else(|_| ScanRecord {
                    target: String::new(),
                    time: String::new(),
                    protocol: String::new(),
                    version: None,
                    details: None,
                    confidence: 0.0,
                }))
            }).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            for row_result in record_iter {
                let record = row_result.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                records.push(record);
            }
        }

        Ok(records)
    }

    fn cleanup(&self) -> io::Result<()> {
        if let Some(db_path) = &self.db_path {
            if db_path.exists() {
                std::fs::remove_file(db_path)?;
            }
        }
        Ok(())
    }
}

fn uuid_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}{:06}", duration.as_secs(), duration.subsec_micros())
}

pub struct Scanner {
    batch_size: usize,
    initial_timeout: Duration,
    detailed_timeout: Duration,
    connect_retries: usize,
    is_resume_mode: bool,
    protocol_detector: ProtocolDetector,
    output_format: OutputFormat,
    output_path: Option<PathBuf>,
    debug_output: Option<Mutex<BufWriter<File>>>,
    debug_log_state: Mutex<DebugLogState>,
    resume_path: PathBuf,
    resume_state: Mutex<ResumeState>,
    persist: Mutex<PersistState>,
    paging: Mutex<PagingManager>,
    target_index: HashMap<String, usize>,
    progress: Mutex<ProgressState>,
}

pub fn default_resume_state_path() -> PathBuf {
    PathBuf::from(RESUME_STATE_FILE)
}

fn default_initial_timeout_ms() -> u64 {
    300
}

fn default_probe_timeout_ms() -> u64 {
    1500
}

fn default_connect_retries() -> usize {
    1
}

pub fn create_resume_state(config: ResumeConfig, sockets: &[SocketAddr]) -> ResumeState {
    let targets = sockets
        .iter()
        .map(|socket| TargetState {
            target: socket.to_string(),
            status: TargetStatus::Pending,
        })
        .collect();

    ResumeState {
        config,
        targets,
        records: Vec::new(),
    }
}

pub fn save_resume_state(path: &PathBuf, state: &ResumeState) -> io::Result<()> {
    let mut temp_path = path.clone();
    temp_path.set_extension("tmp");

    {
        let mut file = File::create(&temp_path)?;
        serde_json::to_writer_pretty(&mut file, state)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        file.sync_all()?;
    }

    if path.exists() {
        std::fs::remove_file(path)?;
    }

    std::fs::rename(&temp_path, path)?;
    Ok(())
}

pub fn load_resume_state(path: &PathBuf) -> io::Result<ResumeState> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    serde_json::from_str::<ResumeState>(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

pub fn pending_sockets(state: &ResumeState) -> Vec<SocketAddr> {
    state
        .targets
        .iter()
        .filter(|t| t.status == TargetStatus::Pending)
        .filter_map(|t| t.target.parse::<SocketAddr>().ok())
        .collect()
}

impl Scanner {
    pub fn new(state: ResumeState, resume_path: PathBuf, is_resume_mode: bool) -> io::Result<Self> {
        let debug_output = match &state.config.debug_log_path {
            Some(path) => Some(Mutex::new(BufWriter::new(File::create(path)?))),
            None => None,
        };

        let mut target_index = HashMap::with_capacity(state.targets.len());
        for (idx, t) in state.targets.iter().enumerate() {
            target_index.insert(t.target.clone(), idx);
        }
        let total_targets = target_index.len().max(1);

        let completed = state
            .targets
            .iter()
            .filter(|t| t.status == TargetStatus::Completed)
            .count();

        let mut paging = PagingManager::new(10000);
        paging.init_db()?;

        Ok(Self {
            batch_size: state.config.concurrency.max(1),
            initial_timeout: Duration::from_millis(state.config.initial_timeout_ms.max(50)),
            detailed_timeout: Duration::from_millis(state.config.probe_timeout_ms.max(100)),
            connect_retries: state.config.connect_retries,
            is_resume_mode,
            protocol_detector: ProtocolDetector::new(
                Duration::from_millis(state.config.probe_timeout_ms.max(100)),
                state.config.connect_retries,
            ),
            output_format: state.config.output_format,
            output_path: state.config.output_path.clone(),
            debug_output,
            debug_log_state: Mutex::new(DebugLogState::new()),
            resume_path,
            resume_state: Mutex::new(state),
            persist: Mutex::new(PersistState {
                pending_changes: 0,
                last_persist_at: Instant::now(),
                persist_count: 0,
                last_persist_time: Instant::now(),
            }),
            paging: Mutex::new(paging),
            target_index,
            progress: Mutex::new(ProgressState {
                completed_targets: completed,
                total_targets,
                last_percent: 0,
                started_at: Instant::now(),
                last_render_at: Instant::now(),
                progress_line_active: false,
            }),
        })
    }

    async fn scan_socket(
        self: Arc<Self>,
        socket: SocketAddr,
        timeout_time: Duration,
    ) -> (SocketAddr, bool) {
        for _ in 0..=self.connect_retries {
            if let Ok(Ok(_)) = timeout(timeout_time, TcpStream::connect(socket)).await {
                return (socket, true);
            }
        }
        (socket, false)
    }

    pub async fn run(self: Arc<Self>, sockets: Vec<SocketAddr>) {
        if sockets.is_empty() {
            let _ = self.flush_output_from_state();
            let _ = self.flush_debug_log();
            let _ = std::fs::remove_file(&self.resume_path);
            return;
        }

        let estimated_rounds = ((sockets.len() + self.batch_size - 1) / self.batch_size).saturating_mul(4);
        let estimated_secs = (estimated_rounds as f64)
            * (self.initial_timeout.as_secs_f64() + self.detailed_timeout.as_secs_f64())
            / 2.0;

        if self.is_resume_mode {
            println!(
                "恢复扫描: 待处理 {} 个目标，批次大小 {}，预计耗时约 {:.1} 秒",
                sockets.len(),
                self.batch_size,
                estimated_secs
            );
        } else {
            println!(
                "开始扫描: 目标 {} 个，批次大小 {}，预计耗时约 {:.1} 秒",
                sockets.len(),
                self.batch_size,
                estimated_secs
            );
        }

        self.log_debug(&format!(
            "scan-start pending={} batch_size={} est_secs={:.1}",
            sockets.len(),
            self.batch_size,
            estimated_secs
        ));

        let validation_window = self.batch_size.saturating_mul(4).max(self.batch_size);
        let mut discovery_ftrs = Vec::new();
        let mut validation_set: JoinSet<(SocketAddr, ScanRecord)> = JoinSet::new();

        for socket in sockets {
            if discovery_ftrs.len() >= self.batch_size {
                let open_sockets = self.clone().process_discovery_batch(&mut discovery_ftrs).await;
                self.enqueue_validation_tasks(open_sockets, &mut validation_set);
                self.clone()
                    .drain_validation_tasks(&mut validation_set, false, validation_window)
                    .await;
            }
            discovery_ftrs.push(tokio::spawn(self.clone().scan_socket(socket, self.initial_timeout)));
        }

        let open_sockets = self.clone().process_discovery_batch(&mut discovery_ftrs).await;
        self.enqueue_validation_tasks(open_sockets, &mut validation_set);
        self.clone()
            .drain_validation_tasks(&mut validation_set, true, validation_window)
            .await;

        self.maybe_persist_state(true);

        if let Err(e) = self.finalize_and_flush_results() {
            eprintln!("结果聚合失败: {:?}", e);
            self.log_debug(&format!("result-aggregation-error err={:?}", e));
            let _ = self.flush_debug_log();
            return;
        }

        if let Err(e) = self.flush_output_from_state() {
            eprintln!("输出写入失败: {:?}", e);
            self.log_debug(&format!("output-flush-error err={:?}", e));
            let _ = self.flush_debug_log();
            return;
        }

        self.print_console_results();

        if let Err(e) = std::fs::remove_file(&self.resume_path) {
            self.log_debug(&format!("resume-cleanup-error err={:?}", e));
        }

        let _ = self.flush_debug_log();
    }

    fn finalize_and_flush_results(&self) -> io::Result<()> {
        let mut paging = self.paging.lock().unwrap();
        
        paging.flush_to_db()?;
        
        let mut all_records = paging.retrieve_all()?;
        
        let mut state = self.resume_state.lock().unwrap();
        state.records.append(&mut all_records);
        
        paging.cleanup()?;
        
        Ok(())
    }

    fn enqueue_validation_tasks(
        self: &Arc<Self>,
        sockets: Vec<SocketAddr>,
        validation_set: &mut JoinSet<(SocketAddr, ScanRecord)>,
    ) {
        for socket in sockets {
            let scanner = self.clone();
            validation_set.spawn(async move { scanner.validate_and_fingerprint(socket).await });
        }
    }

    async fn drain_validation_tasks(
        self: Arc<Self>,
        validation_set: &mut JoinSet<(SocketAddr, ScanRecord)>,
        drain_all: bool,
        window_size: usize,
    ) {
        while !validation_set.is_empty() && (drain_all || validation_set.len() >= window_size) {
            match validation_set.join_next().await {
                Some(Ok((socket, record))) => {
                    self.log_debug(&format!(
                        "fingerprint target={} protocol={} confidence={:.2}",
                        socket, record.protocol, record.confidence
                    ));
                    self.upsert_record(record);
                    self.complete_target(socket);
                }
                Some(Err(e)) => {
                    eprintln!("任务执行失败: {:?}", e);
                    self.log_debug(&format!("fingerprint-join-error err={:?}", e));
                }
                None => break,
            }
        }
    }

    async fn validate_and_fingerprint(self: Arc<Self>, socket: SocketAddr) -> (SocketAddr, ScanRecord) {
        let alive_time = current_local_time_string();
        let info = self.protocol_detector.detect(socket).await;
        let record = ScanRecord {
            target: socket.to_string(),
            time: alive_time,
            protocol: info.name,
            version: info.version,
            details: info.details,
            confidence: info.confidence,
        };
        (socket, record)
    }

    async fn process_discovery_batch(
        self: Arc<Self>,
        ftrs: &mut Vec<tokio::task::JoinHandle<(SocketAddr, bool)>>,
    ) -> Vec<SocketAddr> {
        if ftrs.is_empty() {
            return Vec::new();
        }

        let mut open_sockets = Vec::new();
        let results = join_all(ftrs.drain(..)).await;

        for result in results {
            match result {
                Ok((socket, true)) => {
                    self.log_debug(&format!("discovery-open target={}", socket));
                    open_sockets.push(socket);
                }
                Ok((socket, false)) => {
                    self.log_debug(&format!("discovery-closed target={}", socket));
                    self.complete_target(socket);
                }
                Err(e) => {
                    eprintln!("任务执行失败: {:?}", e);
                    self.log_debug(&format!("discovery-join-error err={:?}", e));
                }
            }
        }

        open_sockets
    }

    fn complete_target(&self, socket: SocketAddr) {
        let key = socket.to_string();
        let mut changed = false;

        if let Some(&idx) = self.target_index.get(&key) {
            let mut state = self.resume_state.lock().unwrap();
            if state.targets[idx].status != TargetStatus::Completed {
                state.targets[idx].status = TargetStatus::Completed;
                changed = true;
            }
        }

        if changed {
            self.tick_progress();
            self.note_state_change();
            self.tick_persist_count();
            self.maybe_persist_state(false);
        }
    }

    fn upsert_record(&self, record: ScanRecord) {
        let mut state = self.resume_state.lock().unwrap();
        if state.records.iter().any(|r| r.target == record.target) {
            return;
        }
        state.records.push(record.clone());
        
        if state.records.len() >= 10000 {
            let mut paging = self.paging.lock().unwrap();
            for r in state.records.drain(..) {
                let _ = paging.add_record(r);
            }
        }
        drop(state);
        self.note_state_change();
        self.maybe_persist_state(false);
    }

    fn persist_state(&self) -> io::Result<()> {
        let snapshot = { self.resume_state.lock().unwrap().clone() };
        save_resume_state(&self.resume_path, &snapshot)
    }

    fn note_state_change(&self) {
        let mut p = self.persist.lock().unwrap();
        p.pending_changes = p.pending_changes.saturating_add(1);
    }

    fn tick_persist_count(&self) {
        let mut p = self.persist.lock().unwrap();
        p.persist_count = p.persist_count.saturating_add(1);
    }

    fn maybe_persist_state(&self, force: bool) {
        const PERSIST_BATCH_SIZE: u32 = 100;
        const PERSIST_TIME_INTERVAL: Duration = Duration::from_secs(5);

        let should_persist = {
            let p = self.persist.lock().unwrap();
            force
                || (p.persist_count >= PERSIST_BATCH_SIZE
                    || (p.persist_count > 0 && p.last_persist_time.elapsed() >= PERSIST_TIME_INTERVAL))
        };

        if !should_persist {
            return;
        }

        match self.persist_state() {
            Ok(()) => {
                let mut p = self.persist.lock().unwrap();
                p.persist_count = 0;
                p.last_persist_time = Instant::now();
                p.pending_changes = 0;
                p.last_persist_at = Instant::now();
            }
            Err(e) => {
                self.log_debug(&format!("persist-error err={:?}", e));
            }
        }
    }

    fn tick_progress(&self) {
        let mut p = self.progress.lock().unwrap();
        p.completed_targets = (p.completed_targets + 1).min(p.total_targets);
        let percent = p.completed_targets.saturating_mul(100) / p.total_targets.max(1);
        let elapsed_since_render = p.last_render_at.elapsed();
        let should_render = p.completed_targets == 1
            || percent > p.last_percent
            || elapsed_since_render >= Duration::from_secs(1)
            || p.completed_targets >= p.total_targets;

        if should_render {
            p.last_percent = percent;
            p.last_render_at = Instant::now();
            let elapsed = p.started_at.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 {
                p.completed_targets as f64 / elapsed
            } else {
                0.0
            };
            let left = p.total_targets.saturating_sub(p.completed_targets) as f64;
            let eta = if speed > 0.0 { left / speed } else { 0.0 };

            if self.is_resume_mode {
                print!(
                    "\r恢复进度 {:>3}% ({}/{}) 已用 {:.1}s ETA {:.1}s",
                    percent, p.completed_targets, p.total_targets, elapsed, eta
                );
            } else {
                print!(
                    "\r扫描进度 {:>3}% ({}/{}) 已用 {:.1}s ETA {:.1}s",
                    percent, p.completed_targets, p.total_targets, elapsed, eta
                );
            }
            let _ = io::stdout().flush();
            p.progress_line_active = true;

            if p.completed_targets >= p.total_targets {
                println!();
                p.progress_line_active = false;
            }
        }
    }

    fn finish_progress_line_if_needed(&self) {
        let mut p = self.progress.lock().unwrap();
        if p.progress_line_active {
            print!("\r\x1b[2K");
            let _ = io::stdout().flush();
            p.progress_line_active = false;
        }
    }

    fn log_debug(&self, message: &str) {
        if let Some(file) = &self.debug_output {
            let mut file = file.lock().unwrap();
            let _ = file.write_all(format!("{}\n", message).as_bytes());

            let mut state = self.debug_log_state.lock().unwrap();
            state.write_count += 1;

            if state.should_flush() {
                let _ = file.flush();
                state.reset();
            }
        }
    }

    fn flush_debug_log(&self) -> io::Result<()> {
        if let Some(file) = &self.debug_output {
            let mut file = file.lock().unwrap();
            file.flush()?;
        }
        Ok(())
    }

    fn flush_output_from_state(&self) -> io::Result<()> {
        let Some(path) = &self.output_path else {
            return Ok(());
        };
        let path = normalize_output_path(path, self.output_format);

        let snapshot = { self.resume_state.lock().unwrap().clone() };
        let records: Vec<ScanRecord> = snapshot
            .records
            .into_iter()
            .map(sanitize_record)
            .collect();

        match self.output_format {
            OutputFormat::Text => {
                let mut file = File::create(&path)?;
                file.write_all(format!("{}\n", result_header_line()).as_bytes())?;
                for record in &records {
                    let line = format_record_line(record);
                    file.write_all(format!("{}\n", line).as_bytes())?;
                }
                Ok(())
            }
            OutputFormat::Json => {
                let mut file = File::create(&path)?;
                serde_json::to_writer_pretty(&mut file, &records)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            }
            OutputFormat::Xlsx => {
                let mut workbook = Workbook::new();
                let worksheet = workbook.add_worksheet();

                worksheet
                    .write_string(0, 0, "target")
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                worksheet
                    .write_string(0, 1, "time")
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                worksheet
                    .write_string(0, 2, "protocol")
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                worksheet
                    .write_string(0, 3, "version")
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                worksheet
                    .write_string(0, 4, "details")
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                worksheet
                    .write_string(0, 5, "confidence")
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                for (idx, record) in records.iter().enumerate() {
                    let row = (idx + 1) as u32;
                    worksheet
                        .write_string(row, 0, &record.target)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    worksheet
                        .write_string(row, 1, &record.time)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    worksheet
                        .write_string(row, 2, &record.protocol)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    worksheet
                        .write_string(row, 3, record.version.as_deref().unwrap_or(""))
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    worksheet
                        .write_string(row, 4, record.details.as_deref().unwrap_or(""))
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    worksheet
                        .write_number(row, 5, record.confidence)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                }

                workbook
                    .save(&path)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            }
        }
    }

    fn print_console_results(&self) {
        let snapshot = { self.resume_state.lock().unwrap().clone() };
        let mut records: Vec<ScanRecord> = snapshot
            .records
            .into_iter()
            .map(sanitize_record)
            .collect();

        records.sort_by(|a, b| a.target.cmp(&b.target));

        self.finish_progress_line_if_needed();
        println!("{}", result_header_line());
        for record in &records {
            println!("{}", format_record_line(record));
        }
    }
}

fn format_record_line(record: &ScanRecord) -> String {
    let record = sanitize_record(record.clone());
    let mut right = format!("{:<22}", record.time);
    right = format!("{} | {:<12}", right, record.protocol);
    right = format!("{} | {:<20}", right, record.version.as_deref().unwrap_or(""));
    right = format!("{} | {:<60}", right, record.details.as_deref().unwrap_or(""));
    right = format!("{} | {:.2}", right, record.confidence);
    format!("{:<21} | {}", record.target, right)
}

fn result_header_line() -> &'static str {
    "target                | time                   | protocol     | version              | details                                                      | confidence"
}

fn sanitize_record(mut record: ScanRecord) -> ScanRecord {
    let is_fallback = record
        .details
        .as_deref()
        .is_some_and(|d| d.starts_with("Fallback:"));

    if record.protocol == "tcp-open" || record.protocol == "tcp-udp-open" || record.protocol == "unknown" || is_fallback {
        record.protocol = "open".to_string();
        record.version = None;
        record.details = None;
        return record;
    }

    if record.details.as_deref().is_some_and(|d| d.starts_with("Fallback:")) {
        record.details = None;
    }

    record
}

fn current_local_time_string() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

fn normalize_output_path(path: &PathBuf, format: OutputFormat) -> PathBuf {
    let suffix = match format {
        OutputFormat::Json => ".json",
        OutputFormat::Xlsx => ".xlsx",
        OutputFormat::Text => return path.clone(),
    };

    let lower = path.as_os_str().to_string_lossy().to_lowercase();
    if lower.ends_with(suffix) {
        return path.clone();
    }

    let mut with_suffix: OsString = path.as_os_str().to_os_string();
    with_suffix.push(suffix);
    PathBuf::from(with_suffix)
}

pub fn load_resume_targets(path: &PathBuf, output_format: OutputFormat) -> io::Result<Vec<SocketAddr>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    match output_format {
        OutputFormat::Text => parse_text_resume(path),
        OutputFormat::Json => parse_json_resume(path),
        OutputFormat::Xlsx => parse_xlsx_resume(path),
    }
}

fn parse_text_resume(path: &PathBuf) -> io::Result<Vec<SocketAddr>> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let mut done = Vec::new();
    for line in content.lines() {
        let left = line.split('|').next().unwrap_or("").trim();
        if let Ok(socket) = left.parse::<SocketAddr>() {
            done.push(socket);
        }
    }
    Ok(done)
}

fn parse_json_resume(path: &PathBuf) -> io::Result<Vec<SocketAddr>> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let records: Vec<ScanRecord> = serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    Ok(records
        .into_iter()
        .filter_map(|record| record.target.parse::<SocketAddr>().ok())
        .collect())
}

fn parse_xlsx_resume(path: &PathBuf) -> io::Result<Vec<SocketAddr>> {
    let mut workbook = open_workbook_auto(path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let sheet_name = workbook
        .sheet_names()
        .first()
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "XLSX 文件中没有工作表"))?;

    let range = workbook
        .worksheet_range(&sheet_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut done = Vec::new();
    for (idx, row) in range.rows().enumerate() {
        if idx == 0 {
            continue;
        }
        if let Some(cell) = row.first() {
            let target = cell.to_string();
            if let Ok(socket) = target.parse::<SocketAddr>() {
                done.push(socket);
            }
        }
    }

    Ok(done)
}
