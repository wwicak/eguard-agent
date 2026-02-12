use std::collections::{HashMap, HashSet, VecDeque};

use aho_corasick::AhoCorasick;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

const EVENT_CLASSES: [EventClass; 7] = [
    EventClass::ProcessExec,
    EventClass::FileOpen,
    EventClass::NetworkConnect,
    EventClass::DnsQuery,
    EventClass::ModuleLoad,
    EventClass::Login,
    EventClass::Alert,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventClass {
    ProcessExec,
    FileOpen,
    NetworkConnect,
    DnsQuery,
    ModuleLoad,
    Login,
    Alert,
}

impl EventClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::FileOpen => "file_open",
            Self::NetworkConnect => "network_connect",
            Self::DnsQuery => "dns_query",
            Self::ModuleLoad => "module_load",
            Self::Login => "login",
            Self::Alert => "alert",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub ts_unix: i64,
    pub event_class: EventClass,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub process: String,
    pub parent_process: String,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    pub dst_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_domain: Option<String>,
    pub command_line: Option<String>,
}

impl TelemetryEvent {
    pub fn entity_key(&self) -> String {
        self.pid.to_string()
    }

    pub fn process_key(&self) -> String {
        format!("{}:{}", self.process, self.parent_process)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Definite,
    VeryHigh,
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignals {
    pub z1_exact_ioc: bool,
    pub z2_temporal: bool,
    pub z3_anomaly_high: bool,
    pub z3_anomaly_med: bool,
    pub z4_kill_chain: bool,
    pub l1_prefilter_hit: bool,
}

pub fn confidence_policy(s: &DetectionSignals) -> Confidence {
    if s.z1_exact_ioc {
        return Confidence::Definite;
    }
    if s.z2_temporal && (s.z4_kill_chain || s.l1_prefilter_hit) {
        return Confidence::VeryHigh;
    }
    if s.z2_temporal || s.z4_kill_chain {
        return Confidence::High;
    }
    if s.z3_anomaly_high && !(s.z1_exact_ioc || s.z2_temporal || s.z4_kill_chain) {
        return Confidence::Medium;
    }
    if s.z3_anomaly_med && !(s.z1_exact_ioc || s.z2_temporal || s.z4_kill_chain) {
        return Confidence::Low;
    }
    Confidence::None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer1Result {
    Clean,
    PrefilterOnly,
    ExactMatch,
}

#[derive(Debug, Clone)]
pub struct Layer1EventHit {
    pub result: Layer1Result,
    pub prefilter_hit: bool,
    pub matched_fields: Vec<String>,
    pub matched_signatures: Vec<String>,
}

impl Default for Layer1EventHit {
    fn default() -> Self {
        Self {
            result: Layer1Result::Clean,
            prefilter_hit: false,
            matched_fields: Vec::new(),
            matched_signatures: Vec::new(),
        }
    }
}

pub struct IocExactStore {
    conn: Connection,
}

impl IocExactStore {
    pub fn in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS ioc_hashes(hash TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS ioc_domains(domain TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS ioc_ips(ip TEXT PRIMARY KEY);
            ",
        )
    }

    pub fn load_hashes<I>(&self, values: I) -> rusqlite::Result<()>
    where
        I: IntoIterator<Item = String>,
    {
        let mut stmt = self
            .conn
            .prepare("INSERT OR IGNORE INTO ioc_hashes(hash) VALUES(?1)")?;
        for v in values {
            stmt.execute(params![v])?;
        }
        Ok(())
    }

    pub fn load_domains<I>(&self, values: I) -> rusqlite::Result<()>
    where
        I: IntoIterator<Item = String>,
    {
        let mut stmt = self
            .conn
            .prepare("INSERT OR IGNORE INTO ioc_domains(domain) VALUES(?1)")?;
        for v in values {
            stmt.execute(params![v.to_ascii_lowercase()])?;
        }
        Ok(())
    }

    pub fn load_ips<I>(&self, values: I) -> rusqlite::Result<()>
    where
        I: IntoIterator<Item = String>,
    {
        let mut stmt = self
            .conn
            .prepare("INSERT OR IGNORE INTO ioc_ips(ip) VALUES(?1)")?;
        for v in values {
            stmt.execute(params![v])?;
        }
        Ok(())
    }

    pub fn contains_hash(&self, hash: &str) -> rusqlite::Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM ioc_hashes WHERE hash = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![hash])?;
        Ok(rows.next()?.is_some())
    }

    pub fn contains_domain(&self, domain: &str) -> rusqlite::Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM ioc_domains WHERE domain = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![domain.to_ascii_lowercase()])?;
        Ok(rows.next()?.is_some())
    }

    pub fn contains_ip(&self, ip: &str) -> rusqlite::Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT 1 FROM ioc_ips WHERE ip = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![ip])?;
        Ok(rows.next()?.is_some())
    }
}

#[derive(Debug)]
pub struct IocLayer1 {
    prefilter_hashes: HashSet<String>,
    exact_hashes: HashSet<String>,
    prefilter_domains: HashSet<String>,
    exact_domains: HashSet<String>,
    prefilter_ips: HashSet<String>,
    exact_ips: HashSet<String>,
    matcher_patterns: Vec<String>,
    matcher: Option<AhoCorasick>,
    exact_store: Option<IocExactStore>,
}

impl IocLayer1 {
    pub fn new() -> Self {
        Self {
            prefilter_hashes: HashSet::new(),
            exact_hashes: HashSet::new(),
            prefilter_domains: HashSet::new(),
            exact_domains: HashSet::new(),
            prefilter_ips: HashSet::new(),
            exact_ips: HashSet::new(),
            matcher_patterns: Vec::new(),
            matcher: None,
            exact_store: None,
        }
    }

    pub fn with_sqlite(path: &str) -> rusqlite::Result<Self> {
        let mut s = Self::new();
        s.exact_store = Some(IocExactStore::open(path)?);
        Ok(s)
    }

    pub fn set_exact_store(&mut self, store: IocExactStore) {
        self.exact_store = Some(store);
    }

    pub fn load_hashes<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = String>,
    {
        let mut copy = Vec::new();
        for v in values {
            self.prefilter_hashes.insert(v.clone());
            self.exact_hashes.insert(v.clone());
            copy.push(v);
        }
        if let Some(store) = &self.exact_store {
            let _ = store.load_hashes(copy);
        }
    }

    pub fn load_domains<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = String>,
    {
        let mut copy = Vec::new();
        for v in values {
            let n = v.to_ascii_lowercase();
            self.prefilter_domains.insert(n.clone());
            self.exact_domains.insert(n.clone());
            copy.push(n);
        }
        if let Some(store) = &self.exact_store {
            let _ = store.load_domains(copy);
        }
    }

    pub fn load_ips<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = String>,
    {
        let mut copy = Vec::new();
        for v in values {
            self.prefilter_ips.insert(v.clone());
            self.exact_ips.insert(v.clone());
            copy.push(v);
        }
        if let Some(store) = &self.exact_store {
            let _ = store.load_ips(copy);
        }
    }

    pub fn load_string_signatures<I>(&mut self, patterns: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.matcher_patterns.clear();
        for p in patterns {
            if !p.is_empty() {
                self.matcher_patterns.push(p);
            }
        }
        if self.matcher_patterns.is_empty() {
            self.matcher = None;
            return;
        }
        self.matcher = AhoCorasick::new(self.matcher_patterns.clone()).ok();
    }

    pub fn check_hash(&self, hash: &str) -> Layer1Result {
        if !self.prefilter_hashes.contains(hash) {
            return Layer1Result::Clean;
        }
        if self.exact_hashes.contains(hash) {
            return Layer1Result::ExactMatch;
        }
        if let Some(store) = &self.exact_store {
            if store.contains_hash(hash).unwrap_or(false) {
                return Layer1Result::ExactMatch;
            }
        }
        Layer1Result::PrefilterOnly
    }

    pub fn check_domain(&self, domain: &str) -> Layer1Result {
        let normalized = domain.to_ascii_lowercase();
        if !self.prefilter_domains.contains(&normalized) {
            return Layer1Result::Clean;
        }
        if self.exact_domains.contains(&normalized) {
            return Layer1Result::ExactMatch;
        }
        if let Some(store) = &self.exact_store {
            if store.contains_domain(&normalized).unwrap_or(false) {
                return Layer1Result::ExactMatch;
            }
        }
        Layer1Result::PrefilterOnly
    }

    pub fn check_ip(&self, ip: &str) -> Layer1Result {
        if !self.prefilter_ips.contains(ip) {
            return Layer1Result::Clean;
        }
        if self.exact_ips.contains(ip) {
            return Layer1Result::ExactMatch;
        }
        if let Some(store) = &self.exact_store {
            if store.contains_ip(ip).unwrap_or(false) {
                return Layer1Result::ExactMatch;
            }
        }
        Layer1Result::PrefilterOnly
    }

    pub fn check_text(&self, text: &str) -> Vec<String> {
        let Some(matcher) = &self.matcher else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for m in matcher.find_iter(text) {
            if let Some(p) = self.matcher_patterns.get(m.pattern().as_usize()) {
                out.push(p.clone());
            }
        }
        out
    }

    pub fn check_event(&self, event: &TelemetryEvent) -> Layer1EventHit {
        let mut hit = Layer1EventHit::default();

        if let Some(h) = &event.file_hash {
            self.apply_result(self.check_hash(h), "file_hash", &mut hit);
        }
        if let Some(d) = &event.dst_domain {
            self.apply_result(self.check_domain(d), "dst_domain", &mut hit);
        }
        if let Some(ip) = &event.dst_ip {
            self.apply_result(self.check_ip(ip), "dst_ip", &mut hit);
        }

        if let Some(cmd) = &event.command_line {
            let matches = self.check_text(cmd);
            if !matches.is_empty() {
                hit.matched_fields.push("command_line".to_string());
                hit.matched_signatures.extend(matches);
            }
        }
        if let Some(path) = &event.file_path {
            let matches = self.check_text(path);
            if !matches.is_empty() {
                hit.matched_fields.push("file_path".to_string());
                hit.matched_signatures.extend(matches);
            }
        }

        if hit.result == Layer1Result::Clean && hit.prefilter_hit {
            hit.result = Layer1Result::PrefilterOnly;
        }

        hit
    }

    fn apply_result(&self, result: Layer1Result, field: &str, hit: &mut Layer1EventHit) {
        match result {
            Layer1Result::Clean => {}
            Layer1Result::PrefilterOnly => {
                hit.prefilter_hit = true;
                hit.matched_fields.push(field.to_string());
                if hit.result != Layer1Result::ExactMatch {
                    hit.result = Layer1Result::PrefilterOnly;
                }
            }
            Layer1Result::ExactMatch => {
                hit.prefilter_hit = true;
                hit.matched_fields.push(field.to_string());
                hit.result = Layer1Result::ExactMatch;
            }
        }
    }
}

impl Default for IocLayer1 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TemporalPredicate {
    pub event_class: EventClass,
    pub process_any_of: Option<HashSet<String>>,
    pub parent_any_of: Option<HashSet<String>>,
    pub uid_eq: Option<u32>,
    pub uid_ne: Option<u32>,
    pub dst_port_not_in: Option<HashSet<u16>>,
}

impl TemporalPredicate {
    pub fn matches(&self, e: &TelemetryEvent) -> bool {
        if self.event_class != e.event_class {
            return false;
        }

        if let Some(set) = &self.process_any_of {
            if !set.contains(&e.process) {
                return false;
            }
        }

        if let Some(set) = &self.parent_any_of {
            if !set.contains(&e.parent_process) {
                return false;
            }
        }

        if let Some(v) = self.uid_eq {
            if e.uid != v {
                return false;
            }
        }

        if let Some(v) = self.uid_ne {
            if e.uid == v {
                return false;
            }
        }

        if let Some(not_ports) = &self.dst_port_not_in {
            match e.dst_port {
                Some(p) => {
                    if !not_ports.contains(&p) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct TemporalStage {
    pub predicate: TemporalPredicate,
    pub within_secs: u64,
}

#[derive(Debug, Clone)]
pub struct TemporalRule {
    pub name: String,
    pub stages: Vec<TemporalStage>,
}

#[derive(Debug, Clone)]
struct TemporalState {
    stage_idx: usize,
    first_match_ts: i64,
    last_match_ts: i64,
}

#[derive(Debug, Default)]
pub struct TemporalEngine {
    rules: Vec<TemporalRule>,
    states: HashMap<(usize, String), TemporalState>,
    subscriptions: HashMap<EventClass, Vec<usize>>,
    reorder_tolerance_secs: i64,
}

impl TemporalEngine {
    pub fn new() -> Self {
        Self {
            reorder_tolerance_secs: 2,
            ..Self::default()
        }
    }

    pub fn with_default_rules() -> Self {
        let mut e = Self::new();

        let web_servers = set_of(["nginx", "apache2", "httpd", "caddy"]);
        let shells = set_of(["sh", "bash", "dash", "zsh", "ksh"]);
        let webshell = TemporalRule {
            name: "phi_webshell".to_string(),
            stages: vec![
                TemporalStage {
                    predicate: TemporalPredicate {
                        event_class: EventClass::ProcessExec,
                        process_any_of: Some(shells),
                        parent_any_of: Some(web_servers),
                        uid_eq: None,
                        uid_ne: None,
                        dst_port_not_in: None,
                    },
                    within_secs: 30,
                },
                TemporalStage {
                    predicate: TemporalPredicate {
                        event_class: EventClass::NetworkConnect,
                        process_any_of: None,
                        parent_any_of: None,
                        uid_eq: None,
                        uid_ne: None,
                        dst_port_not_in: Some(set_u16([80, 443])),
                    },
                    within_secs: 10,
                },
            ],
        };

        let priv_esc = TemporalRule {
            name: "phi_priv_esc".to_string(),
            stages: vec![
                TemporalStage {
                    predicate: TemporalPredicate {
                        event_class: EventClass::ProcessExec,
                        process_any_of: None,
                        parent_any_of: None,
                        uid_eq: None,
                        uid_ne: Some(0),
                        dst_port_not_in: None,
                    },
                    within_secs: 60,
                },
                TemporalStage {
                    predicate: TemporalPredicate {
                        event_class: EventClass::ProcessExec,
                        process_any_of: None,
                        parent_any_of: None,
                        uid_eq: Some(0),
                        uid_ne: None,
                        dst_port_not_in: None,
                    },
                    within_secs: 20,
                },
            ],
        };

        e.add_rule(webshell);
        e.add_rule(priv_esc);
        e
    }

    pub fn add_rule(&mut self, rule: TemporalRule) {
        let rid = self.rules.len();
        for stage in &rule.stages {
            self.subscriptions
                .entry(stage.predicate.event_class)
                .or_default()
                .push(rid);
        }
        self.rules.push(rule);
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Vec<String> {
        let mut hits = Vec::new();
        let Some(rule_ids) = self.subscriptions.get(&event.event_class).cloned() else {
            return hits;
        };

        let entity = event.entity_key();
        for rid in rule_ids {
            let Some(rule) = self.rules.get(rid) else {
                continue;
            };
            if rule.stages.is_empty() {
                continue;
            }

            let key = (rid, entity.clone());
            let current = self.states.get(&key).cloned();

            let mut next_state = current.clone();
            if let Some(state) = current {
                let stage_idx = state.stage_idx.min(rule.stages.len() - 1);
                let stage = &rule.stages[stage_idx];

                let monotonic_ok = event.ts_unix + self.reorder_tolerance_secs >= state.last_match_ts;
                let within = event.ts_unix - state.last_match_ts <= stage.within_secs as i64;
                if monotonic_ok && within && stage.predicate.matches(event) {
                    let advanced = stage_idx + 1;
                    if advanced >= rule.stages.len() {
                        hits.push(rule.name.clone());
                        self.states.remove(&key);
                        continue;
                    }
                    next_state = Some(TemporalState {
                        stage_idx: advanced,
                        first_match_ts: state.first_match_ts,
                        last_match_ts: event.ts_unix,
                    });
                } else if rule.stages[0].predicate.matches(event) {
                    if rule.stages.len() == 1 {
                        hits.push(rule.name.clone());
                        self.states.remove(&key);
                        continue;
                    }
                    next_state = Some(TemporalState {
                        stage_idx: 1,
                        first_match_ts: event.ts_unix,
                        last_match_ts: event.ts_unix,
                    });
                } else {
                    let max_window = rule
                        .stages
                        .iter()
                        .map(|s| s.within_secs as i64)
                        .sum::<i64>();
                    if event.ts_unix-state.first_match_ts > max_window {
                        next_state = None;
                    }
                }
            } else if rule.stages[0].predicate.matches(event) {
                if rule.stages.len() == 1 {
                    hits.push(rule.name.clone());
                    continue;
                }
                next_state = Some(TemporalState {
                    stage_idx: 1,
                    first_match_ts: event.ts_unix,
                    last_match_ts: event.ts_unix,
                });
            }

            match next_state {
                Some(st) => {
                    self.states.insert(key, st);
                }
                None => {
                    self.states.remove(&key);
                }
            }
        }

        hits
    }
}

#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    pub window_size: usize,
    pub alpha: f64,
    pub delta_high: f64,
    pub delta_med: f64,
    pub tau_floor_high: f64,
    pub tau_floor_med: f64,
    pub min_entropy_len: usize,
    pub entropy_threshold: f64,
    pub entropy_z_threshold: f64,
    pub entropy_history_limit: usize,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            window_size: 128,
            alpha: 1.0,
            delta_high: 1e-6,
            delta_med: 1e-3,
            tau_floor_high: 0.25,
            tau_floor_med: 0.10,
            min_entropy_len: 40,
            entropy_threshold: 4.2,
            entropy_z_threshold: 3.0,
            entropy_history_limit: 512,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct WindowState {
    counts: HashMap<EventClass, u64>,
    n: usize,
}

#[derive(Debug, Clone)]
pub struct AnomalyDecision {
    pub high: bool,
    pub medium: bool,
    pub kl_bits: f64,
    pub tau_high: f64,
    pub tau_med: f64,
    pub entropy_bits: Option<f64>,
    pub entropy_z: Option<f64>,
}

pub struct AnomalyEngine {
    config: AnomalyConfig,
    baselines: HashMap<String, HashMap<EventClass, f64>>,
    windows: HashMap<String, WindowState>,
    entropy_history: HashMap<String, VecDeque<f64>>,
}

impl AnomalyEngine {
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            config,
            baselines: HashMap::new(),
            windows: HashMap::new(),
            entropy_history: HashMap::new(),
        }
    }

    pub fn set_baseline(&mut self, process_key: String, dist: HashMap<EventClass, f64>) {
        self.baselines.insert(process_key, dist);
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Option<AnomalyDecision> {
        let key = event.process_key();
        let window = self.windows.entry(key.clone()).or_default();
        *window.counts.entry(event.event_class).or_insert(0) += 1;
        window.n += 1;

        let (entropy_bits, entropy_z, entropy_high) = self.observe_entropy(event);

        if window.n < self.config.window_size {
            if entropy_high {
                return Some(AnomalyDecision {
                    high: true,
                    medium: false,
                    kl_bits: 0.0,
                    tau_high: 0.0,
                    tau_med: 0.0,
                    entropy_bits,
                    entropy_z,
                });
            }
            return None;
        }

        let n = window.n;
        let k = EVENT_CLASSES.len();
        let baseline = self
            .baselines
            .get(&key)
            .cloned()
            .unwrap_or_else(default_uniform_baseline);

        let (p, q) = distributions(window, &baseline, self.config.alpha);
        let kl = kl_divergence_bits(&p, &q);

        let tau_high = self
            .config
            .tau_floor_high
            .max(tau_delta_bits(n, k, self.config.delta_high));
        let tau_med = self
            .config
            .tau_floor_med
            .max(tau_delta_bits(n, k, self.config.delta_med));

        let high = kl > tau_high || entropy_high;
        let medium = !high && kl > tau_med;

        *window = WindowState::default();

        if high || medium {
            return Some(AnomalyDecision {
                high,
                medium,
                kl_bits: kl,
                tau_high,
                tau_med,
                entropy_bits,
                entropy_z,
            });
        }

        None
    }

    fn observe_entropy(&mut self, event: &TelemetryEvent) -> (Option<f64>, Option<f64>, bool) {
        let Some(cmd) = &event.command_line else {
            return (None, None, false);
        };
        if cmd.len() < self.config.min_entropy_len {
            return (None, None, false);
        }

        let h = shannon_entropy_bits(cmd);
        let history = self
            .entropy_history
            .entry(event.process.clone())
            .or_default();

        let z = robust_z(h, history);
        history.push_back(h);
        while history.len() > self.config.entropy_history_limit {
            history.pop_front();
        }

        let high = h > self.config.entropy_threshold && z > self.config.entropy_z_threshold;
        (Some(h), Some(z), high)
    }
}

impl Default for AnomalyEngine {
    fn default() -> Self {
        Self::new(AnomalyConfig::default())
    }
}

#[derive(Debug, Clone)]
struct GraphNode {
    pid: u32,
    ppid: u32,
    process: String,
    uid: u32,
    last_seen: i64,
    network_non_web: bool,
    module_loaded: bool,
    sensitive_file_access: bool,
}

#[derive(Debug, Clone)]
pub struct TemplatePredicate {
    pub process_any_of: Option<HashSet<String>>,
    pub uid_eq: Option<u32>,
    pub uid_ne: Option<u32>,
    pub require_network_non_web: bool,
    pub require_module_loaded: bool,
    pub require_sensitive_file_access: bool,
}

impl TemplatePredicate {
    fn matches(&self, node: &GraphNode) -> bool {
        if let Some(set) = &self.process_any_of {
            if !set.contains(&node.process) {
                return false;
            }
        }
        if let Some(uid) = self.uid_eq {
            if node.uid != uid {
                return false;
            }
        }
        if let Some(uid) = self.uid_ne {
            if node.uid == uid {
                return false;
            }
        }
        if self.require_network_non_web && !node.network_non_web {
            return false;
        }
        if self.require_module_loaded && !node.module_loaded {
            return false;
        }
        if self.require_sensitive_file_access && !node.sensitive_file_access {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct KillChainTemplate {
    pub name: String,
    pub stages: Vec<TemplatePredicate>,
    pub max_depth: usize,
    pub max_inter_stage_secs: i64,
}

#[derive(Debug, Clone)]
struct ProcessGraph {
    nodes: HashMap<u32, GraphNode>,
    children: HashMap<u32, HashSet<u32>>,
    window_secs: i64,
}

impl ProcessGraph {
    fn new(window_secs: i64) -> Self {
        Self {
            nodes: HashMap::new(),
            children: HashMap::new(),
            window_secs,
        }
    }

    fn observe(&mut self, event: &TelemetryEvent) {
        let node = self.nodes.entry(event.pid).or_insert_with(|| GraphNode {
            pid: event.pid,
            ppid: event.ppid,
            process: event.process.clone(),
            uid: event.uid,
            last_seen: event.ts_unix,
            network_non_web: false,
            module_loaded: false,
            sensitive_file_access: false,
        });

        node.ppid = event.ppid;
        node.process = event.process.clone();
        node.uid = event.uid;
        node.last_seen = event.ts_unix;

        self.children
            .entry(event.ppid)
            .or_default()
            .insert(event.pid);

        match event.event_class {
            EventClass::NetworkConnect => {
                if let Some(p) = event.dst_port {
                    if p != 80 && p != 443 {
                        node.network_non_web = true;
                    }
                }
            }
            EventClass::ModuleLoad => {
                node.module_loaded = true;
            }
            EventClass::FileOpen => {
                if let Some(path) = &event.file_path {
                    if path.starts_with("/etc/shadow")
                        || path.starts_with("/etc/passwd")
                        || path.contains("credential")
                    {
                        node.sensitive_file_access = true;
                    }
                }
            }
            _ => {}
        }

        self.prune(event.ts_unix);
    }

    fn prune(&mut self, now: i64) {
        let cutoff = now - self.window_secs;
        let stale: Vec<u32> = self
            .nodes
            .iter()
            .filter_map(|(pid, n)| if n.last_seen < cutoff { Some(*pid) } else { None })
            .collect();

        for pid in stale {
            self.nodes.remove(&pid);
            self.children.remove(&pid);
            for child_set in self.children.values_mut() {
                child_set.remove(&pid);
            }
        }
    }
}

pub struct Layer4Engine {
    graph: ProcessGraph,
    templates: Vec<KillChainTemplate>,
}

impl Layer4Engine {
    pub fn new(window_secs: i64) -> Self {
        Self {
            graph: ProcessGraph::new(window_secs),
            templates: Vec::new(),
        }
    }

    pub fn with_default_templates() -> Self {
        let mut e = Self::new(300);

        e.templates.push(KillChainTemplate {
            name: "killchain_webshell_network".to_string(),
            stages: vec![
                TemplatePredicate {
                    process_any_of: Some(set_of(["nginx", "apache2", "httpd", "caddy"])),
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                },
                TemplatePredicate {
                    process_any_of: Some(set_of(["bash", "sh", "dash", "zsh", "python", "perl"])),
                    uid_eq: None,
                    uid_ne: None,
                    require_network_non_web: true,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                },
            ],
            max_depth: 6,
            max_inter_stage_secs: 30,
        });

        e.templates.push(KillChainTemplate {
            name: "killchain_user_root_module".to_string(),
            stages: vec![
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: None,
                    uid_ne: Some(0),
                    require_network_non_web: false,
                    require_module_loaded: false,
                    require_sensitive_file_access: false,
                },
                TemplatePredicate {
                    process_any_of: None,
                    uid_eq: Some(0),
                    uid_ne: None,
                    require_network_non_web: false,
                    require_module_loaded: true,
                    require_sensitive_file_access: false,
                },
            ],
            max_depth: 6,
            max_inter_stage_secs: 60,
        });

        e
    }

    pub fn add_template(&mut self, template: KillChainTemplate) {
        self.templates.push(template);
    }

    pub fn observe(&mut self, event: &TelemetryEvent) -> Vec<String> {
        self.graph.observe(event);

        let mut hits = Vec::new();
        let node_ids: Vec<u32> = self.graph.nodes.keys().copied().collect();
        for t in &self.templates {
            for pid in &node_ids {
                if self.match_from(*pid, t, 0, 0, 0) {
                    hits.push(t.name.clone());
                    break;
                }
            }
        }

        hits
    }

    fn match_from(
        &self,
        pid: u32,
        template: &KillChainTemplate,
        stage_idx: usize,
        depth: usize,
        prev_ts: i64,
    ) -> bool {
        if stage_idx >= template.stages.len() || depth > template.max_depth {
            return false;
        }

        let Some(node) = self.graph.nodes.get(&pid) else {
            return false;
        };
        if stage_idx > 0 && node.last_seen - prev_ts > template.max_inter_stage_secs {
            return false;
        }

        if !template.stages[stage_idx].matches(node) {
            return false;
        }

        if stage_idx + 1 == template.stages.len() {
            return true;
        }

        if let Some(children) = self.graph.children.get(&pid) {
            for child in children {
                if self.match_from(*child, template, stage_idx + 1, depth + 1, node.last_seen) {
                    return true;
                }
            }
        }

        false
    }
}

impl Default for Layer4Engine {
    fn default() -> Self {
        Self::with_default_templates()
    }
}

#[derive(Debug, Clone)]
pub struct DetectionOutcome {
    pub confidence: Confidence,
    pub signals: DetectionSignals,
    pub temporal_hits: Vec<String>,
    pub kill_chain_hits: Vec<String>,
    pub anomaly: Option<AnomalyDecision>,
    pub layer1: Layer1EventHit,
}

pub struct DetectionEngine {
    pub layer1: IocLayer1,
    pub layer2: TemporalEngine,
    pub layer3: AnomalyEngine,
    pub layer4: Layer4Engine,
}

impl DetectionEngine {
    pub fn new(layer1: IocLayer1, layer2: TemporalEngine, layer3: AnomalyEngine, layer4: Layer4Engine) -> Self {
        Self {
            layer1,
            layer2,
            layer3,
            layer4,
        }
    }

    pub fn default_with_rules() -> Self {
        Self {
            layer1: IocLayer1::new(),
            layer2: TemporalEngine::with_default_rules(),
            layer3: AnomalyEngine::default(),
            layer4: Layer4Engine::with_default_templates(),
        }
    }

    pub fn process_event(&mut self, event: &TelemetryEvent) -> DetectionOutcome {
        let layer1 = self.layer1.check_event(event);
        let temporal_hits = self.layer2.observe(event);
        let anomaly = self.layer3.observe(event);
        let kill_chain_hits = self.layer4.observe(event);

        let signals = DetectionSignals {
            z1_exact_ioc: layer1.result == Layer1Result::ExactMatch,
            z2_temporal: !temporal_hits.is_empty(),
            z3_anomaly_high: anomaly.as_ref().map(|a| a.high).unwrap_or(false),
            z3_anomaly_med: anomaly.as_ref().map(|a| a.medium).unwrap_or(false),
            z4_kill_chain: !kill_chain_hits.is_empty(),
            l1_prefilter_hit: layer1.prefilter_hit,
        };

        let confidence = confidence_policy(&signals);
        DetectionOutcome {
            confidence,
            signals,
            temporal_hits,
            kill_chain_hits,
            anomaly,
            layer1,
        }
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::default_with_rules()
    }
}

fn set_of<const N: usize>(values: [&str; N]) -> Option<HashSet<String>> {
    let mut out = HashSet::new();
    for v in values {
        out.insert(v.to_string());
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn set_u16<const N: usize>(values: [u16; N]) -> HashSet<u16> {
    let mut out = HashSet::new();
    for v in values {
        out.insert(v);
    }
    out
}

fn default_uniform_baseline() -> HashMap<EventClass, f64> {
    let mut out = HashMap::new();
    let p = 1.0 / EVENT_CLASSES.len() as f64;
    for c in EVENT_CLASSES {
        out.insert(c, p);
    }
    out
}

fn distributions(
    window: &WindowState,
    baseline: &HashMap<EventClass, f64>,
    alpha: f64,
) -> (Vec<f64>, Vec<f64>) {
    let mut p = Vec::with_capacity(EVENT_CLASSES.len());
    let mut q = Vec::with_capacity(EVENT_CLASSES.len());

    let n = window.n.max(1) as f64;
    let bsum: f64 = EVENT_CLASSES
        .iter()
        .map(|c| baseline.get(c).copied().unwrap_or(0.0))
        .sum();
    let denom = bsum + alpha * EVENT_CLASSES.len() as f64;

    for c in EVENT_CLASSES {
        let count = window.counts.get(&c).copied().unwrap_or(0) as f64;
        p.push(count / n);

        let b = baseline.get(&c).copied().unwrap_or(0.0);
        q.push((b + alpha) / denom);
    }

    (p, q)
}

fn kl_divergence_bits(p: &[f64], q: &[f64]) -> f64 {
    p.iter()
        .zip(q)
        .filter(|(pi, qi)| **pi > 0.0 && **qi > 0.0)
        .map(|(pi, qi)| pi * (pi / qi).log2())
        .sum()
}

fn tau_delta_bits(n: usize, k: usize, delta: f64) -> f64 {
    if n == 0 || delta <= 0.0 {
        return 0.0;
    }
    let n_f = n as f64;
    let k_f = k as f64;
    (k_f * (n_f + 1.0).log2() + (1.0 / delta).log2()) / n_f
}

fn shannon_entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<u8, usize> = HashMap::new();
    for b in s.as_bytes() {
        *freq.entry(*b).or_insert(0) += 1;
    }

    let n = s.len() as f64;
    freq.values()
        .map(|c| {
            let p = *c as f64 / n;
            if p == 0.0 {
                0.0
            } else {
                -p * p.log2()
            }
        })
        .sum()
}

fn robust_z(value: f64, history: &VecDeque<f64>) -> f64 {
    if history.len() < 10 {
        return 0.0;
    }

    let mut values: Vec<f64> = history.iter().copied().collect();
    values.sort_by(|a, b| a.total_cmp(b));
    let median = percentile_sorted(&values, 50.0);

    let mut abs_dev: Vec<f64> = values.iter().map(|x| (x - median).abs()).collect();
    abs_dev.sort_by(|a, b| a.total_cmp(b));
    let mad = percentile_sorted(&abs_dev, 50.0).max(1e-9);

    (value - median) / (1.4826 * mad)
}

fn percentile_sorted(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * (values.len() - 1) as f64).round() as usize;
    values[rank.min(values.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(ts: i64, class: EventClass, process: &str, parent: &str, uid: u32) -> TelemetryEvent {
        TelemetryEvent {
            ts_unix: ts,
            event_class: class,
            pid: 100,
            ppid: 10,
            uid,
            process: process.to_string(),
            parent_process: parent.to_string(),
            file_path: None,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: None,
        }
    }

    #[test]
    fn confidence_ordering_matches_policy() {
        let base = DetectionSignals {
            z1_exact_ioc: false,
            z2_temporal: false,
            z3_anomaly_high: false,
            z3_anomaly_med: false,
            z4_kill_chain: false,
            l1_prefilter_hit: false,
        };

        let mut s = base.clone();
        s.z1_exact_ioc = true;
        assert_eq!(confidence_policy(&s), Confidence::Definite);

        let mut s = base.clone();
        s.z2_temporal = true;
        s.l1_prefilter_hit = true;
        assert_eq!(confidence_policy(&s), Confidence::VeryHigh);

        let mut s = base.clone();
        s.z2_temporal = true;
        assert_eq!(confidence_policy(&s), Confidence::High);

        let mut s = base.clone();
        s.z3_anomaly_high = true;
        assert_eq!(confidence_policy(&s), Confidence::Medium);

        let mut s = base;
        s.z3_anomaly_med = true;
        assert_eq!(confidence_policy(&s), Confidence::Low);
    }

    #[test]
    fn layer1_exact_verification_works() {
        let mut l1 = IocLayer1::new();
        l1.load_hashes(["abc".to_string()]);
        l1.load_domains(["bad.example".to_string()]);
        l1.load_ips(["1.2.3.4".to_string()]);
        l1.load_string_signatures(["curl|bash".to_string()]);

        assert_eq!(l1.check_hash("abc"), Layer1Result::ExactMatch);
        assert_eq!(l1.check_hash("nope"), Layer1Result::Clean);
        assert_eq!(l1.check_domain("BAD.EXAMPLE"), Layer1Result::ExactMatch);
        assert_eq!(l1.check_ip("1.2.3.4"), Layer1Result::ExactMatch);

        let mut ev = event(1, EventClass::ProcessExec, "bash", "sshd", 1000);
        ev.command_line = Some("curl|bash -s evil".to_string());
        let hit = l1.check_event(&ev);
        assert!(hit.matched_signatures.iter().any(|s| s == "curl|bash"));
    }

    #[test]
    fn temporal_engine_detects_webshell_pattern() {
        let mut t = TemporalEngine::with_default_rules();

        let mut e1 = event(1, EventClass::ProcessExec, "bash", "nginx", 33);
        e1.pid = 200;
        assert!(t.observe(&e1).is_empty());

        let mut e2 = event(5, EventClass::NetworkConnect, "bash", "nginx", 33);
        e2.pid = 200;
        e2.dst_port = Some(8080);

        let hits = t.observe(&e2);
        assert!(hits.iter().any(|h| h == "phi_webshell"));
    }

    #[test]
    fn anomaly_engine_flags_distribution_shift() {
        let mut a = AnomalyEngine::default();
        let mut baseline = HashMap::new();
        baseline.insert(EventClass::ProcessExec, 0.9);
        baseline.insert(EventClass::NetworkConnect, 0.1);
        a.set_baseline("bash:sshd".to_string(), baseline);

        for i in 0..128 {
            let mut e = event(i, EventClass::NetworkConnect, "bash", "sshd", 1000);
            e.dst_port = Some(4444);
            let out = a.observe(&e);
            if i == 127 {
                let decision = out.expect("decision");
                assert!(decision.high || decision.medium);
            }
        }
    }

    #[test]
    fn layer4_matches_default_template() {
        let mut l4 = Layer4Engine::with_default_templates();

        let mut parent = event(1, EventClass::ProcessExec, "nginx", "systemd", 33);
        parent.pid = 10;
        parent.ppid = 1;
        let _ = l4.observe(&parent);

        let mut child = event(2, EventClass::ProcessExec, "bash", "nginx", 33);
        child.pid = 11;
        child.ppid = 10;
        let _ = l4.observe(&child);

        let mut net = event(4, EventClass::NetworkConnect, "bash", "nginx", 33);
        net.pid = 11;
        net.ppid = 10;
        net.dst_port = Some(9001);
        let hits = l4.observe(&net);
        assert!(hits.iter().any(|h| h == "killchain_webshell_network"));
    }

    #[test]
    fn engine_runs_all_layers() {
        let mut d = DetectionEngine::default_with_rules();
        d.layer1.load_hashes(["deadbeef".to_string()]);

        let mut ev = event(1, EventClass::ProcessExec, "bash", "sshd", 1000);
        ev.file_hash = Some("deadbeef".to_string());
        let out = d.process_event(&ev);
        assert_eq!(out.confidence, Confidence::Definite);
    }
}
