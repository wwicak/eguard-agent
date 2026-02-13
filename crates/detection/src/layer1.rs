use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use rusqlite::{params, Connection};

use crate::types::TelemetryEvent;

pub(crate) const PREFILTER_MAX_LOAD_FACTOR: f64 = 0.95;

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn cuckoo_false_positive_rate(bucket_size: u32, fingerprint_bits: u32) -> f64 {
    let numerator = 2.0 * bucket_size as f64;
    let denominator = 2_f64.powi(fingerprint_bits as i32);
    numerator / denominator
}

pub(crate) fn should_rebuild_prefilter(load_factor: f64, insertion_failed: bool) -> bool {
    insertion_failed || load_factor > PREFILTER_MAX_LOAD_FACTOR
}

pub(crate) fn normalize_for_matching(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let c = if ch == '\\' { '/' } else { ch };
        out.push(c.to_ascii_lowercase());
    }
    out
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn base64ish_alphabet_ratio(raw: &str) -> f64 {
    let mut total = 0usize;
    let mut in_alphabet = 0usize;

    for b in raw.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        total += 1;
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_') {
            in_alphabet += 1;
        }
    }

    if total == 0 {
        0.0
    } else {
        in_alphabet as f64 / total as f64
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn passes_optional_alphabet_ratio_gate(raw: &str, min_ratio: Option<f64>) -> bool {
    let Some(min_ratio) = min_ratio else {
        return true;
    };
    base64ish_alphabet_ratio(raw) >= min_ratio
}

fn hashset_load_factor(set: &HashSet<String>) -> f64 {
    if set.is_empty() {
        return 0.0;
    }
    let cap = set.capacity().max(1);
    set.len() as f64 / cap as f64
}

fn rebuild_prefilter_if_needed(set: &mut HashSet<String>, rebuilds: &mut usize) {
    let load_factor = hashset_load_factor(set);
    if !should_rebuild_prefilter(load_factor, false) {
        return;
    }

    let target = ((set.len().max(1) as f64) / PREFILTER_MAX_LOAD_FACTOR).ceil() as usize + 1;
    let mut rebuilt = HashSet::with_capacity(target);
    for value in set.drain() {
        rebuilt.insert(value);
    }
    *set = rebuilt;
    *rebuilds = rebuilds.saturating_add(1);
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

impl std::fmt::Debug for IocExactStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IocExactStore").finish()
    }
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
    prefilter_rebuilds: usize,
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
            prefilter_rebuilds: 0,
        }
    }

    pub fn with_sqlite(path: &str) -> rusqlite::Result<Self> {
        let mut layer = Self::new();
        layer.exact_store = Some(IocExactStore::open(path)?);
        Ok(layer)
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
        rebuild_prefilter_if_needed(&mut self.prefilter_hashes, &mut self.prefilter_rebuilds);
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
            let normalized = v.to_ascii_lowercase();
            self.prefilter_domains.insert(normalized.clone());
            self.exact_domains.insert(normalized.clone());
            copy.push(normalized);
        }
        rebuild_prefilter_if_needed(&mut self.prefilter_domains, &mut self.prefilter_rebuilds);
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
        rebuild_prefilter_if_needed(&mut self.prefilter_ips, &mut self.prefilter_rebuilds);
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
                self.matcher_patterns.push(normalize_for_matching(&p));
            }
        }

        self.rebuild_matcher();
    }

    pub fn append_string_signatures<I>(&mut self, patterns: I)
    where
        I: IntoIterator<Item = String>,
    {
        for p in patterns {
            if p.is_empty() {
                continue;
            }
            let normalized = normalize_for_matching(&p);
            if self
                .matcher_patterns
                .iter()
                .any(|existing| existing == &normalized)
            {
                continue;
            }
            self.matcher_patterns.push(normalized);
        }

        self.rebuild_matcher();
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

        let normalized = normalize_for_matching(text);
        let mut matches = Vec::new();
        for m in matcher.find_iter(&normalized) {
            if let Some(pattern) = self.matcher_patterns.get(m.pattern().as_usize()) {
                matches.push(pattern.clone());
            }
        }
        matches
    }

    pub fn self_check_hash_sample<I>(&self, sample: I) -> bool
    where
        I: IntoIterator<Item = String>,
    {
        for hash in sample {
            if !self.prefilter_hashes.contains(&hash) {
                return false;
            }
            if !matches!(self.check_hash(&hash), Layer1Result::ExactMatch) {
                return false;
            }
        }
        true
    }

    pub fn self_check_domain_sample<I>(&self, sample: I) -> bool
    where
        I: IntoIterator<Item = String>,
    {
        for domain in sample {
            let normalized = domain.to_ascii_lowercase();
            if !self.prefilter_domains.contains(&normalized) {
                return false;
            }
            if !matches!(self.check_domain(&normalized), Layer1Result::ExactMatch) {
                return false;
            }
        }
        true
    }

    pub fn self_check_ip_sample<I>(&self, sample: I) -> bool
    where
        I: IntoIterator<Item = String>,
    {
        for ip in sample {
            if !self.prefilter_ips.contains(&ip) {
                return false;
            }
            if !matches!(self.check_ip(&ip), Layer1Result::ExactMatch) {
                return false;
            }
        }
        true
    }

    pub fn check_event(&self, event: &TelemetryEvent) -> Layer1EventHit {
        let mut hit = Layer1EventHit::default();

        if let Some(hash) = &event.file_hash {
            Self::apply_result(self.check_hash(hash), "file_hash", &mut hit);
        }
        if let Some(domain) = &event.dst_domain {
            Self::apply_result(self.check_domain(domain), "dst_domain", &mut hit);
        }
        if let Some(ip) = &event.dst_ip {
            Self::apply_result(self.check_ip(ip), "dst_ip", &mut hit);
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

    pub fn ioc_entry_count(&self) -> usize {
        self.exact_hashes.len() + self.exact_domains.len() + self.exact_ips.len()
    }

    fn apply_result(result: Layer1Result, field: &str, hit: &mut Layer1EventHit) {
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

    fn rebuild_matcher(&mut self) {
        if self.matcher_patterns.is_empty() {
            self.matcher = None;
            return;
        }
        self.matcher = AhoCorasick::new(self.matcher_patterns.clone()).ok();
    }

    #[cfg(test)]
    pub(crate) fn debug_matcher_pattern_count(&self) -> usize {
        self.matcher_patterns.len()
    }

    #[cfg(test)]
    pub(crate) fn debug_matcher_pattern_bytes(&self) -> usize {
        self.matcher_patterns.iter().map(|p| p.len()).sum()
    }

    #[cfg(test)]
    pub(crate) fn debug_prefilter_load_factors(&self) -> (f64, f64, f64) {
        (
            hashset_load_factor(&self.prefilter_hashes),
            hashset_load_factor(&self.prefilter_domains),
            hashset_load_factor(&self.prefilter_ips),
        )
    }

    #[cfg(test)]
    pub(crate) fn debug_prefilter_rebuilds(&self) -> usize {
        self.prefilter_rebuilds
    }
}

impl Default for IocLayer1 {
    fn default() -> Self {
        Self::new()
    }
}
