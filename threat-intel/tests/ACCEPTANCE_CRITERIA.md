# Threat Intel Pipeline — Acceptance Criteria

> Generated from design doc review (sections 15-18) against implementation.
> Use this document to write unit tests. Each AC has a unique ID for traceability.

---

## Bugs Found (Fix Before Testing)

| # | Severity | Component | Description |
|---|----------|-----------|-------------|
| B1 | **CRITICAL** | cve_extract.py | NVD 2.0 `configurations` is a **list**, code treats it as a dict — `.get("nodes")` on a list raises `AttributeError`. All real NVD 2.0 data will fail. |
| B2 | **HIGH** | sigma_filter.py | Non-dict top-level YAML document crashes script — `docs[0].get("status")` raises `AttributeError` on list/scalar values |
| B3 | **HIGH** | sigma_filter.py | Explicit `status: null` crashes — `None.lower()` raises `AttributeError` (`.get("status", "")` returns `None` not `""` for YAML null) |
| B4 | **HIGH** | yara_validate.py | Silent scan error swallowing — `except yara.Error: pass` in `scan_clean_files()` promotes crash-prone rules to output |
| B5 | **HIGH** | ioc_dedup.py | OTX/alienvault assigned Tier 3, design says Tier 4 — inflates confidence |
| B6 | **HIGH** | ioc_dedup.py | Single Tier 1 source yields "medium" confidence, design says "high" (auto-include) |
| B7 | **MEDIUM** | workflows | Duplicate bundle builds — `gh workflow run` + `workflow_run` trigger both fire |
| B8 | **MEDIUM** | workflows | No concurrency control — parallel collect pushes can fail with non-fast-forward |
| B9 | **MEDIUM** | yara_validate.py | CLI flag `--rules-dir` from design doc doesn't exist, only `--input` |
| B10 | **MEDIUM** | ioc_dedup.py | PhishTank missing from `SOURCE_TIERS` — would fall to Tier 4 |

---

## Design Deviations (Intentional / Accepted)

| # | Topic | Design Says | Implementation Does | Status |
|---|-------|-------------|---------------------|--------|
| DD1 | Signing | Ed25519 (`signature.ed25519`) | GPG (`manifest.json.asc`) | **Intentional change** |
| DD2 | IOC file format | `.json` (JSON arrays) | `.txt` (JSONL) | Accepted — JSONL is streaming-friendly |
| DD3 | CVE file name | `cve/cve-checks.json` | `cve/cves.jsonl` | Accepted |
| DD4 | Repo location | `eguard-threat-intel/` separate repo | `eguard-agent/threat-intel/` | Intentional — same repo |
| DD5 | Script paths | `processing/` at root | `threat-intel/processing/` | Matches DD4 |
| DD6 | ThreatFox fetch | JSON API | CSV export | Functionally equivalent |
| DD7 | Version format | `YYYY.MM.DD` (daily) | `YYYY.MM.DD.HHMM` (minute) | Better — multiple bundles/day |
| DD8 | Webhook notification | POST to eGuard server | Not implemented | **Deferred** — server-side not ready |

---

## 1. sigma_filter.py

### 1.1 Happy Path

| ID | Description |
|----|-------------|
| AC-SIGMA-001 | Rule with `status: stable` + `logsource.product: linux` is kept when `--platforms linux` |
| AC-SIGMA-002 | Rule with `status: test` + `logsource.product: linux` is kept when `--min-status test` |
| AC-SIGMA-003 | Rule with `status: test` is **rejected** when `--min-status stable` |
| AC-SIGMA-004 | Rule with `status: stable`, no `logsource.product`, no Windows-only service → kept (generic rule) |
| AC-SIGMA-005 | Rule with `logsource.product: linux` + `logsource.category: process_creation` → kept |
| AC-SIGMA-006 | Multiple platforms `--platforms linux,macos` — rules for either kept |
| AC-SIGMA-007 | Output subdirectory structure mirrors input layout |
| AC-SIGMA-008 | Summary to stdout shows `kept/total` counts, platforms, min_status |
| AC-SIGMA-009 | Only `.yml` and `.yaml` files processed; `.json`, `.md`, `.txt` ignored |
| AC-SIGMA-010 | File metadata preserved via `shutil.copy2` |

### 1.2 Windows Exclusion

| ID | Description |
|----|-------------|
| AC-SIGMA-W001 | `logsource.product: windows` → rejected |
| AC-SIGMA-W002 | `logsource.product: microsoft365` → rejected |
| AC-SIGMA-W003 | `logsource.product: azure` → rejected |
| AC-SIGMA-W004 | `logsource.product: office365` → rejected |
| AC-SIGMA-W005 | `logsource.service: sysmon` with no product → rejected |
| AC-SIGMA-W006 | `logsource.service: powershell` with no product → rejected |
| AC-SIGMA-W007 | `logsource.service: powershell-classic` with no product → rejected |
| AC-SIGMA-W008 | `logsource.service: windefend` with no product → rejected |
| AC-SIGMA-W009 | `logsource.service: bits-client` with no product → rejected |
| AC-SIGMA-W010 | `logsource.service: wmi` with no product → rejected |
| AC-SIGMA-W011 | `logsource.service: ntlm` with no product → rejected |
| AC-SIGMA-W012 | `logsource.service: security` with no product → rejected |
| AC-SIGMA-W013 | `logsource.service: system` with no product → rejected |
| AC-SIGMA-W014 | `logsource.service: application` with no product → rejected |
| AC-SIGMA-W015 | `logsource.service: taskscheduler` with no product → rejected |
| AC-SIGMA-W016 | `logsource.service: dns-server-analytic` with no product → rejected |
| AC-SIGMA-W017 | Windows-only service + `product: linux` (Sysmon for Linux) → **kept** |

### 1.3 Status Filtering

| ID | Description |
|----|-------------|
| AC-SIGMA-S001 | `status: experimental` → rejected |
| AC-SIGMA-S002 | `status: deprecated` → rejected |
| AC-SIGMA-S003 | `status: unsupported` → rejected |
| AC-SIGMA-S004 | `status: Stable` (mixed case) → kept (`.lower()` normalization) |
| AC-SIGMA-S005 | `status: TEST` (uppercase) → kept when min-status=test |
| AC-SIGMA-S006 | Missing `status` field → rejected (empty string not in valid set) |
| AC-SIGMA-S007 | `status: ""` (empty string) → rejected |
| AC-SIGMA-S008 | `status: null` (YAML null) → **BUG B3** — must not crash, should reject |

### 1.4 Edge Cases

| ID | Description |
|----|-------------|
| AC-SIGMA-E001 | Multi-document YAML — only first document used for filtering |
| AC-SIGMA-E002 | Empty YAML file (0 bytes) → skipped |
| AC-SIGMA-E003 | YAML with only comments → skipped |
| AC-SIGMA-E004 | YAML with null first doc followed by valid rule → skipped |
| AC-SIGMA-E005 | Missing `logsource` field entirely → kept (generic rule) |
| AC-SIGMA-E006 | `logsource` is a string not dict → rejected |
| AC-SIGMA-E007 | Product with mixed case value → `.lower()` handles it |
| AC-SIGMA-E008 | Non-YAML files in input → ignored, not counted in total |
| AC-SIGMA-E009 | Deeply nested subdirectories → preserved in output |
| AC-SIGMA-E010 | Symlinked directories → not traversed (`followlinks=False`) |
| AC-SIGMA-E011 | Symlinked files → processed normally |
| AC-SIGMA-E012 | Empty input directory → 0/0 kept, no error |
| AC-SIGMA-E013 | Duplicate filenames in different subdirs → both handled independently |
| AC-SIGMA-E014 | UTF-8 BOM in file → potential parse issue (uses `utf-8` not `utf-8-sig`) |
| AC-SIGMA-E015 | `product: macos` when `--platforms linux` → rejected |
| AC-SIGMA-E016 | `product: linux` when `--platforms linux,macos` → kept |
| AC-SIGMA-E017 | `product: macos` when `--platforms linux,macos` → kept |
| AC-SIGMA-E018 | `--platforms ""` (empty) → only generic rules kept |
| AC-SIGMA-E019 | Binary file with `.yml` extension → parse error caught, skipped |
| AC-SIGMA-E020 | Very large YAML (>10 MB) → completes (slow, no streaming) |
| AC-SIGMA-E021 | Non-dict top-level YAML (list) → **BUG B2** — must not crash |
| AC-SIGMA-E022 | `status: null` (explicit YAML null) → **BUG B3** — must not crash |
| AC-SIGMA-E023 | Stale rules in output from prior runs → not cleaned (gap) |
| AC-SIGMA-E024 | `--exclude-logsource` from design doc → NOT implemented |

### 1.5 Error Handling

| ID | Description |
|----|-------------|
| AC-SIGMA-ERR001 | Malformed YAML → caught, logged to stderr, skipped |
| AC-SIGMA-ERR002 | Permission denied on input file → caught, skipped |
| AC-SIGMA-ERR003 | Output dir doesn't exist → created automatically |
| AC-SIGMA-ERR004 | Output dir not writable → unhandled PermissionError |
| AC-SIGMA-ERR005 | Input dir doesn't exist → 0/0 kept, exits 0 |
| AC-SIGMA-ERR006 | Non-dict first YAML doc → **BUG B2** |
| AC-SIGMA-ERR007 | Explicit null status → **BUG B3** |
| AC-SIGMA-ERR008 | File disappears between walk and open → caught by try/except |
| AC-SIGMA-ERR009 | Disk full during copy → unhandled OSError |
| AC-SIGMA-ERR010 | Exit code always 0 — CI can't detect failures |

---

## 2. yara_validate.py

### 2.1 Happy Path

| ID | Description |
|----|-------------|
| AC-YARA-001 | Valid `.yar` rules compile and appear in output |
| AC-YARA-002 | Valid `.yara` rules also accepted |
| AC-YARA-003 | Summary shows `valid/total` with compile errors and FP removals |
| AC-YARA-004 | Output preserves subdirectory structure |

### 2.2 Compilation

| ID | Description |
|----|-------------|
| AC-YARA-C001 | Rule with syntax error → rejected, stderr says "INVALID (syntax)" |
| AC-YARA-C002 | Empty `.yar` file → rejected (compile error) |
| AC-YARA-C003 | Binary file with `.yar` extension → rejected, no crash |
| AC-YARA-C004 | Rule with `include "nonexistent.yar"` → rejected with include error |
| AC-YARA-C005 | Rule using modules (`import "pe"`, `import "elf"`) → compiles if yara-python has module support |
| AC-YARA-C006 | Very large rule file (>1 MB) → compiles within reasonable time |

### 2.3 False Positive Detection

| ID | Description |
|----|-------------|
| AC-YARA-FP001 | Rule matching clean file → removed, stderr says "FP REMOVED" |
| AC-YARA-FP002 | Rule `strings: $a = "hello" condition: $a` + clean file with "hello" → FP removed |
| AC-YARA-FP003 | Rule NOT matching any clean file → kept |
| AC-YARA-FP004 | Rule that crashes during scan → **BUG B4** — should be flagged, not silently promoted |
| AC-YARA-FP005 | Empty `--test-files` directory → FP check vacuously passes (document this behavior) |
| AC-YARA-FP006 | `--test-files` not provided → FP check skipped entirely |

### 2.4 Edge Cases

| ID | Description |
|----|-------------|
| AC-YARA-E001 | Non-.yar/.yara files ignored (`.txt`, `.yml`) |
| AC-YARA-E002 | Recursive directory scanning finds rules in subdirs |
| AC-YARA-E003 | Permission denied on rule file → rejected with error, processing continues |
| AC-YARA-E004 | Missing input directory → should error (currently silent 0/0 success) |
| AC-YARA-E005 | Input == output directory → invalid rules must be REMOVED from output |
| AC-YARA-E006 | Symlink handling (follows file symlinks, no infinite loop on dir symlinks) |

### 2.5 CLI / Output

| ID | Description |
|----|-------------|
| AC-YARA-CLI001 | `--rules-dir` accepted as alias for `--input` (design doc compatibility) — **BUG B9** |
| AC-YARA-CLI002 | Exit code reflects outcome (0=all valid, 1=some removed, 2=fatal) |
| AC-YARA-CLI003 | Machine-parseable output (JSON stats) alongside human summary |
| AC-YARA-CLI004 | Scan timeout protection — pathological regex doesn't hang indefinitely |

---

## 3. ioc_dedup.py

### 3.1 Source Tier Classification

| ID | Description |
|----|-------------|
| AC-IOC-T001 | `cisa` → Tier 1 |
| AC-IOC-T002 | `malwarebazaar`, `threatfox`, `feodo`, `urlhaus`, `abusech` → Tier 2 |
| AC-IOC-T003 | `otx`, `alienvault` → **Tier 4** (per design) — **BUG B5** (currently Tier 3) |
| AC-IOC-T004 | Unknown source → Tier 4 |
| AC-IOC-T005 | Case-insensitive tier lookup |
| AC-IOC-T006 | `phishtank` → Tier 2 — **BUG B10** (currently missing) |

### 3.2 Confidence / Corroboration

| ID | Sources | Expected Confidence |
|----|---------|---------------------|
| AC-IOC-C001 | {"cisa", "malwarebazaar"} (2+ sources, Tier 1-2) | high |
| AC-IOC-C002 | {"malwarebazaar", "threatfox"} (2+ Tier 2) | high |
| AC-IOC-C003 | {"cisa"} (single Tier 1) | **high** — **BUG B6** (currently medium) |
| AC-IOC-C004 | {"malwarebazaar"} (single Tier 2) | medium |
| AC-IOC-C005 | {"otx", "alienvault"} (2+ Tier 3/4) | medium |
| AC-IOC-C006 | {"otx"} (single Tier 3/4) | low |
| AC-IOC-C007 | {"other"} (single Tier 4) | low |
| AC-IOC-C008 | {"malwarebazaar", "other"} (2+ sources, min Tier 2) | high |
| AC-IOC-C009 | {"otx", "other"} (2+ sources, min Tier 3/4) | medium |
| AC-IOC-C010 | {"cisa", "malwarebazaar", "otx"} (3+ mixed) | high |

### 3.3 Staleness Expiry

| ID | Description |
|----|-------------|
| AC-IOC-S001 | Hash 89 days old → not stale |
| AC-IOC-S002 | Hash 91 days old → stale (removed) |
| AC-IOC-S003 | Hash exactly 90 days → **not stale** (`ts < cutoff`, boundary is exclusive) |
| AC-IOC-S004 | Domain 59 days → not stale |
| AC-IOC-S005 | Domain 61 days → stale |
| AC-IOC-S006 | IP 29 days → not stale |
| AC-IOC-S007 | IP 31 days → stale |
| AC-IOC-S008 | Unknown IOC type defaults to 90-day threshold |
| AC-IOC-S009 | ISO 8601 with `Z` suffix → parsed correctly |
| AC-IOC-S010 | ISO 8601 with `+00:00` offset → parsed correctly |
| AC-IOC-S011 | Unparseable timestamp → kept (fail-open) |
| AC-IOC-S012 | Empty/None timestamp → kept |
| AC-IOC-S013 | Future timestamp → not stale |

### 3.4 Deduplication

| ID | Description |
|----|-------------|
| AC-IOC-D001 | Exact duplicate values from same source → merged, source count=1 |
| AC-IOC-D002 | Case-insensitive dedup (`ABC123` and `abc123` → one entry) |
| AC-IOC-D003 | Whitespace-padded values trimmed and merged |
| AC-IOC-D004 | Same value from different sources → merged, both sources listed |
| AC-IOC-D005 | Empty value entries → skipped |
| AC-IOC-D006 | `first_seen` tracks earliest timestamp |
| AC-IOC-D007 | `last_seen` tracks latest timestamp |
| AC-IOC-D008 | Stale entries (by `last_seen`) removed from output |
| AC-IOC-D009 | Mixed stale/fresh entries for same value: fresh `last_seen` keeps it |
| AC-IOC-D010 | Sources list sorted alphabetically in output |

### 3.5 File Parsing

| ID | Description |
|----|-------------|
| AC-IOC-P001 | JSONL line with all fields → parsed correctly |
| AC-IOC-P002 | JSONL missing `source` → inferred from filename |
| AC-IOC-P003 | Plain text line → value=first token, source=inferred, timestamp=now |
| AC-IOC-P004 | CSV-like line → value=first comma-delimited field |
| AC-IOC-P005 | Comment lines (`#`) → skipped |
| AC-IOC-P006 | Empty lines → skipped |
| AC-IOC-P007 | Empty file → returns empty list |
| AC-IOC-P008 | File with only comments → returns empty list |
| AC-IOC-P009 | Mixed JSONL and plain text → each parsed by appropriate method |
| AC-IOC-P010 | Malformed JSON falls through to plain text parser |
| AC-IOC-P011 | Unicode values (punycode domains) → preserved, lowercased |
| AC-IOC-P012 | IPv6 addresses → preserved, lowercased |

### 3.6 Source Inference

| ID | Filename | Expected Source |
|----|----------|-----------------|
| AC-IOC-I001 | `malwarebazaar.txt` | "malwarebazaar" |
| AC-IOC-I002 | `threatfox_domains.txt` | "threatfox" |
| AC-IOC-I003 | `otx.txt` | "otx" |
| AC-IOC-I004 | `cisa_hashes.txt` | "cisa" |
| AC-IOC-I005 | `my_custom_feed.txt` | "other" |
| AC-IOC-I006 | `abusech_malwarebazaar.txt` | First match (fragile — document) |
| AC-IOC-I007 | `CISA_HASHES.txt` | "cisa" (basename lowered) |

### 3.7 Output / Integration

| ID | Description |
|----|-------------|
| AC-IOC-O001 | Output is valid JSONL (each line parseable) |
| AC-IOC-O002 | Each entry has: value, confidence, sources, first_seen, last_seen |
| AC-IOC-O003 | Sources is sorted array |
| AC-IOC-O004 | Output directory auto-created |
| AC-IOC-O005 | Compact JSON (`separators=(",",":")`) |
| AC-IOC-M001 | Missing type directory → skip message, no error |
| AC-IOC-M002 | All three types (hashes, domains, ips) processed |
| AC-IOC-M003 | Subdirectories in type dir ignored (only files) |

---

## 4. ioc_allowlist.py

### 4.1 Allowlist Loading

| ID | Description |
|----|-------------|
| AC-AL-L001 | Normal allowlist file → set of lowercased entries |
| AC-AL-L002 | Comment lines (`#`) → skipped |
| AC-AL-L003 | Empty lines → skipped |
| AC-AL-L004 | Case normalization (`ABC123` → `abc123`) |
| AC-AL-L005 | Empty file → empty set |
| AC-AL-L006 | File with only comments → empty set |
| AC-AL-L007 | Missing file path → empty set, no error |
| AC-AL-L008 | Whitespace trimmed (`  abc123  ` → `abc123`) |

### 4.2 Hash Filtering

| ID | Description |
|----|-------------|
| AC-AL-H001 | Exact hash match → removed |
| AC-AL-H002 | Case-insensitive match → removed |
| AC-AL-H003 | Non-matching hash → kept |
| AC-AL-H004 | Empty allowlist → all kept |
| AC-AL-H005 | All IOCs allowlisted → empty output |
| AC-AL-H006 | Partial hash match (substring) → NOT removed (exact only) |

### 4.3 Domain Filtering

| ID | Description |
|----|-------------|
| AC-AL-D001 | Exact domain match → removed |
| AC-AL-D002 | Subdomain NOT removed (`evil.github.com` not matched by `github.com`) |
| AC-AL-D003 | Case-insensitive match → removed |
| AC-AL-D004 | Non-matching domain → kept |
| AC-AL-D005 | Empty allowlist → all kept |
| AC-AL-D006 | Punycode domain match → works |

### 4.4 IP Passthrough

| ID | Description |
|----|-------------|
| AC-AL-I001 | IPs filtered with empty allowlist → all pass through |
| AC-AL-I002 | IP count reported correctly |

### 4.5 JSONL Parsing

| ID | Description |
|----|-------------|
| AC-AL-J001 | Valid JSONL → parsed and filtered |
| AC-AL-J002 | Empty lines → skipped |
| AC-AL-J003 | Malformed JSON → skipped silently |
| AC-AL-J004 | Entry without `value` field → kept (empty string not in allowlist) |
| AC-AL-J005 | Empty JSONL file → (0, 0) |

### 4.6 Missing/Edge Files

| ID | Description |
|----|-------------|
| AC-AL-F001 | Missing input JSONL → (0, 0), no error |
| AC-AL-F002 | Missing hash allowlist path (empty string) → no filtering |
| AC-AL-F003 | Missing domain allowlist path (empty string) → no filtering |
| AC-AL-F004 | Output directory auto-created |
| AC-AL-F005 | Output preserves all input JSONL fields |

---

## 5. cve_extract.py

### 5.1 NVD Parsing

| ID | Description |
|----|-------------|
| AC-CVE-001 | NVD 2.0 JSON: `vulnerabilities[].cve.configurations[]` (list) parsed correctly — **BUG B1** |
| AC-CVE-002 | NVD 1.0 JSON: `CVE_Items[]` with `cpe_match`/`cpe23Uri` (legacy) parsed correctly |
| AC-CVE-003 | Empty JSON object `{}` → zero records, no crash |
| AC-CVE-004 | JSON with `vulnerabilities: []` → zero records |
| AC-CVE-005 | Invalid JSON → graceful error (currently crashes — needs fix) |
| AC-CVE-006 | Directory input: multiple `.json` files processed in sorted order |
| AC-CVE-007 | Directory input: non-`.json` files ignored |
| AC-CVE-008 | Empty directory → zero records |

### 5.2 Linux Relevance Detection

| ID | Description |
|----|-------------|
| AC-CVE-L001 | CPE vendor `linux` → relevant |
| AC-CVE-L002 | CPE vendor `redhat`, `debian`, `ubuntu`, `canonical` → relevant |
| AC-CVE-L003 | CPE product `openssl`, `curl`, `nginx`, `linux_kernel` → relevant |
| AC-CVE-L004 | CPE vendor `microsoft` → NOT relevant |
| AC-CVE-L005 | CPE product `adobe` → NOT relevant |
| AC-CVE-L006 | No configurations/CPE data → NOT relevant |
| AC-CVE-L007 | Mixed CPEs (one Linux + one Windows) → relevant (any Linux match) |
| AC-CVE-L008 | Multiple configuration nodes → all traversed |
| AC-CVE-L009 | Nested children nodes with AND/OR operators → currently NOT traversed (gap) |

### 5.3 CVSS Extraction

| ID | Description |
|----|-------------|
| AC-CVE-CVSS001 | v3.1 + v3.0 + v2.0 all present → v3.1 used |
| AC-CVE-CVSS002 | Only v3.0 → v3.0 used |
| AC-CVE-CVSS003 | Only v2.0 → v2.0 used |
| AC-CVE-CVSS004 | No metrics at all → cvss=0.0, severity="unknown" |
| AC-CVE-CVSS005 | `baseSeverity` in metric level → extracted |
| AC-CVE-CVSS006 | `baseSeverity` in cvssData level (v2 format) → extracted via fallback |

### 5.4 Severity Mapping

| ID | Input | Expected |
|----|-------|----------|
| AC-CVE-SEV001 | CRITICAL | "critical" |
| AC-CVE-SEV002 | HIGH | "high" |
| AC-CVE-SEV003 | MEDIUM | "medium" |
| AC-CVE-SEV004 | LOW | "low" |
| AC-CVE-SEV005 | NONE | "info" |
| AC-CVE-SEV006 | "" (empty) | "unknown" |

### 5.5 Description & Fields

| ID | Description |
|----|-------------|
| AC-CVE-DESC001 | English description selected over other languages |
| AC-CVE-DESC002 | Description > 500 chars → truncated to 500 |
| AC-CVE-DESC003 | No English description → empty string |
| AC-CVE-DESC004 | Empty descriptions list → empty string |
| AC-CVE-PKG001 | Affected packages extracted from CPE matches |
| AC-CVE-PKG002 | `versionStartIncluding` and `versionEndExcluding` extracted |
| AC-CVE-PKG003 | Missing version range fields → empty strings |
| AC-CVE-PKG004 | CPE with < 6 parts → skipped |
| AC-CVE-PKG005 | `versionStartExcluding` and `versionEndIncluding` → currently NOT extracted (gap) |

### 5.6 Dedup & Filtering

| ID | Description |
|----|-------------|
| AC-CVE-DD001 | Duplicate CVE IDs → only first kept |
| AC-CVE-DD002 | All unique IDs → all kept |
| AC-CVE-DD003 | `--min-cvss 7.0`: scores [9.8, 7.0, 6.9] → only 9.8 and 7.0 |
| AC-CVE-DD004 | `--min-cvss 0.0` (default) → all kept |
| AC-CVE-DD005 | `--min-cvss 10.1` → zero records |

### 5.7 CVE ID Validation

| ID | Description |
|----|-------------|
| AC-CVE-ID001 | `CVE-2024-12345` → processed |
| AC-CVE-ID002 | `GHSA-xxxx-yyyy` → skipped (not CVE-) |
| AC-CVE-ID003 | Empty id → skipped |

### 5.8 Output

| ID | Description |
|----|-------------|
| AC-CVE-OUT001 | Each line is valid JSON (JSONL format) |
| AC-CVE-OUT002 | Compact separators |
| AC-CVE-OUT003 | Required fields: cve_id, severity, cvss, affected_packages, description, published |
| AC-CVE-OUT004 | Output directory auto-created |

---

## 6. build_bundle.py

### 6.1 Manifest Structure

| ID | Description |
|----|-------------|
| AC-BDL-M001 | Manifest has all required fields: version, timestamp, sigma_count, yara_count, ioc_hash_count, ioc_domain_count, ioc_ip_count, cve_count, files |
| AC-BDL-M002 | All `*_count` fields are non-negative integers |
| AC-BDL-M003 | `files` values match pattern `sha256:[0-9a-f]{64}` |
| AC-BDL-M004 | `manifest.json` itself NOT in `files` dict |
| AC-BDL-M005 | Manifest is valid JSON with 2-space indent, trailing newline |

### 6.2 Version & Timestamp

| ID | Description |
|----|-------------|
| AC-BDL-V001 | Default version matches `YYYY.MM.DD` format |
| AC-BDL-V002 | Custom `--version` used verbatim |
| AC-BDL-V003 | Timestamp matches `YYYY-MM-DDTHH:MM:SSZ` (UTC) |
| AC-BDL-V004 | Timestamp within ±60 seconds of current time |

### 6.3 Hash Correctness

| ID | Description |
|----|-------------|
| AC-BDL-H001 | SHA-256 of known content matches expected digest |
| AC-BDL-H002 | Every file in bundle has correct hash in manifest |
| AC-BDL-H003 | Files are byte-identical copies of source |

### 6.4 Count Accuracy

| ID | Description |
|----|-------------|
| AC-BDL-CNT001 | `sigma_count` = number of files in `sigma/` (recursive) |
| AC-BDL-CNT002 | `yara_count` = number of files in `yara/` (recursive) |
| AC-BDL-CNT003 | `ioc_hash_count` = non-empty lines in `ioc/hashes.txt` |
| AC-BDL-CNT004 | `ioc_domain_count` = non-empty lines in `ioc/domains.txt` |
| AC-BDL-CNT005 | `ioc_ip_count` = non-empty lines in `ioc/ips.txt` |
| AC-BDL-CNT006 | `cve_count` = non-empty lines in `cve/cves.jsonl` |
| AC-BDL-CNT007 | Missing source type → count = 0 |

### 6.5 Empty & Partial Bundles

| ID | Description |
|----|-------------|
| AC-BDL-E001 | No sources at all → empty bundle with only `manifest.json` |
| AC-BDL-E002 | Only `--sigma` → yara/ioc/cve counts = 0 |
| AC-BDL-E003 | Only `--ioc` → sigma/yara/cve counts = 0 |
| AC-BDL-E004 | Each source type individually produces correct bundle |

### 6.6 Idempotency & Cleanup

| ID | Description |
|----|-------------|
| AC-BDL-I001 | Existing output dir with stale files → completely removed before build |
| AC-BDL-I002 | Two runs with same args → identical output |
| AC-BDL-I003 | Old files from previous build never leak into new bundle |

### 6.7 Edge Cases

| ID | Description |
|----|-------------|
| AC-BDL-EDGE001 | Special characters in filenames handled correctly |
| AC-BDL-EDGE002 | Manifest paths use forward slashes, no `./` or `/` prefix, no `..` |
| AC-BDL-EDGE003 | Large bundle (500+ files) → all hashes correct |
| AC-BDL-EDGE004 | Missing source directories → no crash, count = 0 |
| AC-BDL-EDGE005 | Missing CVE file → no crash, count = 0 |
| AC-BDL-EDGE006 | Circular symlinks → potential infinite loop (document risk) |

---

## 7. GitHub Actions Workflows

### 7.1 Triggers

| ID | Description |
|----|-------------|
| AC-WF-T001 | collect-sigma: `0 2 * * *` + `workflow_dispatch` |
| AC-WF-T002 | collect-yara: `0 3 * * *` + `workflow_dispatch` |
| AC-WF-T003 | collect-ioc: `0 */4 * * *` + `workflow_dispatch` |
| AC-WF-T004 | collect-cve: `0 4 * * *` + `workflow_dispatch` |
| AC-WF-T005 | build-bundle: `workflow_run` on collect completion + `workflow_dispatch` |
| AC-WF-T006 | **FIX**: Remove `gh workflow run build-bundle.yml` from collect workflows (causes duplicate builds — **BUG B7**) |

### 7.2 Git Operations

| ID | Description |
|----|-------------|
| AC-WF-G001 | No file changes → no commit created |
| AC-WF-G002 | No commit → push skipped |
| AC-WF-G003 | **FIX**: Add `concurrency` groups to prevent push conflicts — **BUG B8** |

### 7.3 GPG Signing

| ID | Description |
|----|-------------|
| AC-WF-GPG001 | GPG private key imported from secret |
| AC-WF-GPG002 | `allow-preset-passphrase` set and agent restarted |
| AC-WF-GPG003 | Detached ASCII-armored signature created |
| AC-WF-GPG004 | Signature verified immediately after creation |
| AC-WF-GPG005 | `manifest.json.asc` included as release asset |

### 7.4 GitHub Release

| ID | Description |
|----|-------------|
| AC-WF-R001 | Tag format: `rules-YYYY.MM.DD.HHMM` |
| AC-WF-R002 | Title: `Rule Bundle YYYY.MM.DD.HHMM` |
| AC-WF-R003 | Assets: `.bundle.tar.zst` + `manifest.json.asc` |
| AC-WF-R004 | Release notes include all 6 category counts |

### 7.5 Error Handling

| ID | Description |
|----|-------------|
| AC-WF-ERR001 | All curl commands have `--retry 3 --max-time` |
| AC-WF-ERR002 | All curl commands use `-f` (fail on HTTP error) |
| AC-WF-ERR003 | OTX step conditional on `OTX_API_KEY` secret |
| AC-WF-ERR004 | GHSA query has fallback to empty JSON on failure |
| AC-WF-ERR005 | No YARA rules to validate → skip step gracefully |

### 7.6 Missing Features (from design)

| ID | Description |
|----|-------------|
| AC-WF-MISS001 | Webhook notification step (design lines 2794-2799) — deferred |
| AC-WF-MISS002 | PhishTank source — not in design section 17 either |
| AC-WF-MISS003 | GHSA ecosystem filter too narrow (PIP only) — should broaden |

---

## Summary Statistics

| Component | Happy Path | Edge Cases | Error Handling | Total ACs |
|-----------|-----------|------------|----------------|-----------|
| sigma_filter.py | 10 | 24 | 10 | 44 |
| yara_validate.py | 4 | 6 | 4+6=10 | 20 |
| ioc_dedup.py | 10+13+10+12+7+3 = 55 | (included above) | (included above) | 55 |
| ioc_allowlist.py | 8+6+6+2+5+5 = 32 | (included above) | (included above) | 32 |
| cve_extract.py | 8+9+6+6+5+3+4 = 41 | (included above) | (included above) | 41 |
| build_bundle.py | 5+4+3+7+4+3+6 = 32 | (included above) | (included above) | 32 |
| Workflows | 6+3+5+4+5+3 = 26 | (included above) | (included above) | 26 |
| **Total** | | | | **~250** |
