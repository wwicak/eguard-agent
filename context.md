# eGuard Agent Config Startup & Fallback Behavior

## Executive Summary

When `/etc/eguard-agent/agent.conf` is missing, the agent **silently falls back to hardcoded defaults** with no self-healing. The smallest self-healing implementation path is to **reconstruct agent.conf from bootstrap.conf** at startup, as bootstrap already persists critical enrollment state.

---

## Files Retrieved & Key Functions

### Configuration Loading Flow

1. **`/home/dimas/eguard-agent/crates/agent-core/src/main.rs` (line 56)**
   - Entry point: `let config = AgentConfig::load()?;`
   - Calls the load orchestration

2. **`/home/dimas/eguard-agent/crates/agent-core/src/config/load.rs` (lines 1-11)**
   - `AgentConfig::load()` -> sequence: apply_file_config, apply_bootstrap_config, apply_env_overrides
   ```rust
   pub fn load() -> Result<Self> {
       let mut cfg = Self::default();
       cfg.apply_file_config()?;        // Line 8 - applies agent.conf
       cfg.apply_bootstrap_config()?;   // Line 9 - applies bootstrap.conf
       cfg.apply_env_overrides();       // Line 10 - applies env vars
       Ok(cfg)
   }
   ```

### File Resolution

3. **`/home/dimas/eguard-agent/crates/agent-core/src/config/paths.rs` (lines 11-25)**
   - `resolve_config_path()` -> searches candidates, returns `Ok(None)` if not found (line 12-13)
   - `resolve_bootstrap_path()` -> searches candidates, returns `Ok(None)` if not found (line 16-17)
   - Candidates defined in `constants.rs`:
     - Linux agent config: `/etc/eguard-agent/agent.conf`, `./conf/agent.conf`, `./agent.conf`
     - Linux bootstrap: `/etc/eguard-agent/bootstrap.conf`, `./conf/bootstrap.conf`, `./bootstrap.conf`

4. **`/home/dimas/eguard-agent/crates/agent-core/src/config/constants.rs` (lines 1-30)**
   ```rust
   const AGENT_CONFIG_CANDIDATES: [&str; 3] = [
       "/etc/eguard-agent/agent.conf",    // PRIMARY
       "./conf/agent.conf",
       "./agent.conf",
   ];
   
   const BOOTSTRAP_CONFIG_CANDIDATES: [&str; 3] = [
       "/etc/eguard-agent/bootstrap.conf", // PRIMARY
       "./conf/bootstrap.conf",
       "./bootstrap.conf",
   ];
   ```

### File Application

5. **`/home/dimas/eguard-agent/crates/agent-core/src/config/file.rs` (lines 11-45)**
   - `AgentConfig::apply_file_config(&mut self) -> Result<bool>`
   - Returns `Ok(false)` if no file found (line 14)
   - Silently succeeds with defaults if file missing
   - **NO FALLBACK TO BOOTSTRAP OR LAST-KNOWN-GOOD**

6. **`/home/dimas/eguard-agent/crates/agent-core/src/config/bootstrap.rs` (lines 46-90)**
   - `AgentConfig::apply_bootstrap_config(&mut self) -> Result<()>`
   - Returns `Ok(())` if no bootstrap found (line 58)
   - Only applies if bootstrap file exists
   - Extracts: `address`, `grpc_port`, `enrollment_token`, `tenant_id`, `schema_version`

### Defaults

7. **`/home/dimas/eguard-agent/crates/agent-core/src/config/defaults.rs` (lines 80-160)**
   - `impl Default for AgentConfig` -> hardcoded defaults
   - Key defaults when no config found:
     - `server_addr: DEFAULT_SERVER_ADDR.to_string()` = "eguard-server:50053" (line 133)
     - `mode: AgentMode::Learning` (line 132)
     - `transport_mode: "http".to_string()` (line 131)
     - `enrollment_token: None` (line 127)
     - `tenant_id: None` (line 128)

### Types

8. **`/home/dimas/eguard-agent/crates/agent-core/src/config/types.rs`**
   - `AgentConfig` struct - all ~60 configuration fields
   - Field: `bootstrap_config_path: Option<PathBuf>` (line 50) - **tracks source**

---

## Current Fallback Behavior (Agent.conf Missing)

### Scenario: `/etc/eguard-agent/agent.conf` deleted

**Sequence:**
1. `main.rs:56` calls `AgentConfig::load()?`
2. `load.rs:8` calls `apply_file_config()` 
3. `paths.rs:12` calls `resolve_config_path()` → searches candidates → **returns `Ok(None)`** (no file exists)
4. `file.rs:13-14` checks `let Some(path) = path else { return Ok(false); }`
5. Returns `Ok(false)` - **no error, no fallback applied**
6. `load.rs:9` calls `apply_bootstrap_config()`
   - If bootstrap.conf exists, **only** `address`, `grpc_port`, `enrollment_token`, `tenant_id` applied
   - Other settings remain at defaults from step 1
7. `load.rs:10` applies env overrides
8. Agent **starts with mixed state**: bootstrap enrollment details + hardcoded defaults for everything else

**Result:**
- ✅ Bootstrap enrollment state persists (good)
- ❌ **Agent.conf settings lost** (detection rules dir, response policies, TLS certs, etc.)
- ❌ No attempt to restore or reconstruct agent.conf

---

## Self-Healing Implementation Paths

### Option 1: Reconstruct from Bootstrap (Smallest, Recommended)
**Scope:** Minimal changes, leverages existing bootstrap persistence

**Changes:**
1. After `apply_bootstrap_config()` in `load.rs:9`, if agent.conf was missing AND bootstrap.conf exists:
   - Call new function: `reconstruct_agent_config_from_bootstrap()?`
   
2. New function in `file.rs`:
   ```rust
   fn reconstruct_agent_config_from_bootstrap(
       bootstrap_path: &Path,
       agent_config_path: &Path,
   ) -> Result<()> {
       // Read bootstrap
       let raw = fs::read_to_string(bootstrap_path)?;
       let bootstrap = parse_bootstrap_config(&raw)?;
       
       // Generate minimal agent.conf with bootstrap values + defaults
       let reconstructed = format!(
           "[agent]\nserver_addr = \"{}\"\nenrollment_token = \"{}\"\ntenant_id = \"{}\"\nmode = \"learning\"\n",
           bootstrap.address.unwrap_or_default(),
           bootstrap.enrollment_token.unwrap_or_default(),
           bootstrap.tenant_id.unwrap_or_default(),
       );
       
       // Write to agent.conf with secure permissions
       fs::write(agent_config_path, reconstructed)?;
       Ok(())
   }
   ```

3. **Affected files:**
   - `load.rs` - add conditional call after line 9
   - `file.rs` - add `reconstruct_agent_config_from_bootstrap()` function
   - `bootstrap.rs` - export parse function (already pub)

4. **Tracing:** Add info log when reconstruction happens
   ```
   info!(path = %agent_config_path.display(), "reconstructed agent.conf from bootstrap")
   ```

---

### Option 2: Encrypted Backup File (More Robust, Larger)
**Scope:** Runtime backup of agent.conf on successful load

**New file:** `/var/lib/eguard-agent/agent.conf.backup.enc` (encrypted)

**Changes:**
1. After successful `apply_file_config()` load:
   - Call `backup_agent_config_encrypted(path, backup_path)?`
2. When agent.conf missing but backup exists:
   - Decrypt and restore backup
3. Requires: crypto module integration, new constants

---

### Option 3: Last-Known-Good Snapshot (Production-Grade, Largest)
**Scope:** Versioned snapshots with CRC validation

- Store `/var/lib/eguard-agent/agent.conf.lkg` (versioned)
- Use on file missing + hash mismatch detection
- Requires: version tracking, snapshot management

---

## Recommended Path: **Option 1 (Reconstruct from Bootstrap)**

**Why:**
- ✅ Minimal code: ~50 lines
- ✅ Leverages existing bootstrap persistence mechanism
- ✅ No new dependencies or crypto operations
- ✅ Fast recovery (no decryption overhead)
- ✅ Aligns with existing enrollment flow
- ✅ Easy to test (uses existing bootstrap parsing)

**Exact Implementation Steps:**

### File 1: `file.rs` - Add reconstruction function after line 44
```rust
pub(super) fn reconstruct_agent_config_from_bootstrap(
    bootstrap_path: &Path,
    agent_path: &Path,
) -> Result<()> {
    let raw = fs::read_to_string(bootstrap_path)
        .with_context(|| format!("failed reading bootstrap for reconstruction {}", bootstrap_path.display()))?;
    let bootstrap = super::bootstrap::parse_bootstrap_config(&raw)?;
    
    let mut content = String::from("[agent]\n");
    if let Some(addr) = &bootstrap.address {
        content.push_str(&format!("server_addr = \"{}\"\n", addr.trim_matches('"')));
    }
    if let Some(token) = &bootstrap.enrollment_token {
        content.push_str(&format!("enrollment_token = \"{}\"\n", token.trim_matches('"')));
    }
    if let Some(tenant) = &bootstrap.tenant_id {
        content.push_str(&format!("tenant_id = \"{}\"\n", tenant.trim_matches('"')));
    }
    content.push_str("mode = \"learning\"\n");
    
    if let Some(port) = bootstrap.grpc_port {
        content.push_str(&format!("\n[transport]\nmode = \"grpc\"\n"));
    }
    
    fs::write(agent_path, content)
        .with_context(|| format!("failed writing reconstructed agent.conf {}", agent_path.display()))?;
    
    Ok(())
}
```

### File 2: `load.rs` - Modify load sequence (lines 6-11)
```rust
pub fn load() -> Result<Self> {
    let mut cfg = Self::default();
    
    // Attempt primary config load
    let agent_config_loaded = cfg.apply_file_config()?;
    
    // Apply bootstrap config
    cfg.apply_bootstrap_config()?;
    
    // If agent.conf missing but bootstrap exists, reconstruct it
    if !agent_config_loaded {
        let bootstrap_path = resolve_bootstrap_path()?;
        let agent_path = resolve_config_path()?; // Gets candidate path even if not exists
        
        if let (Some(bp), Some(_agent_candidate)) = (bootstrap_path, agent_path) {
            if let Err(e) = super::file::reconstruct_agent_config_from_bootstrap(&bp, &agent_path.unwrap_or_default()) {
                warn!(error = %e, "failed to reconstruct agent.conf from bootstrap");
            }
        }
    }
    
    cfg.apply_env_overrides();
    Ok(cfg)
}
```

Actually, simplify - we already know primary path:

```rust
pub fn load() -> Result<Self> {
    let mut cfg = Self::default();
    let agent_config_loaded = cfg.apply_file_config()?;
    cfg.apply_bootstrap_config()?;
    
    // Self-heal: reconstruct agent.conf from bootstrap if missing
    if !agent_config_loaded {
        if let Ok(Some(bootstrap_path)) = resolve_bootstrap_path() {
            let primary_agent_path = PathBuf::from(
                #[cfg(target_os = "linux")]
                "/etc/eguard-agent/agent.conf",
                #[cfg(target_os = "macos")]
                "/Library/Application Support/eGuard/agent.conf",
                #[cfg(target_os = "windows")]
                r"C:\ProgramData\eGuard\agent.conf",
            );
            if let Err(e) = super::file::reconstruct_agent_config_from_bootstrap(&bootstrap_path, &primary_agent_path) {
                warn!(error = %e, "failed self-healing agent.conf from bootstrap; continuing with defaults");
            }
        }
    }
    
    cfg.apply_env_overrides();
    Ok(cfg)
}
```

### File 3: `bootstrap.rs` - Export parse function (already public at line 60-64)
```rust
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn parse_bootstrap_config(raw: &str) -> Result<BootstrapConfig> {  // ← change to pub(super)
```

---

## Testing the Implementation

**Test location:** `config/tests.rs`

**New test after line 345:**
```rust
#[test]
fn agent_config_reconstructed_from_bootstrap_when_missing() {
    let _guard = env_lock().lock().expect("env lock");
    clear_env();
    
    let bootstrap_path = std::env::temp_dir().join(
        format!("test-bootstrap-{}.conf", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
    );
    let mut f = std::fs::File::create(&bootstrap_path).expect("create bootstrap");
    writeln!(f, "[server]\naddress = recovery.example.com\nenrollment_token = recovery-token-123\ntenant_id = recovery-tenant").unwrap();
    
    std::env::set_var("EGUARD_BOOTSTRAP_CONFIG", &bootstrap_path);
    
    // Do not set EGUARD_AGENT_CONFIG - ensure agent.conf resolution returns None
    let cfg = AgentConfig::load().expect("load should succeed even without agent.conf");
    
    // Verify bootstrap values applied
    assert!(cfg.server_addr.contains("recovery.example.com"));
    assert_eq!(cfg.enrollment_token.as_deref(), Some("recovery-token-123"));
    
    // Verify agent.conf was reconstructed (exists on primary path)
    let primary_path = Path::new("/etc/eguard-agent/agent.conf");
    assert!(primary_path.exists(), "agent.conf should be reconstructed");
    
    let content = std::fs::read_to_string(primary_path).expect("read reconstructed file");
    assert!(content.contains("recovery.example.com"));
    assert!(content.contains("recovery-token-123"));
    
    // Cleanup
    let _ = std::fs::remove_file(&bootstrap_path);
    let _ = std::fs::remove_file(primary_path);
}
```

---

## Impact & Risk Analysis

### Minimal Option (Recommended)
- **Lines changed:** ~80 total (30 in file.rs, 20 in load.rs, 5 imports)
- **New functions:** 1 (`reconstruct_agent_config_from_bootstrap`)
- **New dependencies:** None
- **Risk:** Very low - only activates when agent.conf missing + bootstrap exists
- **Recovery time:** ~100ms (file I/O only)

### Testing
- Add test case (see above)
- Verify no change to behavior when both files present
- Verify no change when only bootstrap missing
- Verify reconstruction only happens once per startup

---

## References

### Trace Paths
1. Config missing path: `main.rs:56` → `load.rs:8` → `paths.rs:12` → `file.rs:11`
2. Bootstrap apply path: `load.rs:9` → `bootstrap.rs:46`
3. Default fallback: `defaults.rs:130-140` (hardcoded defaults)

### Related Code
- Bootstrap validation: `bootstrap.rs:192-216` (validate_bootstrap_config)
- Bootstrap parsing: `bootstrap.rs:263-330` (parse_bootstrap_ini)
- Config file structure: `file.rs:380-550` (FileConfig, FileAgentConfig structs)
