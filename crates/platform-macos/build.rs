fn main() {
    println!("cargo:rerun-if-env-changed=EGUARD_AGENT_EXPECTED_SHA256");

    if let Ok(value) = std::env::var("EGUARD_AGENT_EXPECTED_SHA256") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            println!("cargo:rustc-env=EGUARD_AGENT_EMBEDDED_SHA256={trimmed}");
        }
    }
}
