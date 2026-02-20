//! LaunchDaemon plist generation.

const DEFAULT_LABEL: &str = "com.eguard.agent";
const DEFAULT_BINARY_PATH: &str = "/usr/local/bin/eguard-agent";
const DEFAULT_PLIST_PATH: &str = "/Library/LaunchDaemons/com.eguard.agent.plist";

/// Escape a string for safe interpolation into XML `<string>` elements.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Generate a LaunchDaemon plist XML string.
pub fn generate_plist(label: &str, binary_path: &str) -> String {
    let label = xml_escape(label);
    let binary_path = xml_escape(binary_path);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/eguard-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/eguard-agent.err</string>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>ThrottleInterval</key>
    <integer>5</integer>
</dict>
</plist>
"#
    )
}

/// Generate a plist with default settings.
pub fn generate_default_plist() -> String {
    generate_plist(DEFAULT_LABEL, DEFAULT_BINARY_PATH)
}

/// Default plist installation path.
pub fn default_plist_path() -> &'static str {
    DEFAULT_PLIST_PATH
}

#[cfg(test)]
mod tests {
    use super::{generate_plist, DEFAULT_LABEL};

    #[test]
    fn generated_plist_contains_label() {
        let plist = generate_plist(DEFAULT_LABEL, "/usr/local/bin/eguard-agent");
        assert!(plist.contains("<string>com.eguard.agent</string>"));
        assert!(plist.contains("<string>/usr/local/bin/eguard-agent</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
    }

    #[test]
    fn generated_plist_is_valid_xml_header() {
        let plist = generate_plist("test.label", "/bin/test");
        assert!(plist.starts_with("<?xml version=\"1.0\""));
        assert!(plist.contains("<!DOCTYPE plist"));
    }

    #[test]
    fn xml_special_chars_are_escaped() {
        let plist = generate_plist("com.<evil>&'\"", "/bin/<script>");
        assert!(plist.contains("com.&lt;evil&gt;&amp;&apos;&quot;"));
        assert!(plist.contains("/bin/&lt;script&gt;"));
        assert!(!plist.contains("<evil>"));
        assert!(!plist.contains("<script>"));
    }
}
