#![cfg(feature = "yara-x")]
use detection::YaraEngine;
fn check(strings: &str, condition: &str, yes: &[u8], no: &[u8]) {
    let src = format!(
        "rule fixture {{ {} condition: {condition} }}",
        if strings.is_empty() {
            String::new()
        } else {
            format!("strings: {strings}")
        }
    );
    let mut engine = YaraEngine::new();
    engine.load_rules_str(&src).unwrap();
    assert!(!engine.scan_bytes("yes", yes).is_empty());
    assert!(engine.scan_bytes("no", no).is_empty());
}
#[test]
fn semantics_any() {
    check(
        "$a = \"alpha\" $b = \"beta\"",
        "any of them",
        b"beta",
        b"gamma",
    );
}
#[test]
fn semantics_hex() {
    check("$a = { 41 42 ?? 44 }", "$a", b"ABCD", b"ABCE");
}
#[test]
fn semantics_regex() {
    check("$a = /ab[0-9]{2}z/", "$a", b"ab42z", b"abxxz");
}
#[test]
fn semantics_uint16() {
    check("", "uint16(0) == 0x5A4D", b"MZxx", b"ZMxx");
}
#[test]
fn semantics_filesize() {
    check("$a = \"tag\"", "$a and filesize == 3", b"tag", b"tagx");
}
#[test]
fn semantics_wide_nocase() {
    check("$a = \"AB\" wide nocase", "$a", b"a\0b\0", b"ab");
}
#[test]
fn semantics_counts() {
    check("$a = \"ab\"", "#a == 2", b"abab", b"ab");
}
#[test]
fn semantics_pe_module() {
    let mut pe = vec![0; 1024];
    pe[..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&128u32.to_le_bytes());
    pe[128..132].copy_from_slice(b"PE\0\0");
    pe[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[134..136].copy_from_slice(&1u16.to_le_bytes());
    pe[148..150].copy_from_slice(&240u16.to_le_bytes());
    pe[150..152].copy_from_slice(&0x2022u16.to_le_bytes());
    pe[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
    let mut engine = YaraEngine::new();
    engine
        .load_rules_str(
            "import \"pe\" rule fixture { condition: pe.is_pe and pe.characteristics & pe.DLL }",
        )
        .unwrap();
    assert!(!engine.scan_bytes("yes", &pe).is_empty());
    assert!(engine.scan_bytes("no", b"MZ not a real PE").is_empty());
}
