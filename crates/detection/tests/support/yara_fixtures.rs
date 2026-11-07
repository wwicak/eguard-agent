pub fn pe(size: usize, offset: usize, pe32: bool) -> Vec<u8> {
    let mut bytes = vec![0; size.max(offset + 512)];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&(offset as u32).to_le_bytes());
    bytes[offset..offset + 4].copy_from_slice(b"PE\0\0");
    bytes[offset + 4..offset + 6]
        .copy_from_slice(&(if pe32 { 0x14cu16 } else { 0x8664u16 }).to_le_bytes());
    bytes[offset + 6..offset + 8].copy_from_slice(&1u16.to_le_bytes());
    bytes[offset + 20..offset + 22]
        .copy_from_slice(&(if pe32 { 224u16 } else { 240u16 }).to_le_bytes());
    bytes[offset + 22..offset + 24].copy_from_slice(&0x2022u16.to_le_bytes());
    bytes[offset + 24..offset + 26]
        .copy_from_slice(&(if pe32 { 0x10bu16 } else { 0x20bu16 }).to_le_bytes());
    bytes
}
fn hex(value: &str) -> Vec<u8> {
    value
        .split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}
fn wide(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
pub fn cases() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    let mut cases = Vec::new();
    let mut linux =
        b"\x7fELF\0find_applet_by_name\0bb_basename\0hk_printf_chk\0runCommand\0initialize\0"
            .to_vec();
    let mut negative = linux.clone();
    negative[linux
        .windows(13)
        .position(|s| s == b"hk_printf_chk")
        .unwrap()] = b'X';
    cases.push((
        "APT_Trojan_Linux_REDFLARE_1",
        std::mem::take(&mut linux),
        negative,
    ));
    let mut pgf = pe(1024, 512, false);
    let rich=hex("A8 B7 17 3A EC D6 79 69 EC D6 79 69 EC D6 79 69 2F D9 24 69 E8 D6 79 69 E5 AE EC 69 EA D6 79 69 EC D6 78 69 A8 D6 79 69 E5 AE EA 69 EF D6 79 69 E5 AE FA 69 D0 D6 79 69 E5 AE EB 69 ED D6 79 69 E5 AE FD 69 E2 D6 79 69 CB 10 07 69 ED D6 79 69 E5 AE E8 69 ED D6 79 69");
    pgf[128..128 + rich.len()].copy_from_slice(&rich);
    let mut negative = pgf.clone();
    negative[128] ^= 1;
    cases.push(("APT_Loader_Win_PGF_2", pgf, negative));
    let mut dshell = pe(1024, 512, true);
    dshell.extend(hex("6A 40 68 00 30 00 00 00 00 00 00 E8 00 00 00 00 50 E8 00 00 00 00 6A FF 00 6A 00 6A 00 50 6A 00 6A 00 E8 00 00 00 00 50"));
    dshell.extend(hex("FF 70 0C B0 00 00 00 00 FF 70 08 50 E8 00 00 00 00 84 C0 74 05 B0 01 00 00 00 80 F2 01 0F 84"));
    dshell.extend(b"\0CreateThread\0base64.d\0core.sys.windows\0");
    let negative = dshell[..dshell.len() - 17].to_vec();
    cases.push(("APT_Loader_Win32_DShell_1", dshell, negative));
    let mut silk = pe(1024, 128, false);
    silk.extend(wide("TRANSFER"));
    let negative = silk.clone();
    silk.extend(wide("vbccsb"));
    cases.push(("SILKLOADER", silk, negative));
    let mut tangle = pe(1024, 128, false);
    tangle.extend(b"Can't call WinAPI function\0");
    for _ in 0..50 {
        tangle.extend(hex("41 B8 D7 08 00 00 E8"));
    }
    let negative = tangle.clone();
    tangle.extend(hex("41 B8 D7 08 00 00 E8"));
    cases.push(("tanglecrypt", tangle, negative));
    let under=hex("C0 74 6F 4C 8B DE 49 8D 1C 02 4D 2B 5D 30 4C 3B D3 73 5F BF 00 F0 00 00 41 BE 00 A0 00 00 41 83 3A 00 74 4E 45 8B 42 04 4D 8D 4A 08 49 83 E8 08 49 D1 E8 45 85 C0 74 2E 90 41 0F B7 11 41 FF C8");
    let mut negative = under.clone();
    negative[0] ^= 1;
    cases.push(("Andariel_UnderCrypt", under, negative));
    let mut star = pe(1024, 128, false);
    star.extend(b"StarShell\0ReadRlt\0");
    let negative = star.clone();
    star.extend(b"SendRlt\0");
    cases.push(("Andariel_StarShellRAT", star, negative));
    let mut gopher = pe(1024, 128, false);
    let negative = gopher.clone();
    gopher.extend(hex("35 70 95 A2 21 F0 33 AC"));
    cases.push(("Andariel_GopherRAT", gopher, negative));
    let mut jelus = pe(1024, 128, false);
    let negative = jelus.clone();
    jelus.extend(b"jelus rat project.pdb\0");
    cases.push(("Andariel_JelusRAT_PDB", jelus, negative));
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec();
    let mut negative = eicar.clone();
    negative.resize(129, 0);
    cases.push(("eguard_eicar_test_file", eicar, negative));
    cases
}
