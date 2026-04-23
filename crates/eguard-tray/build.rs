#[cfg(target_os = "windows")]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("assets/tray.ico");
    res.set("ProductName", "Eguard ZTNA");
    res.set("FileDescription", "Eguard ZTNA Tray");
    res.set("InternalName", "Eguard ZTNA");
    res.set("OriginalFilename", "eguard-tray.exe");
    res.set("CompanyName", "eGuard");
    res.set("LegalCopyright", "eGuard");
    let _ = res.compile();
}

#[cfg(not(target_os = "windows"))]
fn main() {}
