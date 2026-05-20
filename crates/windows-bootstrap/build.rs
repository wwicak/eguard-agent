#[cfg(target_os = "windows")]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("../eguard-tray/assets/tray.ico");
    res.set("ProductName", "eGuard Setup");
    res.set("FileDescription", "eGuard Endpoint Installer Bootstrap");
    res.set("InternalName", "eGuard Setup");
    res.set("OriginalFilename", "eguard-setup.exe");
    res.set("CompanyName", "eGuard");
    res.set("LegalCopyright", "eGuard");
    let _ = res.set_manifest_file("../../installer/windows/assets/eguard-setup.manifest");
    let _ = res.compile();
}

#[cfg(not(target_os = "windows"))]
fn main() {}
