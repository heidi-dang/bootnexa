// Windows VERSIONINFO is required for consistent product identity in releases.
// The MSVC resource compiler is supplied by the Windows build runner.
#[cfg(windows)]
fn main() {
    let pkg_version = env!("CARGO_PKG_VERSION");
    let mut resource = winres::WindowsResource::new();
    resource.set("ProductName", "BootNexa Agent");
    resource.set("FileDescription", "BootNexa read-only USB device companion");
    resource.set("CompanyName", "BootNexa");
    resource.set("LegalCopyright", "Copyright (c) 2026 BootNexa contributors");
    resource.set("OriginalFilename", "bootnexa-agent.exe");
    resource.set("InternalName", "bootnexa-agent");
    resource.set_icon("../packaging/windows/bootnexa.ico");
    resource.set("ProductVersion", pkg_version);
    resource.set("FileVersion", pkg_version);
    resource.set_version_info(
        winres::VersionInfo::PRODUCTVERSION,
        version_quad(pkg_version),
    );
    resource.set_version_info(winres::VersionInfo::FILEVERSION, version_quad(pkg_version));
    resource
        .compile()
        .expect("failed to embed Windows version metadata");
}

#[cfg(windows)]
fn version_quad(raw: &str) -> u64 {
    let mut components = raw.split('.');
    let major: u64 = components
        .next()
        .expect("major")
        .parse()
        .expect("major numeric");
    let minor: u64 = components
        .next()
        .expect("minor")
        .parse()
        .expect("minor numeric");
    let patch: u64 = components
        .next()
        .expect("patch")
        .parse()
        .expect("patch numeric");
    assert!(major <= u16::MAX as u64 && minor <= u16::MAX as u64 && patch <= u16::MAX as u64);
    (major << 48) | (minor << 32) | (patch << 16)
}

#[cfg(not(windows))]
fn main() {}
