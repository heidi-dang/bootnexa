//! BootNexa read-only Windows safety probe.
//! This is NOT an elevated process or a device writer; no physical disk
//! handles are opened, no target can be supplied and no approvals are issued.
use bootnexa_agent::safety::SafetyReport;
#[cfg(windows)]
use bootnexa_agent::safety::assess_snapshots;
#[cfg(windows)]
use bootnexa_agent::safety::capture_windows;

#[cfg(windows)]
async fn run() -> Result<SafetyReport, &'static str> {
    let before = capture_windows()
        .await
        .map_err(|_| "Windows snapshot unavailable")?;
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let after = capture_windows()
        .await
        .map_err(|_| "Windows snapshot unavailable")?;
    Ok(assess_snapshots(&before, &after))
}
#[cfg(not(windows))]
async fn run() -> Result<SafetyReport, &'static str> {
    Err("Windows read-only probe unavailable on this operating system")
}
#[tokio::main]
async fn main() {
    if std::env::args().len() != 2 || std::env::args().nth(1).as_deref() != Some("--probe") {
        eprintln!(
            "usage: bootnexa-safety-probe --probe (Windows only; read-only; no device selection)"
        );
        std::process::exit(2);
    }
    let result = run().await;
    match result {
        Ok(report) => println!(
            "{}",
            serde_json::to_string(&report).expect("report serializable")
        ),
        Err(message) => {
            // Never output raw provider errors, serials, PnP paths or secrets.
            eprintln!("{message}");
            std::process::exit(1)
        }
    }
}
