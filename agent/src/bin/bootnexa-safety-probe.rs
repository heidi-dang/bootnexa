//! BootNexa read-only Windows safety probe.
//! This is NOT an elevated process or a device writer; no physical disk
//! handles are opened, no target can be supplied and no approvals are issued.
use bootnexa_agent::safety::SafetyReport;
#[cfg(windows)]
use bootnexa_agent::{
    native_ancestry::{NativeAncestryReport, assess_native, capture_native},
    safety::{assess_snapshots, capture_windows},
};
use serde::Serialize;
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    #[serde(flatten)]
    safety: SafetyReport,
    #[cfg(windows)]
    native_ancestry: NativeAncestryReport,
}
#[cfg(windows)]
async fn run() -> Result<Report, &'static str> {
    let first = capture_windows()
        .await
        .map_err(|_| "Windows snapshot unavailable")?;
    let native_first = capture_native();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let second = capture_windows()
        .await
        .map_err(|_| "Windows snapshot unavailable")?;
    let native_second = capture_native();
    let disks = first.disks.iter().map(|d| d.number).collect();
    let native = assess_native(&disks, &native_first, &native_second);
    let mut safety = assess_snapshots(&first, &second);
    // Native ancestry is essential to reliable status; an incomplete or
    // changing native observation invalidates a "stable" safety finding.
    if !native.native_ancestry_complete {
        for finding in &mut safety.findings {
            finding.identity_stable_between_samples = false;
            finding.risk_codes.push("native_ancestry_not_authoritative");
        }
    }
    Ok(Report {
        safety,
        native_ancestry: native,
    })
}
#[cfg(not(windows))]
async fn run() -> Result<Report, &'static str> {
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
