//! Authoritative developer-only read-only safety report, shared by the
//! command-line probe and local authenticated diagnostic IPC service.
#[cfg(windows)]
use crate::{
    native_ancestry::{NativeAncestryReport, assess_native, capture_native},
    protected_ancestry::{ProtectionReport, assess_protection},
    safety::{SafetyReport, assess_snapshots, capture_windows},
};
#[cfg(windows)]
use serde::Serialize;

#[cfg(windows)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadOnlyReport {
    #[serde(flatten)]
    pub safety: SafetyReport,
    pub native_ancestry: NativeAncestryReport,
    pub protected_ancestry: ProtectionReport,
}
#[cfg(windows)]
pub async fn collect() -> Result<ReadOnlyReport, &'static str> {
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
    let protection = assess_protection(&first, &second, &native_first, &native_second);
    let mut safety = assess_snapshots(&first, &second);
    if !native.native_ancestry_complete {
        for f in &mut safety.findings {
            f.identity_stable_between_samples = false;
            f.risk_codes.push("native_ancestry_not_authoritative");
        }
    }
    Ok(ReadOnlyReport {
        safety,
        native_ancestry: native,
        protected_ancestry: protection,
    })
}
