//! Real subprocess acceptance on Windows and Linux. No physical USB access.
use serde_json::Value;
use std::{path::Path, process::Command};
fn invoke(db: &Path, command: &str, extra: &[&str]) -> Value {
    let mut proc = Command::new(env!("CARGO_BIN_EXE_bootnexa-jobsim"));
    proc.arg(command).arg(db).args(extra);
    let output = proc.output().expect("simulation executable starts");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid json")
}
#[test]
fn durable_simulated_success_replayed_in_separate_process() {
    let folder = tempfile::tempdir().unwrap();
    let db = folder.path().join("jobs.sqlite");
    let run = invoke(&db, "demo", &[]);
    assert_eq!(run["simulationOnly"], true);
    assert_eq!(run["phase"], "SIMULATED_SUCCEEDED");
    assert_eq!(run["result"], "no_physical_media_access");
    assert_eq!(run["flushSimulated"], true);
    assert_eq!(run["bytes"], 4096);
    assert_eq!(run["verifiedBytes"], 4096);
    let id = run["jobId"].as_str().unwrap();
    let snapshot = invoke(&db, "inspect", &[id]);
    assert_eq!(snapshot["phase"], "SIMULATED_SUCCEEDED");
    let events = invoke(&db, "events", &[id, "0"]);
    let items = events["events"].as_array().unwrap();
    assert!(items.len() >= 10);
    assert_eq!(items.last().unwrap()["phase"], "SIMULATED_SUCCEEDED");
    let cursor = items[5]["sequence"].as_i64().unwrap();
    let replay = invoke(&db, "events", &[id, &cursor.to_string()]);
    assert!(replay["events"][0]["sequence"].as_i64().unwrap() > cursor);
    assert_eq!(invoke(&db, "recover", &[])["interrupted"], 0);
}
#[test]
fn restart_and_cancellation_never_report_physical_success() {
    let folder = tempfile::tempdir().unwrap();
    let db = folder.path().join("crash.sqlite");
    let run = invoke(&db, "crash-fixture", &[]);
    let id = run["jobId"].as_str().unwrap();
    assert_eq!(invoke(&db, "inspect", &[id])["phase"], "WRITING");
    assert_eq!(invoke(&db, "recover", &[])["interrupted"], 1);
    assert_eq!(invoke(&db, "inspect", &[id])["phase"], "INTERRUPTED");
    assert_eq!(
        invoke(&db, "inspect", &[id])["failureCode"],
        "agent_restart"
    );
    assert_eq!(invoke(&db, "recover", &[])["interrupted"], 0);
    let next = invoke(&db, "crash-fixture", &[]);
    let pending = next["jobId"].as_str().unwrap();
    let cancel = invoke(&db, "cancel", &[pending]);
    assert_eq!(cancel["phase"], "CANCELLED");
    assert_eq!(invoke(&db, "recover", &[])["interrupted"], 0);
    let events = invoke(&db, "events", &[pending, "0"]);
    assert!(
        !events["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["phase"] == "SIMULATED_SUCCEEDED")
    );
}

#[test]
fn virtual_cli_reports_full_readback_and_failed_corruption_on_disk() {
    let folder = tempfile::tempdir().unwrap();
    let db = folder.path().join("virtual-cli.sqlite");
    let result = invoke(&db, "virtual-demo", &["524288"]);
    assert_eq!(result["phase"], "SIMULATED_SUCCEEDED");
    assert_eq!(result["physicalWrite"], false);
    assert_eq!(result["readbackSha256"], result["sourceSha256"]);
    assert_eq!(result["verifiedBytes"], 524288);
    assert!(result["maxBufferBytes"].as_u64().unwrap() <= 131072);
    let failed = invoke(&db, "virtual-corrupt", &["262144"]);
    assert_eq!(failed["phase"], "FAILED");
    assert_eq!(failed["physicalWrite"], false);
    let detached = invoke(&db, "virtual-unplug", &["262144"]);
    assert_eq!(detached["phase"], "FAILED");
    assert_eq!(detached["failureCode"], "device_disconnected");
    let cancelled = invoke(&db, "virtual-cancel", &["262144"]);
    assert_eq!(cancelled["phase"], "CANCELLED");
    assert_eq!(invoke(&db, "recover", &[])["interrupted"], 0);
}
