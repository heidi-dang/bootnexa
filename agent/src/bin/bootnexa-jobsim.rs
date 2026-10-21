//! Operator-facing Phase 4 test simulator. Never opens a physical disk.
use bootnexa_agent::journal::{JobRequest, JobStore, Phase};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use uuid::Uuid;

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 3 {
        return Err("usage: bootnexa-jobsim demo|crash-fixture|recover|inspect|events|cancel <sqlite-path> [job-id] [cursor]".into());
    }
    let operation = args[1].as_str();
    let store = JobStore::open(&args[2])?;
    match operation {
        "demo" | "crash-fixture" => {
            // Each invocation uses an independent synthetic target fingerprint.
            // A demo creates NO file images, device handles, or write operations.
            let nonce = Uuid::new_v4().to_string();
            let job = store.create(&JobRequest {
                idempotency_key: format!("demo:{nonce}"),
                source_sha256: digest("BootNexa synthetic image fixture"),
                simulated_target: digest(&format!("mock-target:{nonce}")),
                expected_bytes: 4 * 1024,
            })?;
            for phase in [
                Phase::Preflighted,
                Phase::WaitingForConsent,
                Phase::Locking,
                Phase::Preparing,
                Phase::Writing,
            ] {
                store.advance(&job.id, phase)?;
            }
            store.progress(&job.id, 2048, &digest("synthetic bytes:2048"))?;
            if operation == "crash-fixture" {
                println!(
                    "{}",
                    json!({"simulationOnly":true,"jobId":job.id,
                    "phase":"WRITING","result":"pending_restart_recovery","bytes":2048})
                );
                return Ok(());
            }
            store.progress(&job.id, 4096, &digest("synthetic bytes:4096"))?;
            store.advance(&job.id, Phase::Flushing)?;
            store.simulate_flush(&job.id)?;
            store.advance(&job.id, Phase::Verifying)?;
            store.simulate_verify(&job.id, 4096)?;
            let done = store.advance(&job.id, Phase::SimulatedSucceeded)?;
            println!(
                "{}",
                json!({"simulationOnly":true,"jobId":done.id,
                "phase":done.phase.as_str(),"bytes":done.completed_bytes,
                "verifiedBytes":done.verified_bytes,"flushSimulated":done.flush_recorded,
                "result":"no_physical_media_access"})
            );
        }
        "recover" => {
            println!(
                "{}",
                json!({"simulationOnly":true,"interrupted":store.recover_interrupted()?})
            );
        }
        "inspect" => {
            let id = args.get(3).ok_or("inspect requires job-id")?;
            let job = store.get(id)?;
            println!(
                "{}",
                json!({"simulationOnly":true,"jobId":job.id,
                "phase":job.phase.as_str(),"sourceSha256":job.source_sha256,
                "simulatedTarget":job.simulated_target,"expectedBytes":job.expected_bytes,
                "completedBytes":job.completed_bytes,"verifiedBytes":job.verified_bytes,
                "flushSimulated":job.flush_recorded,"failureCode":job.failure_code})
            );
        }
        "events" => {
            let id = args.get(3).ok_or("events requires job-id")?;
            let cursor: i64 = args.get(4).map(|s| s.parse()).transpose()?.unwrap_or(0);
            let events = store.events_after(id, cursor, 100)?;
            let entries = events
                .iter()
                .map(|entry| {
                    json!({"sequence":entry.sequence,
                "phase":entry.phase.as_str(),"bytes":entry.completed_bytes,
                "verifiedBytes":entry.verified_bytes,"code":entry.code,"atMs":entry.at_ms})
                })
                .collect::<Vec<_>>();
            println!(
                "{}",
                json!({"simulationOnly":true,"jobId":id,"events":entries,
                "nextCursor":events.last().map(|e|e.sequence).unwrap_or(cursor)})
            );
        }
        "cancel" => {
            let id = args.get(3).ok_or("cancel requires job-id")?;
            let job = store.cancel(id)?;
            println!(
                "{}",
                json!({"simulationOnly":true,"jobId":job.id,"phase":job.phase.as_str()})
            );
        }
        _ => return Err("unknown simulation command".into()),
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("BootNexa simulation failed: {error}");
        std::process::exit(1);
    }
}
