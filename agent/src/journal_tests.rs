use crate::journal::{Failure, JobRequest, JobStore, JournalError, Phase};
use std::sync::{Arc, Barrier};
use tempfile::tempdir;

fn request(key: &str, target_char: char, bytes: u64) -> JobRequest {
    JobRequest {
        idempotency_key: key.to_string(),
        source_sha256: "a".repeat(64),
        simulated_target: target_char.to_string().repeat(64),
        expected_bytes: bytes,
    }
}
fn store() -> (tempfile::TempDir, JobStore) {
    let dir = tempdir().unwrap();
    let store = JobStore::open(dir.path().join("jobs.sqlite")).unwrap();
    (dir, store)
}
fn reach(store: &JobStore, id: &str, phase: Phase) {
    for next in [
        Phase::Preflighted,
        Phase::WaitingForConsent,
        Phase::Locking,
        Phase::Preparing,
        Phase::Writing,
        Phase::Flushing,
        Phase::Verifying,
    ] {
        if store.get(id).unwrap().phase == phase {
            return;
        }
        // Reaching FLUSHING requires complete progress; reaching VERIFYING
        // requires recording simulated flush evidence.
        if next == Phase::Flushing && phase != Phase::Writing {
            store.progress(id, 4096, &"b".repeat(64)).unwrap();
        }
        if next == Phase::Verifying {
            store.simulate_flush(id).unwrap();
        }
        store.advance(id, next).unwrap();
        if next == phase {
            return;
        }
    }
    panic!("phase not reachable");
}

#[test]
fn schema_and_create_are_durable_and_idempotent() {
    let (dir, store) = store();
    let req = request("request.00000001", 'b', 4096);
    let first = store.create(&req).unwrap();
    assert_eq!(first.phase, Phase::Created);
    assert_eq!(store.create(&req).unwrap().id, first.id);
    assert_eq!(store.events_after(&first.id, 0, 100).unwrap().len(), 1);
    let reopened = JobStore::open(dir.path().join("jobs.sqlite")).unwrap();
    assert_eq!(
        reopened.get(&first.id).unwrap().source_sha256,
        req.source_sha256
    );
    let mut changed = req.clone();
    changed.expected_bytes = 8192;
    assert!(matches!(
        reopened.create(&changed),
        Err(JournalError::IdempotencyConflict)
    ));
    assert_eq!(reopened.events_after(&first.id, 0, 100).unwrap().len(), 1);
}

#[test]
fn negative_inputs_and_cursors_are_rejected() {
    let (_dir, store) = store();
    let mut invalid = request("too", 'b', 4096);
    assert!(matches!(
        store.create(&invalid),
        Err(JournalError::InvalidRequest)
    ));
    invalid.idempotency_key = "valid-idempotency".into();
    invalid.source_sha256 = "not-sha".into();
    assert!(matches!(
        store.create(&invalid),
        Err(JournalError::InvalidRequest)
    ));
    invalid.source_sha256 = "a".repeat(64);
    invalid.simulated_target = "raw-drive-path".into();
    assert!(matches!(
        store.create(&invalid),
        Err(JournalError::InvalidRequest)
    ));
    invalid.simulated_target = "b".repeat(64);
    invalid.expected_bytes = u64::MAX;
    assert!(matches!(
        store.create(&invalid),
        Err(JournalError::InvalidRequest)
    ));
    let j = store.create(&request("valid-key00001", 'b', 4096)).unwrap();
    for (cursor, limit) in [(-1, 10), (0, 0), (0, 101)] {
        assert!(matches!(
            store.events_after(&j.id, cursor, limit),
            Err(JournalError::InvalidCursor)
        ));
    }
    assert!(matches!(store.get("missing"), Err(JournalError::NotFound)));
}

#[test]
fn transaction_and_phase_order_enforced() {
    let (_dir, store) = store();
    let j = store
        .create(&request("phase.000000001", 'b', 4096))
        .unwrap();
    assert!(matches!(
        store.advance(&j.id, Phase::Writing),
        Err(JournalError::InvalidTransition)
    ));
    assert!(matches!(
        store.advance(&j.id, Phase::SimulatedSucceeded),
        Err(JournalError::InvalidTransition)
    ));
    assert_eq!(store.events_after(&j.id, 0, 100).unwrap().len(), 1);
    reach(&store, &j.id, Phase::Writing);
    assert!(matches!(
        store.advance(&j.id, Phase::Flushing),
        Err(JournalError::InvalidEvidence)
    ));
    assert!(matches!(
        store.progress(&j.id, 4097, &"b".repeat(64)),
        Err(JournalError::InvalidEvidence)
    ));
    assert!(matches!(
        store.progress(&j.id, 3, "fake"),
        Err(JournalError::InvalidEvidence)
    ));
    store.progress(&j.id, 2048, &"c".repeat(64)).unwrap();
    assert!(matches!(
        store.progress(&j.id, 100, &"c".repeat(64)),
        Err(JournalError::InvalidEvidence)
    ));
    assert!(matches!(
        store.progress(&j.id, 2048, &"d".repeat(64)),
        Err(JournalError::InvalidEvidence)
    ));
    store.progress(&j.id, 2048, &"c".repeat(64)).unwrap();
    store.progress(&j.id, 4096, &"e".repeat(64)).unwrap();
    let before = store.events_after(&j.id, 0, 100).unwrap();
    assert_eq!(
        before
            .iter()
            .filter(|e| e.code.is_none() && e.completed_bytes == 2048)
            .count(),
        1
    );
    store.advance(&j.id, Phase::Flushing).unwrap();
    assert!(matches!(
        store.advance(&j.id, Phase::Verifying),
        Err(JournalError::InvalidEvidence)
    ));
    store.simulate_flush(&j.id).unwrap();
    store.simulate_flush(&j.id).unwrap();
    store.advance(&j.id, Phase::Verifying).unwrap();
    assert!(matches!(
        store.advance(&j.id, Phase::SimulatedSucceeded),
        Err(JournalError::InvalidEvidence)
    ));
    store.simulate_verify(&j.id, 4096).unwrap();
    let final_job = store.advance(&j.id, Phase::SimulatedSucceeded).unwrap();
    assert_eq!(final_job.phase, Phase::SimulatedSucceeded);
    assert!(final_job.flush_recorded && final_job.verified_bytes == 4096);
    assert!(matches!(
        store.cancel(&j.id),
        Err(JournalError::InvalidTransition)
    ));
    assert!(matches!(
        store.progress(&j.id, 4096, &"e".repeat(64)),
        Err(JournalError::InvalidEvidence)
    ));
    assert!(matches!(
        store.advance(&j.id, Phase::SimulatedSucceeded),
        Err(JournalError::InvalidTransition)
    ));
}

#[test]
fn cursor_replay_and_monotonic_global_events_survive_restart() {
    let (dir, store) = store();
    let j1 = store.create(&request("cursor-000001", 'b', 4096)).unwrap();
    let j2 = store.create(&request("cursor-000002", 'c', 4096)).unwrap();
    reach(&store, &j1.id, Phase::Writing);
    let first = store.events_after(&j1.id, 0, 2).unwrap();
    assert_eq!(first.len(), 2);
    assert!(first[0].sequence < first[1].sequence);
    let next = store.events_after(&j1.id, first[1].sequence, 100).unwrap();
    assert!(!next.is_empty());
    assert!(
        next.iter()
            .all(|event| event.job_id == j1.id && event.sequence > first[1].sequence)
    );
    assert!(
        store
            .events_after(&j2.id, 0, 100)
            .unwrap()
            .iter()
            .all(|e| e.job_id == j2.id)
    );
    drop(store);
    let reopened = JobStore::open(dir.path().join("jobs.sqlite")).unwrap();
    assert_eq!(
        reopened
            .events_after(&j1.id, first[1].sequence, 100)
            .unwrap()
            .len(),
        next.len()
    );
    assert!(
        reopened
            .events_after(&j1.id, i64::MAX, 100)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn restart_marks_interrupted_and_releases_target_lease() {
    let (dir, store) = store();
    let req = request("recover-000001", 'b', 4096);
    let j = store.create(&req).unwrap();
    reach(&store, &j.id, Phase::Writing);
    store.progress(&j.id, 2048, &"b".repeat(64)).unwrap();
    drop(store);
    let restarted = JobStore::open(dir.path().join("jobs.sqlite")).unwrap();
    assert_eq!(restarted.recover_interrupted().unwrap(), 1);
    assert_eq!(restarted.recover_interrupted().unwrap(), 0);
    let old = restarted.get(&j.id).unwrap();
    assert_eq!(old.phase, Phase::Interrupted);
    assert_eq!(old.completed_bytes, 2048);
    assert_eq!(old.failure_code.as_deref(), Some("agent_restart"));
    assert!(matches!(
        restarted.advance(&j.id, Phase::Flushing),
        Err(JournalError::InvalidTransition)
    ));
    assert_eq!(restarted.create(&req).unwrap().id, j.id); // retry cannot resurrect stale job
    let mut new = req.clone();
    new.idempotency_key = "recover-000002".into();
    assert_ne!(restarted.create(&new).unwrap().id, j.id);
}

#[test]
fn exclusive_target_lock_released_only_at_terminal_phase() {
    let (_dir, store) = store();
    let first = store
        .create(&request("lease-job-00001", 'b', 4096))
        .unwrap();
    assert!(matches!(
        store.create(&request("lease-job-00002", 'b', 4096)),
        Err(JournalError::TargetBusy)
    ));
    store.cancel(&first.id).unwrap();
    let next = store
        .create(&request("lease-job-00002", 'b', 4096))
        .unwrap();
    assert_ne!(first.id, next.id);
    assert_eq!(store.get(&first.id).unwrap().phase, Phase::Cancelled);
    assert_eq!(store.get(&next.id).unwrap().phase, Phase::Created);
}

#[test]
fn all_failure_classes_are_sanitized_durable_and_terminal() {
    let all = [
        Failure::DeviceDisconnected,
        Failure::ZeroByteWrite,
        Failure::ShortWrite,
        Failure::IoError,
        Failure::AccessDenied,
        Failure::WriteProtected,
        Failure::LockedVolume,
        Failure::InsufficientCapacity,
        Failure::SleepWake,
        Failure::PowerLoss,
        Failure::Crash,
        Failure::UserCancelled,
    ];
    let (_dir, store) = store();
    for (i, failure) in all.into_iter().enumerate() {
        let j = store
            .create(&JobRequest {
                idempotency_key: format!("fault-case-{i:04}"),
                source_sha256: "a".repeat(64),
                simulated_target: format!("{i:064x}"),
                expected_bytes: 4096,
            })
            .unwrap();
        reach(&store, &j.id, Phase::Writing);
        let failed = store.fail(&j.id, failure).unwrap();
        assert_eq!(failed.phase, Phase::Failed);
        assert_eq!(failed.failure_code.as_deref(), Some(failure.code()));
        let events = store.events_after(&j.id, 0, 100).unwrap();
        assert_eq!(events.last().unwrap().code.as_deref(), Some(failure.code()));
        assert!(
            !events
                .iter()
                .any(|event| event.phase == Phase::SimulatedSucceeded)
        );
        assert!(matches!(
            store.cancel(&j.id),
            Err(JournalError::InvalidTransition)
        ));
    }
}

#[test]
fn concurrent_same_key_is_idempotent_and_target_locked() {
    let (dir, _store) = store();
    let path = dir.path().join("jobs.sqlite");
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|n| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = JobStore::open(path).unwrap();
                barrier.wait();
                store.create(&request(
                    if n % 2 == 0 {
                        "parallel-one-id"
                    } else {
                        "parallel-two-id"
                    },
                    'd',
                    4096,
                ))
            })
        })
        .collect::<Vec<_>>();
    let mut accepted = vec![];
    let mut busy = 0;
    for result in handles {
        match result.join().unwrap() {
            Ok(job) => accepted.push(job.id),
            Err(JournalError::TargetBusy) => busy += 1,
            Err(other) => panic!("unexpected: {other:?}"),
        }
    }
    assert!(!accepted.is_empty());
    assert!(accepted.iter().all(|id| id == &accepted[0]));
    assert_eq!(accepted.len() + busy, 8);
    let store = JobStore::open(path).unwrap();
    assert_eq!(store.events_after(&accepted[0], 0, 100).unwrap().len(), 1);
}

#[test]
fn forward_unknown_database_schema_must_not_be_downgraded() {
    let (dir, store) = store();
    drop(store);
    let path = dir.path().join("jobs.sqlite");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA user_version=99").unwrap();
    drop(conn);
    assert!(matches!(
        JobStore::open(path),
        Err(JournalError::InvalidRequest)
    ));
}

#[test]
fn cancellation_cooperatively_aborts_and_never_claims_media_recovered() {
    let (_dir, store) = store();
    let j = store.create(&request("cancel-case-01", 'e', 4096)).unwrap();
    reach(&store, &j.id, Phase::Writing);
    store.progress(&j.id, 1024, &"f".repeat(64)).unwrap();
    let cancelled = store.cancel(&j.id).unwrap();
    assert_eq!(cancelled.phase, Phase::Cancelled);
    assert_eq!(cancelled.completed_bytes, 1024);
    assert!(!cancelled.flush_recorded);
    assert!(matches!(
        store.progress(&j.id, 4096, &"f".repeat(64)),
        Err(JournalError::InvalidEvidence)
    ));
    assert!(
        !store
            .events_after(&j.id, 0, 100)
            .unwrap()
            .iter()
            .any(|e| e.phase == Phase::SimulatedSucceeded)
    );
}

#[test]
fn injected_event_persist_failure_rolls_back_phase_atomically() {
    let (dir, store) = store();
    let j = store
        .create(&request("event-rollback-01", 'f', 4096))
        .unwrap();
    let db = dir.path().join("jobs.sqlite");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER fail_audit BEFORE INSERT ON job_events
        WHEN NEW.phase='PREFLIGHTED'
        BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;",
    )
    .unwrap();
    drop(conn);
    assert!(matches!(
        store.advance(&j.id, Phase::Preflighted),
        Err(JournalError::Database(_))
    ));
    let unchanged = store.get(&j.id).unwrap();
    assert_eq!(unchanged.phase, Phase::Created);
    assert_eq!(store.events_after(&j.id, 0, 100).unwrap().len(), 1);
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch("DROP TRIGGER fail_audit").unwrap();
    assert_eq!(
        store.advance(&j.id, Phase::Preflighted).unwrap().phase,
        Phase::Preflighted
    );
    assert_eq!(store.events_after(&j.id, 0, 100).unwrap().len(), 2);
}
