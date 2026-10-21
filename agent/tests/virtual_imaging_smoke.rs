use bootnexa_agent::{
    journal::{JobStore, Phase},
    virtual_imaging::{
        Fault, ImagingError, MAX_VIRTUAL_BYTES, VirtualImage, VirtualTarget, image_virtual,
    },
};
use tempfile::TempDir;
fn setup() -> (TempDir, JobStore) {
    let d = tempfile::tempdir().unwrap();
    let j = JobStore::open(d.path().join("virtual-jobs.sqlite")).unwrap();
    (d, j)
}
fn run_fault(fault: Fault) -> Phase {
    let (_dir, store) = setup();
    let mut image = VirtualImage::seeded(3 * 65536, 29).unwrap();
    let mut target = VirtualTarget::new(4 * 65536).unwrap();
    let result = image_virtual(&store, &mut image, &mut target, fault);
    assert!(result.is_err(), "injected fault unexpectedly succeeded");
    // All in-flight fault outcomes are committed as terminal FAILED/CANCELLED.
    let jobs = store.list_recent(10).unwrap();
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert!(!job.flush_recorded || job.phase != Phase::SimulatedSucceeded);
    assert!(
        !store
            .events_after(&job.id, 0, 100)
            .unwrap()
            .iter()
            .any(|e| e.phase == Phase::SimulatedSucceeded)
    );
    job.phase
}
#[test]
fn raw_virtual_imaging_flushes_and_verifies_every_byte() {
    let (_dir, store) = setup();
    for (size, seed) in [
        (512, 11),
        (65536, 17),
        (131072 + 99, 19),
        (9 * 1024 * 1024 + 17, 27),
    ] {
        let mut src = VirtualImage::seeded(size, seed).unwrap();
        let digest = src.digest().unwrap();
        let mut target = VirtualTarget::new(size + 512).unwrap();
        let report = image_virtual(&store, &mut src, &mut target, Fault::None).unwrap();
        assert_eq!(report.source_sha256, digest);
        assert_eq!(report.readback_sha256, Some(digest));
        assert_eq!(report.readback_bytes, size);
        assert_eq!(report.job.phase, Phase::SimulatedSucceeded);
        assert_eq!(report.job.completed_bytes, size);
        assert_eq!(report.job.verified_bytes, size);
        assert!(report.job.flush_recorded);
        assert!(report.max_buffer_bytes <= 128 * 1024);
        let mut cursor = 0;
        let mut events = vec![];
        loop {
            let page = store.events_after(&report.job.id, cursor, 100).unwrap();
            if page.is_empty() {
                break;
            }
            cursor = page.last().unwrap().sequence;
            events.extend(page);
        }
        assert_eq!(events.last().unwrap().phase, Phase::SimulatedSucceeded);
        assert!(events.windows(2).all(|w| w[0].sequence < w[1].sequence));
        assert_eq!(store.recover_interrupted().unwrap(), 0);
    }
}
#[test]
fn physical_device_paths_cannot_be_passed_to_virtual_constructors() {
    for size in [0, MAX_VIRTUAL_BYTES + 1, u64::MAX] {
        assert!(matches!(
            VirtualImage::seeded(size, 1),
            Err(ImagingError::InvalidFixture)
        ));
        assert!(matches!(
            VirtualTarget::new(size),
            Err(ImagingError::InvalidFixture)
        ));
    }
    let (_dir, store) = setup();
    let mut image = VirtualImage::seeded(65536, 2).unwrap();
    let mut target = VirtualTarget::new(65535).unwrap();
    assert!(matches!(
        image_virtual(&store, &mut image, &mut target, Fault::None),
        Err(ImagingError::InvalidFixture)
    ));
    assert!(store.list_recent(10).unwrap().is_empty());
}
#[test]
fn simulated_disconnect_short_zero_and_eio_fail_closed() {
    for fault in [
        Fault::UnplugAfter(65536),
        Fault::ZeroWriteAfter(65536),
        Fault::ShortWriteAfter(65536),
        Fault::IoAfter(65536),
        Fault::AccessDenied,
        Fault::WriteProtected,
        Fault::LockedVolume,
        Fault::SleepWakeAfter(65536),
        Fault::PowerLossAfter(65536),
        Fault::FlushError,
        Fault::ReadbackError,
    ] {
        assert_eq!(run_fault(fault), Phase::Failed);
    }
}
#[test]
fn cancellation_never_marks_virtual_target_usable() {
    assert_eq!(run_fault(Fault::CancelAfter(65536)), Phase::Cancelled);
    assert_eq!(run_fault(Fault::CancelAfter(0)), Phase::Cancelled);
}
#[test]
fn corrupted_readback_cannot_report_success_even_after_sync_all() {
    let (_dir, store) = setup();
    let mut image = VirtualImage::seeded(65536 + 8, 17).unwrap();
    let mut target = VirtualTarget::new(2 * 65536).unwrap();
    assert!(matches!(
        image_virtual(
            &store,
            &mut image,
            &mut target,
            Fault::CorruptBeforeReadback
        ),
        Err(ImagingError::VerificationMismatch)
    ));
    let jobs = store.list_recent(1).unwrap();
    assert_eq!(jobs[0].phase, Phase::Failed);
    assert!(jobs[0].flush_recorded);
    assert_eq!(jobs[0].verified_bytes, 0);
}
#[test]
fn retry_requires_new_job_and_never_reuses_committed_failed_image() {
    let (_dir, store) = setup();
    let mut image = VirtualImage::seeded(65536 * 2, 17).unwrap();
    let mut target = VirtualTarget::new(65536 * 2).unwrap();
    assert!(image_virtual(&store, &mut image, &mut target, Fault::UnplugAfter(65536)).is_err());
    let failed = store.list_recent(1).unwrap().pop().unwrap();
    assert_eq!(failed.phase, Phase::Failed);
    let done = image_virtual(&store, &mut image, &mut target, Fault::None).unwrap();
    assert_ne!(failed.id, done.job.id);
    assert_eq!(done.job.phase, Phase::SimulatedSucceeded);
}
