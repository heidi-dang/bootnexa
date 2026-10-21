//! Phase 5: bounded raw imaging into anonymous temporary *regular files*.
//! There is intentionally NO API for paths, device handles, partitions or USB IO.
use crate::journal::{Failure, Job, JobRequest, JobStore, JournalError, Phase};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
use thiserror::Error;
use uuid::Uuid;
const CHUNK: usize = 64 * 1024;
pub const MAX_VIRTUAL_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    UnplugAfter(u64),
    ZeroWriteAfter(u64),
    ShortWriteAfter(u64),
    IoAfter(u64),
    CancelAfter(u64),
    AccessDenied,
    WriteProtected,
    LockedVolume,
    SleepWakeAfter(u64),
    PowerLossAfter(u64),
    FlushError,
    ReadbackError,
    CorruptBeforeReadback,
}
#[derive(Debug, Error)]
pub enum ImagingError {
    #[error("invalid or oversized virtual media fixture")]
    InvalidFixture,
    #[error("source digest or target verification mismatch")]
    VerificationMismatch,
    #[error("injected simulated fault: {0:?}")]
    Injected(Failure),
    #[error("simulator I/O error")]
    Io(#[from] std::io::Error),
    #[error("job journal error: {0}")]
    Journal(#[from] JournalError),
}
/// An anonymous, unlinked regular-file fixture. Constructors accept sizes,
/// NEVER OS paths; there is no way to supply \`PhysicalDriveN\` or /dev nodes.
pub struct VirtualImage {
    file: File,
    size: u64,
}
impl VirtualImage {
    pub fn seeded(size: u64, seed: u8) -> Result<Self, ImagingError> {
        if size == 0 || size > MAX_VIRTUAL_BYTES {
            return Err(ImagingError::InvalidFixture);
        }
        let mut file = tempfile::tempfile()?;
        let mut left = size;
        let mut offset = 0_u64;
        let mut bytes = [0_u8; CHUNK];
        while left > 0 {
            let count = left.min(CHUNK as u64) as usize;
            for (i, item) in bytes[..count].iter_mut().enumerate() {
                *item = seed
                    .wrapping_add((offset + i as u64) as u8)
                    .rotate_left(((offset + i as u64) % 8) as u32);
            }
            file.write_all(&bytes[..count])?;
            offset += count as u64;
            left -= count as u64;
        }
        file.sync_all()?;
        file.rewind()?;
        Ok(Self { file, size })
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn digest(&mut self) -> Result<String, ImagingError> {
        self.file.rewind()?;
        let mut sha = Sha256::new();
        let mut chunk = [0_u8; CHUNK];
        loop {
            let n = self.file.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            sha.update(&chunk[..n]);
        }
        self.file.rewind()?;
        Ok(hex::encode(sha.finalize()))
    }
}

/// Exactly one anonymous virtual target per instance. Never a device handle.
pub struct VirtualTarget {
    file: File,
    capacity: u64,
}
impl VirtualTarget {
    pub fn new(capacity: u64) -> Result<Self, ImagingError> {
        if capacity == 0 || capacity > MAX_VIRTUAL_BYTES {
            return Err(ImagingError::InvalidFixture);
        }
        let file = tempfile::tempfile()?;
        file.set_len(capacity)?;
        Ok(Self { file, capacity })
    }
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
}

pub struct ImagingReport {
    pub job: Job,
    pub source_sha256: String,
    pub readback_sha256: Option<String>,
    pub readback_bytes: u64,
    pub max_buffer_bytes: usize,
}
fn injection(at: u64, fault: Fault) -> Option<Failure> {
    match fault {
        Fault::UnplugAfter(position) if at >= position => Some(Failure::DeviceDisconnected),
        Fault::ZeroWriteAfter(position) if at >= position => Some(Failure::ZeroByteWrite),
        Fault::ShortWriteAfter(position) if at >= position => Some(Failure::ShortWrite),
        Fault::IoAfter(position) if at >= position => Some(Failure::IoError),
        Fault::CancelAfter(position) if at >= position => Some(Failure::UserCancelled),
        Fault::SleepWakeAfter(position) if at >= position => Some(Failure::SleepWake),
        Fault::PowerLossAfter(position) if at >= position => Some(Failure::PowerLoss),
        Fault::AccessDenied => Some(Failure::AccessDenied),
        Fault::WriteProtected => Some(Failure::WriteProtected),
        Fault::LockedVolume => Some(Failure::LockedVolume),
        _ => None,
    }
}
fn abort(store: &JobStore, id: &str, reason: Failure) -> ImagingError {
    if reason == Failure::UserCancelled {
        let _ = store.cancel(id);
    } else {
        let _ = store.fail(id, reason);
    }
    ImagingError::Injected(reason)
}
fn journal_error(store: &JobStore, id: &str, error: ImagingError) -> ImagingError {
    // No failed or cancelled operation may be reported SUCCEEDED.
    let _ = store.fail(id, Failure::IoError);
    error
}

/// Real byte-copy, OS flush and source-to-target readback ONLY on our
/// anonymous file fixtures, with bounded buffers and a durable simulation
/// journal. No caller can pass an existing disk or pathname.
pub fn image_virtual(
    store: &JobStore,
    source: &mut VirtualImage,
    target: &mut VirtualTarget,
    fault: Fault,
) -> Result<ImagingReport, ImagingError> {
    let size = source.size;
    if size > target.capacity {
        return Err(ImagingError::InvalidFixture);
    }
    let expected = source.digest()?;
    let nonce = Uuid::new_v4();
    let fingerprint = hex::encode(Sha256::digest(
        format!("anonymous-virtual:{nonce}").as_bytes(),
    ));
    let job = store.create(&JobRequest {
        idempotency_key: format!("virtual:{nonce}"),
        source_sha256: expected.clone(),
        simulated_target: fingerprint,
        expected_bytes: size,
    })?;
    let id = job.id;
    // No native consent: the 'consent' phase is only a virtual placeholder.
    for phase in [
        Phase::Preflighted,
        Phase::WaitingForConsent,
        Phase::Locking,
        Phase::Preparing,
        Phase::Writing,
    ] {
        store.advance(&id, phase)?;
    }
    let mut written: u64 = 0;
    let mut data = [0_u8; CHUNK];
    let mut source_hash = Sha256::new();
    source.file.rewind()?;
    target.file.rewind()?;
    while written < size {
        if let Some(reason) = injection(written, fault) {
            return Err(abort(store, &id, reason));
        }
        let desired = ((size - written) as usize).min(CHUNK);
        if let Err(e) = source.file.read_exact(&mut data[..desired]) {
            return Err(journal_error(store, &id, ImagingError::Io(e)));
        }
        let actual = match target.file.write(&data[..desired]) {
            Ok(n) => n,
            Err(e) => return Err(journal_error(store, &id, ImagingError::Io(e))),
        };
        if actual != desired {
            return Err(abort(
                store,
                &id,
                if actual == 0 {
                    Failure::ZeroByteWrite
                } else {
                    Failure::ShortWrite
                },
            ));
        }
        source_hash.update(&data[..desired]);
        written += desired as u64;
        if let Err(e) = store.progress(&id, written, &hex::encode(source_hash.clone().finalize())) {
            return Err(journal_error(store, &id, ImagingError::Journal(e)));
        }
    }
    if hex::encode(source_hash.finalize()) != expected {
        let _ = store.fail(&id, Failure::IoError);
        return Err(ImagingError::VerificationMismatch);
    }
    store.advance(&id, Phase::Flushing)?;
    if fault == Fault::FlushError {
        return Err(abort(store, &id, Failure::IoError));
    }
    if let Err(e) = target.file.sync_all() {
        return Err(journal_error(store, &id, ImagingError::Io(e)));
    }
    store.simulate_flush(&id)?;
    store.advance(&id, Phase::Verifying)?;
    if fault == Fault::ReadbackError {
        return Err(abort(store, &id, Failure::IoError));
    }
    if fault == Fault::CorruptBeforeReadback {
        target.file.seek(SeekFrom::Start(0))?;
        target.file.write_all(&[0xa5])?;
        target.file.sync_all()?;
    }
    target.file.rewind()?;
    source.file.rewind()?;
    let mut verification = Sha256::new();
    let mut check = [0_u8; CHUNK];
    let mut checked = 0_u64;
    while checked < size {
        let n = ((size - checked) as usize).min(CHUNK);
        if let Err(e) = target.file.read_exact(&mut check[..n]) {
            return Err(journal_error(store, &id, ImagingError::Io(e)));
        }
        if let Err(e) = source.file.read_exact(&mut data[..n]) {
            return Err(journal_error(store, &id, ImagingError::Io(e)));
        }
        if data[..n] != check[..n] {
            let _ = store.fail(&id, Failure::IoError);
            return Err(ImagingError::VerificationMismatch);
        }
        verification.update(&check[..n]);
        checked += n as u64;
        store.simulate_verify(&id, checked)?;
    }
    let readback_sha = hex::encode(verification.finalize());
    if readback_sha != expected {
        let _ = store.fail(&id, Failure::IoError);
        return Err(ImagingError::VerificationMismatch);
    }
    let complete = store.advance(&id, Phase::SimulatedSucceeded)?;
    Ok(ImagingReport {
        job: complete,
        source_sha256: expected,
        readback_sha256: Some(readback_sha),
        readback_bytes: checked,
        max_buffer_bytes: CHUNK * 2,
    })
}
