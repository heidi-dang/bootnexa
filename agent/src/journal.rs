//! Durable, SQLite-backed SIMULATION journal. No device handles or image I/O.
//! Physical jobs are deliberately unrepresentable in this milestone.
//!
//! Each mutation uses BEGIN IMMEDIATE + an event insert in the same transaction.
//! SQLite's writer serialization and the partial unique index make target leases
//! robust across multiple processes sharing the same database.
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("database failure: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("invalid simulation request")]
    InvalidRequest,
    #[error("simulation not found")]
    NotFound,
    #[error("idempotency key reused with different immutable inputs")]
    IdempotencyConflict,
    #[error("another active simulated job already owns the target")]
    TargetBusy,
    #[error("invalid or terminal job transition")]
    InvalidTransition,
    #[error("progress, flush or verification evidence is inconsistent")]
    InvalidEvidence,
    #[error("event cursor or replay limit invalid")]
    InvalidCursor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Created,
    Preflighted,
    WaitingForConsent,
    Locking,
    Preparing,
    Writing,
    Flushing,
    Verifying,
    SimulatedSucceeded,
    Failed,
    Cancelled,
    Interrupted,
}
impl Phase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Preflighted => "PREFLIGHTED",
            Self::WaitingForConsent => "WAITING_FOR_CONSENT",
            Self::Locking => "LOCKING",
            Self::Preparing => "PREPARING",
            Self::Writing => "WRITING",
            Self::Flushing => "FLUSHING",
            Self::Verifying => "VERIFYING",
            Self::SimulatedSucceeded => "SIMULATED_SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::Interrupted => "INTERRUPTED",
        }
    }
    fn from_db(value: &str) -> rusqlite::Result<Self> {
        let value = match value {
            "CREATED" => Self::Created,
            "PREFLIGHTED" => Self::Preflighted,
            "WAITING_FOR_CONSENT" => Self::WaitingForConsent,
            "LOCKING" => Self::Locking,
            "PREPARING" => Self::Preparing,
            "WRITING" => Self::Writing,
            "FLUSHING" => Self::Flushing,
            "VERIFYING" => Self::Verifying,
            "SIMULATED_SUCCEEDED" => Self::SimulatedSucceeded,
            "FAILED" => Self::Failed,
            "CANCELLED" => Self::Cancelled,
            "INTERRUPTED" => Self::Interrupted,
            _ => return Err(rusqlite::Error::InvalidQuery),
        };
        Ok(value)
    }
    pub const fn terminal(self) -> bool {
        matches!(
            self,
            Self::SimulatedSucceeded | Self::Failed | Self::Cancelled | Self::Interrupted
        )
    }
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::Created => Self::Preflighted,
            Self::Preflighted => Self::WaitingForConsent,
            Self::WaitingForConsent => Self::Locking,
            Self::Locking => Self::Preparing,
            Self::Preparing => Self::Writing,
            Self::Writing => Self::Flushing,
            Self::Flushing => Self::Verifying,
            Self::Verifying => Self::SimulatedSucceeded,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    DeviceDisconnected,
    ZeroByteWrite,
    ShortWrite,
    IoError,
    AccessDenied,
    WriteProtected,
    LockedVolume,
    InsufficientCapacity,
    SleepWake,
    PowerLoss,
    Crash,
    UserCancelled,
}
impl Failure {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DeviceDisconnected => "device_disconnected",
            Self::ZeroByteWrite => "zero_byte_write",
            Self::ShortWrite => "short_write",
            Self::IoError => "io_error",
            Self::AccessDenied => "access_denied",
            Self::WriteProtected => "write_protected",
            Self::LockedVolume => "locked_volume",
            Self::InsufficientCapacity => "insufficient_capacity",
            Self::SleepWake => "sleep_wake",
            Self::PowerLoss => "power_loss",
            Self::Crash => "process_crash",
            Self::UserCancelled => "user_cancelled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct JobRequest {
    pub idempotency_key: String,
    pub source_sha256: String,
    /// A hashed, NON-AUTHORITATIVE fixture identifier; never a disk path/index.
    pub simulated_target: String,
    pub expected_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: String,
    pub idempotency_key: String,
    pub source_sha256: String,
    pub simulated_target: String,
    pub expected_bytes: u64,
    pub phase: Phase,
    pub completed_bytes: u64,
    pub verified_bytes: u64,
    pub flush_recorded: bool,
    pub rolling_sha256: Option<String>,
    pub failure_code: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
#[derive(Debug, Clone)]
pub struct Event {
    pub sequence: i64,
    pub job_id: String,
    pub phase: Phase,
    pub completed_bytes: u64,
    pub verified_bytes: u64,
    pub code: Option<String>,
    pub at_ms: i64,
}

pub struct JobStore {
    path: PathBuf,
}
impl JobStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
        };
        let conn = store.connection()?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version != 0 && version != 4 {
            return Err(JournalError::InvalidRequest);
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS jobs(
                id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                source_sha256 TEXT NOT NULL,
                simulated_target TEXT NOT NULL,
                expected_bytes INTEGER NOT NULL CHECK(expected_bytes > 0),
                phase TEXT NOT NULL CHECK(phase IN
                    ('CREATED','PREFLIGHTED','WAITING_FOR_CONSENT','LOCKING',
                     'PREPARING','WRITING','FLUSHING','VERIFYING',
                     'SIMULATED_SUCCEEDED','FAILED','CANCELLED','INTERRUPTED')),
                completed_bytes INTEGER NOT NULL DEFAULT 0,
                verified_bytes INTEGER NOT NULL DEFAULT 0,
                flush_recorded INTEGER NOT NULL DEFAULT 0,
                rolling_sha256 TEXT,
                failure_code TEXT,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                simulation_only INTEGER NOT NULL DEFAULT 1 CHECK(simulation_only = 1)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS active_simulation_target
              ON jobs(simulated_target)
              WHERE phase NOT IN ('SIMULATED_SUCCEEDED','FAILED','CANCELLED','INTERRUPTED');
            CREATE TABLE IF NOT EXISTS job_events(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL REFERENCES jobs(id),
                phase TEXT NOT NULL,
                completed_bytes INTEGER NOT NULL,
                verified_bytes INTEGER NOT NULL,
                code TEXT,
                at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS job_events_by_job_cursor ON job_events(job_id, sequence);",
        )?;
        if version == 0 {
            conn.pragma_update(None, "user_version", 4)?;
        }
        Ok(store)
    }
    fn connection(&self) -> Result<Connection, JournalError> {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        Ok(conn)
    }
    pub fn create(&self, req: &JobRequest) -> Result<Job, JournalError> {
        if !valid_idempotency(&req.idempotency_key)
            || !valid_digest(&req.source_sha256)
            || !valid_digest(&req.simulated_target)
            || req.expected_bytes == 0
            || req.expected_bytes > i64::MAX as u64
        {
            return Err(JournalError::InvalidRequest);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM jobs WHERE idempotency_key=?1",
                [&req.idempotency_key],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            let job = load(&tx, &id)?;
            if job.source_sha256 != req.source_sha256
                || job.simulated_target != req.simulated_target
                || job.expected_bytes != req.expected_bytes
            {
                return Err(JournalError::IdempotencyConflict);
            }
            tx.commit()?;
            return Ok(job);
        }
        let occupied: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE simulated_target=?1
             AND phase NOT IN ('SIMULATED_SUCCEEDED','FAILED','CANCELLED','INTERRUPTED'))",
            [&req.simulated_target],
            |row| row.get(0),
        )?;
        if occupied {
            return Err(JournalError::TargetBusy);
        }
        let id = Uuid::new_v4().to_string();
        let now = millis();
        tx.execute(
            "INSERT INTO jobs(id,idempotency_key,source_sha256,simulated_target,expected_bytes,phase,created_at_ms,updated_at_ms)
             VALUES(?1,?2,?3,?4,?5,'CREATED',?6,?6)",
            params![id,req.idempotency_key,req.source_sha256,req.simulated_target,req.expected_bytes as i64,now]
        )?;
        append(&tx, &id, Phase::Created, 0, 0, None, now)?;
        let job = load(&tx, &id)?;
        tx.commit()?;
        Ok(job)
    }
    /// Bounded, newest-first synthetic jobs for read-only Activity history.
    pub fn list_recent(&self, limit: usize) -> Result<Vec<Job>, JournalError> {
        if !(1..=100).contains(&limit) {
            return Err(JournalError::InvalidCursor);
        }
        let conn = self.connection()?;
        let mut stmt =
            conn.prepare("SELECT id FROM jobs ORDER BY created_at_ms DESC, rowid DESC LIMIT ?1")?;
        let ids = stmt
            .query_map([limit as i64], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| load(&conn, id)).collect()
    }
    pub fn get(&self, id: &str) -> Result<Job, JournalError> {
        load(&self.connection()?, id)
    }
    /// Persistent cursor replay, in order. A reconnect can use the last seen
    /// sequence and reconstruct missing events without trusting live delivery.
    pub fn events_after(
        &self,
        id: &str,
        after: i64,
        limit: usize,
    ) -> Result<Vec<Event>, JournalError> {
        if after < 0 || !(1..=100).contains(&limit) {
            return Err(JournalError::InvalidCursor);
        }
        self.get(id)?;
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT sequence,job_id,phase,completed_bytes,verified_bytes,code,at_ms
             FROM job_events WHERE job_id=?1 AND sequence>?2 ORDER BY sequence ASC LIMIT ?3",
        )?;
        let events = stmt
            .query_map(params![id, after, limit as i64], |row| {
                Ok(Event {
                    sequence: row.get(0)?,
                    job_id: row.get(1)?,
                    phase: Phase::from_db(&row.get::<_, String>(2)?)?,
                    completed_bytes: row.get::<_, i64>(3)? as u64,
                    verified_bytes: row.get::<_, i64>(4)? as u64,
                    code: row.get(5)?,
                    at_ms: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(events)
    }
    /// Single legal forward step. SIMULATED_SUCCEEDED requires flush and
    /// complete verification evidence, and is never actual media success.
    pub fn advance(&self, id: &str, next: Phase) -> Result<Job, JournalError> {
        self.change(id, |tx, job, now| {
            if job.phase.next() != Some(next) {
                return Err(JournalError::InvalidTransition);
            }
            if next == Phase::Flushing && job.completed_bytes != job.expected_bytes {
                return Err(JournalError::InvalidEvidence);
            }
            if next == Phase::Verifying && !job.flush_recorded {
                return Err(JournalError::InvalidEvidence);
            }
            if next == Phase::SimulatedSucceeded
                && (!job.flush_recorded || job.verified_bytes != job.expected_bytes)
            {
                return Err(JournalError::InvalidEvidence);
            }
            change_phase(tx, job, next, None, now)
        })
    }
    pub fn progress(&self, id: &str, bytes: u64, digest: &str) -> Result<Job, JournalError> {
        if !valid_digest(digest) {
            return Err(JournalError::InvalidEvidence);
        }
        self.change(id, |tx, job, now| {
            if job.phase != Phase::Writing
                || bytes > job.expected_bytes
                || bytes < job.completed_bytes
            {
                return Err(JournalError::InvalidEvidence);
            }
            if bytes == job.completed_bytes {
                if job.rolling_sha256.as_deref() == Some(digest) {
                    return Ok(());
                }
                return Err(JournalError::InvalidEvidence);
            }
            tx.execute(
                "UPDATE jobs SET completed_bytes=?2,rolling_sha256=?3,updated_at_ms=?4 WHERE id=?1",
                params![id, bytes as i64, digest, now],
            )?;
            append(tx, id, job.phase, bytes, job.verified_bytes, None, now)
        })
    }
    /// Evidence records are SIMULATED, never proof that an OS flush occurred.
    pub fn simulate_flush(&self, id: &str) -> Result<Job, JournalError> {
        self.change(id, |tx, job, now| {
            if job.phase != Phase::Flushing || job.completed_bytes != job.expected_bytes {
                return Err(JournalError::InvalidEvidence);
            }
            if job.flush_recorded {
                return Ok(());
            }
            tx.execute(
                "UPDATE jobs SET flush_recorded=1,updated_at_ms=?2 WHERE id=?1",
                params![id, now],
            )?;
            append(
                tx,
                id,
                job.phase,
                job.completed_bytes,
                job.verified_bytes,
                Some("simulated_flush"),
                now,
            )
        })
    }
    pub fn simulate_verify(&self, id: &str, verified: u64) -> Result<Job, JournalError> {
        self.change(id, |tx, job, now| {
            if job.phase != Phase::Verifying
                || !job.flush_recorded
                || verified > job.expected_bytes
                || verified < job.verified_bytes
            {
                return Err(JournalError::InvalidEvidence);
            }
            if verified == job.verified_bytes {
                return Ok(());
            }
            tx.execute(
                "UPDATE jobs SET verified_bytes=?2,updated_at_ms=?3 WHERE id=?1",
                params![id, verified as i64, now],
            )?;
            append(
                tx,
                id,
                job.phase,
                job.completed_bytes,
                verified,
                Some("simulated_verify"),
                now,
            )
        })
    }
    pub fn fail(&self, id: &str, fault: Failure) -> Result<Job, JournalError> {
        self.terminate(id, Phase::Failed, fault.code())
    }
    pub fn cancel(&self, id: &str) -> Result<Job, JournalError> {
        self.terminate(id, Phase::Cancelled, Failure::UserCancelled.code())
    }
    fn terminate(&self, id: &str, phase: Phase, code: &str) -> Result<Job, JournalError> {
        self.change(id, |tx, job, now| {
            if job.phase.terminal() {
                return Err(JournalError::InvalidTransition);
            }
            change_phase(tx, job, phase, Some(code), now)
        })
    }
    /// Startup recovery is explicitly terminal and non-resumable. A fresh
    /// idempotency key (new operator intent) is needed for another attempt.
    /// Simulated leases release atomically with the phase transition.
    pub fn recover_interrupted(&self) -> Result<usize, JournalError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let jobs: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM jobs WHERE phase NOT IN
                 ('SIMULATED_SUCCEEDED','FAILED','CANCELLED','INTERRUPTED') ORDER BY id",
            )?;
            stmt.query_map([], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let now = millis();
        for id in &jobs {
            let job = load(&tx, id)?;
            change_phase(&tx, &job, Phase::Interrupted, Some("agent_restart"), now)?;
        }
        tx.commit()?;
        Ok(jobs.len())
    }
    fn change(
        &self,
        id: &str,
        operation: impl FnOnce(&Transaction<'_>, &Job, i64) -> Result<(), JournalError>,
    ) -> Result<Job, JournalError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = load(&tx, id)?;
        operation(&tx, &old, millis())?;
        let new = load(&tx, id)?;
        tx.commit()?;
        Ok(new)
    }
}
fn valid_digest(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_idempotency(v: &str) -> bool {
    (8..=128).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn load(conn: &Connection, id: &str) -> Result<Job, JournalError> {
    conn.query_row(
        "SELECT id,idempotency_key,source_sha256,simulated_target,expected_bytes,phase,
                completed_bytes,verified_bytes,flush_recorded,rolling_sha256,failure_code,
                created_at_ms,updated_at_ms FROM jobs WHERE id=?1",
        [id],
        |row| {
            Ok(Job {
                id: row.get(0)?,
                idempotency_key: row.get(1)?,
                source_sha256: row.get(2)?,
                simulated_target: row.get(3)?,
                expected_bytes: row.get::<_, i64>(4)? as u64,
                phase: Phase::from_db(&row.get::<_, String>(5)?)?,
                completed_bytes: row.get::<_, i64>(6)? as u64,
                verified_bytes: row.get::<_, i64>(7)? as u64,
                flush_recorded: row.get::<_, i64>(8)? == 1,
                rolling_sha256: row.get(9)?,
                failure_code: row.get(10)?,
                created_at_ms: row.get(11)?,
                updated_at_ms: row.get(12)?,
            })
        },
    )
    .optional()?
    .ok_or(JournalError::NotFound)
}
fn append(
    tx: &Transaction<'_>,
    id: &str,
    phase: Phase,
    completed: u64,
    verified: u64,
    code: Option<&str>,
    now: i64,
) -> Result<(), JournalError> {
    tx.execute(
        "INSERT INTO job_events(job_id,phase,completed_bytes,verified_bytes,code,at_ms)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            id,
            phase.as_str(),
            completed as i64,
            verified as i64,
            code,
            now
        ],
    )?;
    Ok(())
}
fn change_phase(
    tx: &Transaction<'_>,
    job: &Job,
    next: Phase,
    failure: Option<&str>,
    now: i64,
) -> Result<(), JournalError> {
    tx.execute(
        "UPDATE jobs SET phase=?2,failure_code=?3,updated_at_ms=?4 WHERE id=?1",
        params![job.id, next.as_str(), failure, now],
    )?;
    append(
        tx,
        &job.id,
        next,
        job.completed_bytes,
        job.verified_bytes,
        failure,
        now,
    )
}
