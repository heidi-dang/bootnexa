# Phase 4 — durable transactional job journal and simulator

**Status:** The simulation-grade journal, interruption recovery, CLI driver, snapshot API and SSE replay are implemented. **Physical media writing and production job execution are not implemented.** The current browser never issues destructive operations.

## Architecture and trust boundaries

The Rust journal lives in `agent/src/journal.rs` as an independent library, backed by an on-disk SQLite database (bundled SQLite), with foreign keys, WAL journaling, FULL synchronous durability and an explicit schema version. Every state transition, progress record, simulated flush, simulated verification and terminal outcome is committed with its corresponding audit event in the **same SQLite transaction**. Mutations use `BEGIN IMMEDIATE`, with a bounded busy timeout and a partial unique index over active target fingerprints. No journal method opens a disk handle, formats media, unmounts volumes or reads an image.

The prototype is intentionally restricted to **synthetic media jobs**. The only completed-success state is `SIMULATED_SUCCEEDED`, which is never synonymous with physical USB write success. Flush and verification evidence are deliberately named *simulated* and must not be used to infer that actual I/O occurred. Real helper attestation and physical `SUCCEEDED` reporting are separate, gated work.

| Boundary | Implementation |
| --- | --- |
| Job identity | Random UUID; caller supplies an idempotency key validated and bound to immutable source SHA-256, simulated target fingerprint and expected byte count |
| Per-target ownership | Unique active-target index serializes competing jobs across processes; no physical device lock is claimed |
| State | `CREATED → PREFLIGHTED → WAITING_FOR_CONSENT → LOCKING → PREPARING → WRITING → FLUSHING → VERIFYING → SIMULATED_SUCCEEDED` |
| Interrupted or cancelled | Explicit `FAILED`, `CANCELLED`, `INTERRUPTED` terminal states; no automatic restart or false "media restored" result |
| Progress | Monotonic byte counter, rolling digest field, bounded source size, duplicates idempotent |
| Completion | Requires all simulated bytes recorded, simulated flush marker, and complete simulated verification |
| Audit/replay | Monotonic SQLite AUTOINCREMENT event sequence, persisted with every job update; events can be resumed from a cursor |
| Crash recovery | On explicit recovery or an opt-in agent restart, nonterminal jobs are marked `INTERRUPTED` atomically and synthetic target ownership is released |
| Error handling | Fixed enum of sanitized failure codes; no untrusted raw exceptions are serialized into events |

### Run the simulator (no Windows device required)

Use a temporary local SQLite file, not a production service database.

```bash
cargo test --manifest-path agent/Cargo.toml --locked --all-targets
cargo run --manifest-path agent/Cargo.toml --bin bootnexa-jobsim -- demo ./bootnexa-simulation.sqlite
# The command prints a JSON jobId and SIMULATED_SUCCEEDED.
cargo run --manifest-path agent/Cargo.toml --bin bootnexa-jobsim -- inspect ./bootnexa-simulation.sqlite <job-id>
cargo run --manifest-path agent/Cargo.toml --bin bootnexa-jobsim -- events ./bootnexa-simulation.sqlite <job-id> 0
```

For interrupted-job testing, run `crash-fixture` instead of `demo` (leaves a synthetic job in `WRITING`). In a new process, invoke `recover` with the same SQLite path. The prior job becomes `INTERRUPTED`, and its event history remains available. Run `cancel` with a currently active synthetic job ID to verify cancellation. The simulator never takes paths to physical drives as arguments; its target IDs are synthetic SHA-256 fingerprints.

### Optional read-only local API

This API is **disabled by default** and must not be enabled as an end-user disk-writing feature. Developers may opt in while testing a local database by setting both `BOOTNEXA_ENABLE_SIMULATIONS=1` and `BOOTNEXA_SIMULATION_DB=<path-to-existing-or-creatable-sqlite-file>` before launching the normal interactive agent. On startup, it marks any unfinished *simulation* jobs interrupted.

The simulation API uses the existing origin-bound, Windows native-approved read-only bearer session. The browser must supply its `Origin` and `Authorization: Bearer <session-token>` headers; no cross-origin or unauthenticated access is provided. Its endpoints are:

| Route | Purpose |
| --- | --- |
| `GET /v1/simulations/{id}` | Durable simulation snapshot |
| `GET /v1/simulations/{id}/events?after=0&limit=100` | Cursor-based persisted JSON event replay |
| `GET /v1/simulations/{id}/stream?after=0` | Bounded SSE event stream with sequence `id` and keep-alive, replaying persisted events before polling for new ones |

The feed is read-only: there are **no HTTP routes to create jobs, advance states, cancel, unlock physical disks, or write images**. Web clients that cannot attach a bearer to native EventSource requests should use an authenticated streaming `fetch` or the JSON replay endpoint. SSE sessions expire after 120 seconds and can be resumed using their last sequence through `?after=`. The `devices:read` bearer never confers job execution authority.

### Acceptance tests

- State-machine gates reject out-of-order stages, invalid progress, missing flush or incomplete verification.
- Idempotent retries return the original job, while conflicting payload reuse is rejected.
- SQLite writer contention across eight threads cannot create duplicate active jobs for one target.
- Injected event-insert failures roll back the corresponding state change atomically.
- Restart marks jobs interrupted and permits a new attempt only under a fresh idempotency key.
- Replay after process exit reconstructs exact monotonic events; invalid cursors are rejected.
- Fixed, sanitized failures cover device removal, short/zero-byte write, I/O error, write protection, locked volume, access denial, insufficient capacity, sleep/wake, power loss and crash **as simulations**.
- Two real child-process acceptance tests exercise the simulator executable using a shared database.
- Read-only HTTP tests confirm disabled-by-default routes, authorization, Origin checks, snapshots, JSON cursor replay and SSE for a terminal job.

CI runs Rust tests, strict Clippy, Windows native read-only agent tests, installer signing isolation, browser acceptance and production-release rejection on the exact Git revision.

## Not yet qualified

This phase does **not** include a privileged USB writer, exclusive physical volume lock, hardware cancellation, durable real-media flush, target read-back, real progress from device I/O or a browser-side activity/job controller. The future physical executor must revalidate image bytes and complete device ancestry, bind destructive approval to a specific operation plan, and distinguish user cancellation from a safe/usable target. A real `SUCCEEDED` state is intentionally not representable in this simulation journal.

Production-trusted Windows signing remains tracked in [issue #5](https://github.com/heidi-dang/bootnexa/issues/5). The next planned imaging milestone is Phase 5, first using **file-backed virtual block devices only** and fault injection. Physical USB writing continues to require separate safety approval and actual Windows hardware qualification.
