# Phase 5 — file-backed virtual raw imaging

**Status:** Implemented and software-tested as a **virtual-media-only** imaging engine. No USB block device, raw physical disk, disk path, UAC elevation or destructive network endpoint is used or exposed. Production-signed Windows installer and physical USB qualification remain blocked independently.

## Architecture

The Rust module `agent/src/virtual_imaging.rs` implements actual byte-copy, local file flush and full source-to-target read-back **only for anonymous temporary regular-file fixtures**. The constructors take fixture capacity and a deterministic seed, not disk paths, handles or user-supplied operating-system device names. Both source and target are allocated using `tempfile::tempfile()`; the private file fields cannot be replaced through the public virtual imager interface. Input and target capacity are capped at 256 MiB in this test-only engine. A 64 KiB buffered copy and two 64 KiB comparison buffers impose a maximum working data buffer of 128 KiB for the imager (apart from library/system buffers).

Every run creates a unique simulation journal job with immutable SHA-256 source fingerprint and an opaque, synthetic target fingerprint. The ordered SQLite state machine from Phase 4 records progress monotonically, and all incomplete or failed jobs remain terminal/incomplete rather than being resurrected.

The pipeline is:

1. Generate an anonymous source file, compute its full SHA-256, and allocate an anonymous target.
2. Reject oversized images before creating a job. Advance through the journal's simulation-only preparatory states.
3. Read and write source bytes using bounded chunks and reject any missing/short/zero write.
4. Persist per-chunk progress with a SHA-256 rolling prefix hash, then require complete byte-count evidence.
5. Call the target regular file's `sync_all()`. The SQLite journal marks this only as **simulated flush evidence**, not a real USB-drive cache flush.
6. Rewind both files, compare **every byte** while calculating read-back SHA-256, persist verified progress, and compare both digests.
7. Only after all checks pass, transition to `SIMULATED_SUCCEEDED`. Physical `SUCCEEDED` remains unrepresentable.

**Not tested:** Actual USB controller flush semantics, dynamic volume extents, SCSI bridge behavior, device disconnect, Windows sleep/wake, write-protected media, fixed-disk exclusion in a native writer, and real bootability. Failure injection simulates these responses; it does not reproduce their kernel/device behavior.

## Fault injection and acceptance

The simulator supports injected unplug, zero/short write, I/O error, access denial, write protection, locked volume, sleep/wake, simulated power loss, cancellation, regular-file flush error, read-back error and **actual deliberate target corruption before read-back**.

Regression tests verify: single-sector fixtures; multi-chunk (>9 MiB) streaming; non-sector-multiple tail handling; bounded working buffer; capacity rejection; restart-safe journal event pagination; replacement-job identity; no completed status following any injected failure; corrupted target rejection even following successful `sync_all()`; terminal cancellation; and source/target digest matching only on fully verified files.

The CLI is for developers only:

```bash
cargo run --manifest-path agent/Cargo.toml --bin bootnexa-jobsim -- virtual-demo ./virtual-test.sqlite 2097152
cargo run --manifest-path agent/Cargo.toml --bin bootnexa-jobsim -- virtual-corrupt ./virtual-test.sqlite 262144
cargo run --manifest-path agent/Cargo.toml --bin bootnexa-jobsim -- virtual-unplug ./virtual-test.sqlite 262144
cargo run --manifest-path agent/Cargo.toml --bin bootnexa-jobsim -- virtual-cancel ./virtual-test.sqlite 262144
```

The first prints `SIMULATED_SUCCEEDED`, full verified bytes, source/read-back SHA-256 and `physicalWrite:false`. The others print explicit FAILED/CANCELLED and sanitized fault codes. The binary never accepts an output device path or image file path for these modes.

## Read-only Activity UI

The browser's **Activity** tab now displays the last 20 simulated jobs if the Windows native agent has been explicitly started with `BOOTNEXA_ENABLE_SIMULATIONS=1` and `BOOTNEXA_SIMULATION_DB` pointing at the same local SQLite file used by the simulator. The GET-only route `/v1/simulations?limit=20` requires the existing native-approved bearer and exact Origin, and the user may refresh it manually. An offline agent or disabled simulation feed displays an explanatory state.

The Activity page cannot start, cancel, retry, unlock or write to any device; the only mutations are made by the separately launched developer CLI. No physical media write button has been enabled anywhere.

## Explicit incomplete release qualifications

See [Physical USB release gates](PHYSICAL-WRITE-RELEASE-GATES.md). Real USB writes require a separate privileged helper and independent OS-level protected-disk ancestry validation, generation-bound target identity and explicit per-device destructive consent, device locking, real flush and read-back evidence, and physical Windows USB acceptance. Public trust also requires completing code-signing [issue #5](https://github.com/heidi-dang/bootnexa/issues/5) with a real provider. None can be marked complete through simulation.

**Roadmap status:** Phase 5 *virtual-media foundation* complete; physical end-to-end raw imaging not yet delivered.
