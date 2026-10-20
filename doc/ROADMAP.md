# BootNexa — implementation roadmap

> **Status:** Planning baseline · 20 October 2026  
> **Target:** A safe, web-first bootable-media workstation with a locally installed native agent.  
> **Rufus baseline:** 4.15 (30 June 2026), verified against https://rufus.ie/  
> **Owner:** BootNexa maintainers

## Product definition

BootNexa brings the essential workflows of a native bootable-USB utility into a modern browser workspace without surrendering control of physical disks to a remote service. The browser owns interaction, guidance, diagnostics views, and progress presentation. A signed local agent owns device discovery and authorised disk operations. ISO files and device contents never need to leave the user's computer.

The first supported operating system is Windows 10/11 on x64; Windows on Arm and Linux/macOS agents are separate compatibility programmes. This ordering intentionally privileges correctness, hardware coverage, and a smaller first release over a simultaneous cross-platform launch.

### Non-negotiable principles

1. **Fail closed:** no connected agent, no physical writes; no explicit device consent, no write; any unexpected device identity change, abort.
2. **Local by design:** media data streams directly between the user's machine and the selected drive; server-side image upload is not part of the workflow.
3. **Truthful state:** "selected", "analysed", "verified", and "boot-tested" are different states; the UI must never conflate them.
4. **Bounded privilege:** the agent UI/service runs unprivileged and a small operation-specific helper receives the least privilege the platform permits.
5. **Deterministic contracts:** versioned commands and append-only job events; clients can reconnect without losing the authoritative job state.
6. **Compatibility backed by evidence:** implement each image format and boot path behind a test matrix, not marketing checkboxes.
7. **No partial-success theatre:** incomplete media, cancelled writes, unreadable verification, and unsupported image combinations must produce explicit failure.

## Current repository state

The initial commit contains a responsive React UI preview, original SVG identity, navigation and settings controls, a local image selector, and technical planning documents. **There is no disk agent, partitioning engine, elevated helper, genuine device discovery, image analysis engine, or safe physical USB writer yet.** The "Start writing" button is intentionally disabled. Other workspaces (ISO Library, Backup, Diagnostics, Activity, Settings) are navigable placeholders. Screenshots document the current UI, not a delivered flashing capability.

## Release sequence

| Release | Primary outcome | Minimum quality gate |
| --- | --- | --- |
| 0.1 — Product foundation | Repository, original identity, browser shell, contracts and security design | Typecheck, production build, responsive/a11y review |
| 0.2 — Paired local agent | Signed Windows agent, discovery, consent, loopback protocol, read-only metadata | Device matrices + origin/auth abuse suite |
| 0.3 — Safe raw imaging | Device locking, IMG/DD writer, checksums, cancellation, verification and logs | Physical USB destructive tests + replay and failure injection |
| 0.4 — Bootable ISO workflows | ISO inspection, FAT/NTFS, GPT/MBR, BIOS/UEFI compatibility | Boot in QEMU/OVMF and physical UEFI/BIOS |
| 0.5 — Windows installation media | WIM/ESD handling, large-file strategies, EFI boot and documented Win11 customisation | Windows install/upgrade smoke matrix |
| 0.6 — Linux and advanced images | Syslinux/GRUB, persistence, compressed images, backup/restore | Distro and image-format compatibility matrix |
| 0.7 — Diagnostics and operational hardening | Bad blocks, fake capacity, FFU/VHD/VHDX, device forensics, release/recovery | Hardware endurance + power-loss/cancellation suite |
| 1.0 — Production | Signed installers, updater, docs, accessibility, parity report, stable API | All P0 acceptance gates and audited P1 supported paths |
| 1.x — Additional platforms | Linux/macOS native drivers where technically feasible | Independent per-OS hardware and privilege qualification |

Dates are intentionally omitted. Completion requires evidence, not a calendar promise.

---

## Phase 0 — Baseline, scope and risk register

**Work:** Define supported hardware, architectures, browsers and OS builds; enumerate format/boot feature requirements from Rufus 4.15 docs, source and executable behaviour; select licence and dependency compliance programme; inventory disk APIs for Windows/Linux/macOS; issue a signed threat-model baseline.

**Deliverables**
- `doc/FEATURE_MATRIX.md` lists every in-scope feature with owner, OS, priority and test evidence.
- Requirements ledger distinguishes *not started*, *in progress*, *qualified*, and *unsupported*.
- Device fixtures: USB 2/3 flash, large external SSD, USB SATA/NVMe bridges, read-only media, faulty drives, and a machine with multiple internal disks.
- Environments: x64 Windows 10/11, UEFI and legacy BIOS test machines, virtual boot fixtures, standard and non-admin users.

**Exit gate:** Product scope reviewed; no destructive device operation is available in the web preview.

## Phase 1 — Design system and browser application

**Work:** Establish responsive navigation, theme tokens, keyboard patterns, accessible form semantics, states and error copy. Build the ISO picker and local metadata display; differentiate native-agent availability from demo/preview. Implement direct refresh, device selection, review dialog, progress panel, log drawer, persistence preferences, job history, and media diagnostics surfaces.

**Architecture:** React + TypeScript + Vite with small, typed components. Add a router only when deep-linking warrants it; use React Query or a similar cache only for authoritative agent-backed state. Do not introduce a cloud database for local disk jobs.

**Tests:** Playwright keyboard/screen-reader smoke; cross-browser responsive checks; unit tests for format, capacity, step transitions; no fake successful writer. Inspect click targets and contrast on iPhone-width layouts.

**Exit gate:** UI is buildable and screenshots reflect the running code. Start is disabled until a capability-qualified agent and confirmed safe target exist.

## Phase 2 — Protocol and Windows agent bootstrap

**Work:** Create `apps/agent` in Rust (Tokio) and `apps/web` for the current frontend; define a stable `packages/contracts` OpenAPI/JSON Schema interface or generate TS bindings from Rust schemas. Start the agent with a loopback-only listener, never `0.0.0.0`. Advertise current protocol version, installed agent build, OS, supported capabilities, health, and session policy.

**Pairing/security**
- Initial pairing requires a local native OS interaction, time-limited one-time code and clear website identity.
- Origin allowlist is scoped to the installed application's website origin or developer loopback endpoints.
- Per-session CSRF-resistant bearer/DPoP-style proof or an equivalent explicit design; short TTL, replay resistance, no wildcard CORS.
- Reject localhost DNS rebinding and non-loopback connections; verify `Host`, `Origin`, remote peer and scheme semantics.
- Avoid exposing write operations via GET, WebSocket cross-origin upgrades, ambient cookies or unauthenticated local endpoints.
- Browser local-network/private-network permission behavior must be tested across supported Chrome/Edge/Firefox versions rather than assumed.
- Native launcher/offline UI fallback is required if browser localhost policy blocks the hosted origin.

**Agent API v1 proposal**
```text
GET    /v1/health                -> status, platform, protocol_version
GET    /v1/capabilities          -> versioned capability manifest
POST   /v1/pair/begin           -> expiring pairing challenge
POST   /v1/pair/complete        -> scoped browser-session grant
GET    /v1/devices              -> non-sensitive candidate devices
POST   /v1/images/inspect       -> local file handle / agent-side path identity
POST   /v1/jobs/preflight       -> signed/expiring preflight result
POST   /v1/jobs                 -> idempotent confirmed job request
GET    /v1/jobs/{id}            -> authoritative state/snapshot
GET    /v1/jobs/{id}/events     -> event stream with replay cursor
POST   /v1/jobs/{id}/cancel     -> bounded cooperative cancellation
GET    /v1/jobs/{id}/report     -> outcome and verification evidence
```
No disk access from a browser alone; file handles selected in the browser are not automatically trusted native paths. Design the local-data transfer protocol to stream chunks on localhost (no cloud) or select image files using a native OS picker with explicit consent. Validate canonical paths, symlinks, hardlinks and file replacement at operation time.

**Exit gate:** No privileged process runs for ordinary health/device GET; origin, nonce, replay, and permission tests pass.

## Phase 3 — Trusted device inventory and authorisation

**Work:** Implement Windows device inventory using SetupAPI, storage device IOCTLs, volume mapping and stable identifiers. Return internal/fixed/removable heuristics and known mountpoints without exposing sensitive files. Treat removability as a hint: USB-attached storage can report as fixed.

**Operation-level safeguards**
1. Enumerate disks with stable identity (instance ID, physical index, serial where available, capacity, bus and volume relationships).
2. Exclude OS boot/system disks, their parents, and currently mounted essential volumes from any write candidates.
3. Obtain exclusive access, flush and unmount affected volumes through an elevated helper.
4. Resolve the target again immediately before opening the block device; re-evaluate identity, device generation, size and boot/system mapping.
5. Require a separate confirmation that includes *device model, capacity, stable suffix, erase warning*.
6. Bind consent to the specific device identity + image digest + intended partition plan + expiry; refuse stale approvals.
7. If ambiguous (enclosure identity changes, multiple matching serials, hot swap, OS disk uncertainty), stop and request re-selection.
8. Never rely solely on `PhysicalDriveN` indices or a checkbox labelled "show fixed disks".

**Exit gate:** Unit and hardware tests prove the OS disk cannot be selected by accidental index reuse, drive removal/reinsertion, misleading device metadata, or changed volume topology.

## Phase 4 — Transactional job engine and write journal

**Work:** Implement durable SQLite job state with monotonic events and atomic lifecycle transitions: `CREATED -> PREFLIGHTED -> WAITING_FOR_CONSENT -> LOCKING -> PREPARING -> WRITING -> FLUSHING -> VERIFYING -> SUCCEEDED`; cancellation and failures land in explicit terminal states. Persist before each irreversible operation.

**Contracts:** Job ID, idempotency key, source image digest, target identity fingerprint, capability set, created/updated timestamps, phases, bytes completed, rolling hash, stream retry counters, warning codes, scrubbed error details, and native helper exit report. Stream events over SSE/WebSocket with increasing cursor and snapshot replay after disconnect.

**Cancellation:** Always stop writes cooperatively, flush safely when possible, unlock resources in a guaranteed cleanup path, and mark media incomplete. A cancelled write may still leave the drive unusable and must never be shown as "restored".

**Failure injection:** USB disconnect, 0-byte write, short write, EIO, access denied, write-protect, locked volume, sleep/wake, insufficient capacity, power failure, process crash, and agent restart.

**Exit gate:** A job cannot be reported `SUCCEEDED` without successful flush and configured verification, and a restarted agent can reconstruct an honest terminal or resumable state.

## Phase 5 — First end-to-end writer: raw images

**Work:** Support directly writable IMG/DD and uncompressed raw images using bounded buffered or aligned I/O. Record source/target size; reject images larger than the device. Enforce a single writer per device, bounded retries on transient errors, and speed calculations based on monotonic timing.

**Verify:** Hash source as it is read, flush target, read back written bytes, and compare to source using a verified strategy. For a media writer, a successful source checksum alone does **not** prove the target was written correctly. Expose exact verification coverage and status in the final report.

**Performance:** Buffer sizing and I/O concurrency controlled by media characteristics; avoid random writes and memory-mapping untrusted multi-GB sources by default. Define measured throughput baselines across USB2, USB3 and SSD bridges only after physical profiling.

**Exit gate:** Physical image write/read-back validation passes on representative flash drives; no desktop system disk ever changes in test runs.

## Phase 6 — Partition layout and filesystem creation

**Work:** Implement or integrate MBR and GPT partition table operations, protective MBR, GPT backup header and CRC validation, alignment, and partitions required for BIOS/UEFI. Introduce a layout planner that emits a reviewable operation plan **before** execution. Add FAT16/FAT32, NTFS, exFAT, and any additional filesystems only with verified OS tool/driver licensing and interoperability.

**Disk plan example**
```json
{
  "target": "stable-device-fingerprint",
  "partitionScheme": "GPT",
  "bootMode": "UEFI",
  "filesystem": "FAT32",
  "layout": [{"kind": "efi-system", "size": "computed"}],
  "requiresErase": true,
  "verification": "full-readback"
}
```
Treat a layout plan as untrusted until recomputed and signed by the local agent; browser fields can request preferences, not authorise raw disk operations.

**Exit gate:** Test partitions are mountable on target Windows and firmware; corruption and out-of-range layouts are rejected before writes.

## Phase 7 — ISO classification and UEFI/BIOS paths

**Work:** Inspect ISO9660/UDF metadata; enumerate boot catalog entries, EFI payloads, partition images, Windows install media, Linux bootloader layouts and architecture. Differentiate hybrid ISO raw-write from extraction/copy workflows.

**Boot targets**
- UEFI GPT/FAT32; multi-file extraction; large-file handling if install media exceed FAT32's file limit.
- UEFI/NTFS boot integration for appropriate targets with Secure Boot provenance/compatibility review.
- Legacy BIOS/MBR with boot sector/bootloader installation when supported.
- Explicit combinations of architecture, firmware, partition scheme, filesystem and boot mode.

**Testing:** QEMU/OVMF and real hardware using clean Windows installer ISOs and tested Linux distributions; UEFI Secure Boot enabled/disabled; older BIOS machines. A QEMU boot alone does not equal physical hardware coverage.

**Exit gate:** Every supported image/firmware row has a reproducible boot report; unsupported layouts fail with actionable reason.

## Phase 8 — Windows install media and customisation

**Work:** Add Windows ISO acquisition through official, license-compliant sources; WIM/ESD metadata and multiple-image indexes via `wimlib` or equivalent; split `install.wim` where needed. Create Windows installation customisation workflow: local account settings, region/time, privacy, hardware-check options, and installer compatibility constraints.

**Important:** Document OS build applicability, Microsoft licensing, enterprise requirements and the risk of unsupported upgrade/bypass features. Treat TPM/Secure Boot/RAM setup-check modification as an opt-in *installer customisation*, never an assurance of hardware compatibility, support, updates or licensing. Never distribute Microsoft binaries in BootNexa.

**Exit gate:** Install media is bootable and tested to an actual Windows setup environment; modifications validated against supported Windows releases and kept optional.

## Phase 9 — Linux media and persistence

**Work:** Support hybrid ISOs, distribution-specific extraction, GRUB/Syslinux configurations, persistence partitions/files and boot-time kernel parameter modification where the target distribution supports it. Linux persistence must be gated by a distro + release compatibility registry rather than a universal toggle.

**Matrix:** Ubuntu LTS, Debian stable, Fedora current, plus known unsupported distributions. Add architecture/UEFI/Secure Boot differences per image. Incorporate signed bootloaders only under compatible licensing and verified supply chains.

**Exit gate:** Boot, data persistence across reboot and failure cases tested for each advertised profile.

## Phase 10 — Advanced image formats and backup/restore

**Work:** Stream gzip/xz/zip compression formats with decompression bombs defended by output-size and memory limits. Add VHD/VHDX/FFU read/write with format-specific parsers, sparse allocation, metadata integrity, and extensive hostile-input fuzz testing. Implement drive-to-image backups without image upload, with free-space preflight, provenance and optional encryption chosen by the user.

**Exit gate:** Full/partial write failures cannot overwrite destination image backups silently; image exports reimport correctly in round-trip tests.

## Phase 11 — Diagnostics, checksums and media health

**Work:** Compute MD5/SHA-1 for compatibility display only; SHA-256/512 for integrity decisions. Add SMART where available, block read tests, write-read destructivity warnings, capacity validation, fake media indicators, bad-block testing and report export. Diagnostic destructive passes need a separate explicit consent flow distinct from imaging consent.

**Exit gate:** Health and capacity claims report limits of measurement and are not based on one heuristic.

## Phase 12 — Agent lifecycle, signing and updates

**Work:** Signed Windows installer, least-privilege service/helper, code-signed binaries, binary and update manifest verification, rollback to previously trusted agent, updater staging and anti-downgrade policy. Explicit supported version ranges between the web app and native agent; show helpful "update required" prompts without bypass paths.

**Exit gate:** Supply-chain verification, tampered updater, unsigned binary, interrupted upgrade and rollback tests pass. No updater can trigger disk writes.

## Phase 13 — Observability and supportability

**Work:** Local event log, structured error codes, diagnostic export that strips identifiers and private paths by default, opt-in crash reporting, actionable help articles, compatibility matrix provenance and support bundles. No compulsory cloud accounts or telemetry for core bootable-media creation.

**Exit gate:** A maintainer can reproduce test failures from redacted operation metadata without receiving private ISO contents or storage volumes.

## Phase 14 — Release automation and quality matrix

**CI gates**
- TS/Rust lint, strict typecheck, unit/component tests and dependency/license scanning.
- Signed release provenance, reproducible build metadata, SBOM, vulnerability review.
- Protocol compatibility tests across browser/agent versions.
- Property-based tests for partition geometry and size arithmetic; fuzz ISO/archive/FFU/VHD parsing.
- Agent security suite: origin, CSRF, Host, DNS rebinding, symlink, injection, token replay, cross-user and scope confusion.
- UI tests: Playwright main flows, screen-reader/keyboard, narrow layouts, high contrast, motion preference, light/dark screenshot regression.
- VM boot smoke: QEMU/OVMF targets; virtual block devices never mistaken for host physical disks.
- Dedicated physical hardware lab runs using sacrificial drives only, segregated from CI runner system disks.

**Exit gate:** Release is blocked on any untriaged destructive-operation or auth defect; build-only green is insufficient.

## Phase 15 — Public 1.0 and cross-platform programmes

**1.0 ship criteria**
- All **P0** rows in the feature matrix qualify on Windows x64 with recorded test artifact(s).
- Writer safety audit and signed Windows distribution are complete.
- Recovery, cancellation, agent restart and unplugging are exercised on physical devices.
- Support documentation covers failures, UEFI/BIOS choices and Windows 11 installer-specific claims.
- License review covers all bundled binaries, bootloaders and copied code.

**Linux agent:** UDisks2, udev, polkit/privileged worker boundary, device-mapper and mount namespace constraints; validate each distribution and GUI packaging target independently.

**macOS agent:** Disk Arbitration, IOKit/DriverKit as appropriate, authorisation services, filesystem support limits, notarisation; avoid promising native Windows installer-media fidelity until proven.

**ARM platforms:** Treat ARM64 Windows and RISC-V boot as separate architecture/firmware matrices rather than silent extrapolations.

## Workstreams and repository structure

```text
bootnexa/
├── apps/
│   ├── web/                 # React web application (move root preview here in Phase 2)
│   └── agent/               # Rust local service and signed distribution
├── crates/
│   ├── bootnexa-core/       # Plans, image metadata, jobs and errors
│   ├── bootnexa-device/     # Cross-platform device models/interfaces
│   ├── bootnexa-windows/    # Windows native discovery and privileged I/O
│   ├── bootnexa-images/     # Format parsers, stream readers and checksums
│   └── bootnexa-policy/     # Consent, allowlists, device safety rules
├── packages/
│   └── contracts/           # Versioned TS+Rust protocol types
├── assets/                  # Brand and verified product screenshots
├── doc/                     # Specifications, roadmaps and threat model
└── .github/workflows/       # Web build and future native gates
```

Keep the initial root Vite app until the agent integration requires the monorepo. Migrating too early only creates build overhead.

## Stable interfaces and product boundaries

### Browser ↔ agent

The web app sends a high-level request: requested image, target candidate, boot preferences, preflight token and scoped confirmation. The agent independently validates and expands these into a concrete privileged disk plan. **The browser never supplies arbitrary disk paths or raw device handles directly to the elevated helper.**

### Agent ↔ privileged helper

Use a small RPC surface with OS-native ACLs and attested caller identity. The helper accepts signed, expiring, single-use plan identifiers issued by the unprivileged agent after consent, rather than freeform shell commands. Device identity must be rechecked inside the helper. Per-device leases prevent concurrent writers, diagnostic scans and backup jobs from racing.

### Capability negotiation

Each UI control is conditional on agent-advertised verified capabilities; unsupported inputs remain explainable but unavailable. Device and image compatibility must be determined by the backend, not solely frontend string matching.

## Risk register

| Risk | Severity | Primary mitigation |
| --- | --- | --- |
| Erasure of OS/internal disk | Critical | Identity binding, system disk exclusion, exclusive lock, separate consent, in-helper revalidation |
| Browser-to-localhost exploitation | Critical | Pairing, origin/host/peer validation, short-lived scoped credentials, CSRF/rebinding tests |
| Malicious or malformed ISO/archive | High | Isolated parsers, size limits, fuzzing, no shell interpolation |
| Secure Boot and UEFI variance | High | Signed bootloader provenance, architecture-specific boot matrix |
| GPL and third-party code obligations | High | Legal review before Rufus/wimlib/bootloader integration and redistribution |
| Power-loss/unplug mid-write | High | Durable journal, incomplete-media state, safe resource release, explicit retry |
| Incorrect Windows compatibility statements | Medium | Tested OS builds, opt-in modifications, no update or support guarantees |
| Feature bloat before safe writer | High | P0 vertical slice and verified hardware gate before P1 expansion |
| Browser-origin restrictions | Medium | Desktop loopback testing, signed desktop launch fallback |
| Agent updater compromise | Critical | Signed artifact/metadata verification, pinned trusted keys, rollback policy |

## Definition of done for every capability

A feature is **qualified** only after a written spec, threat assessment, implementation, automated unit/integration tests, at least one suitable real-device or boot test, accessibility text, failure-mode documentation, telemetry/redaction review, and a linked evidence report. UI existence, demonstration screenshots, and passing TypeScript builds are not evidence of disk functionality.

## Initial issue backlog (suitable for GitHub milestones)

1. `web: establish design tokens and screenshot baselines`
2. `contracts: define agent v1 schema and capability negotiation`
3. `security: author loopback pairing and hostile-origin test harness`
4. `agent: Windows discovery with protected-system-disk classification`
5. `agent: preflight plan + device identity revalidation`
6. `jobs: SQLite journal and replayable event transport`
7. `images: raw streaming writer + full read-back verify`
8. `qa: sacrificial hardware harness and unplug/failure suite`
9. `images: ISO metadata and boot-path classification`
10. `boot: UEFI FAT32 + GPT boot matrix`
11. `boot: BIOS MBR boot matrix`
12. `windows: WIM/ESD, FAT32 large-file strategy`
13. `linux: hybrid ISO profiles and persistence compatibility`
14. `release: sign Windows installer and agent update chain`
15. `docs: publish evidence-backed parity report and 1.0 readiness gates`

## Source references

- Rufus homepage, release history and licence: https://rufus.ie/
- Rufus source and issues: https://github.com/pbatard/rufus
- Microsoft Windows storage APIs and device IOCTLs: https://learn.microsoft.com/en-us/windows/win32/fileio/disk-management
- WebUSB limitations and browser support: https://developer.mozilla.org/en-US/docs/Web/API/WebUSB_API
- Windows Imaging (WIM): https://wimlib.net/
- UDisks2: https://storaged.org/doc/udisks2-api/latest/
- UEFI specification: https://uefi.org/specifications
