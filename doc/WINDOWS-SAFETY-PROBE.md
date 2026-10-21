# Windows safety probe and future privileged-helper design

**Implemented:** Independent, read-only `bootnexa-safety-probe.exe` and fail-closed Rust identity/topology policy. **Not implemented:** Elevated service, named-pipe broker, destructive plan approval, volume dismount, disk locking, partitioning or raw block writing.

## Architecture and isolation

~~~text
Browser (untrusted preferences, read-only token)
   |
   v
BootNexa Agent (per-user, unprivileged, loopback read-only APIs)
   |  DISPLAY inventory only
   +-- bootnexa-safety-probe.exe [developer/CI executable, NOT installed]
          |  fixed, read-only PowerShell Get-Disk / Get-Partition /
          |  Get-Volume / Win32_DiskDrive / Win32_OperatingSystem /
          |  Win32_PageFileUsage
          v
       2 immutable in-memory Windows storage snapshots
          |
          v
       Strict Rust comparison and risk report
          |
          +-- ALWAYS physicalWriteAuthorized=false
~~~

The probe is compiled as a **separate Rust binary** but is **not an elevated helper** and **is not distributed by the per-user Windows installer**. It receives no target disk number, file path, write plan, UAC authority, credentials, or device handles. Its only CLI action is `--probe`, which enumerates the whole inventory without destructive operations. It is not registered as an HTTP route, system service, startup task or scheduled job. It does not open physical disk handles.

The probe uses fixed, non-interpolated Windows Storage and CIM commands. The two samples are collected independently with a short delay, and the second is checked for changes to disk index, bus type, size, PnP identifier, Win32 device path, Windows Storage path, unique/serial fields, partition numbers, volume identifiers, mountpoint paths and protection flags. Evidence is bounded (1 MiB JSON, at most 128 disks and 128 partitions per disk), schema-validated, and rejects unknown fields. Missing provider information is a risk, **not** proof of an empty disk.

The report contains fixed risk codes, disk number and short randomized diagnostic pseudonyms, without exposing serials, PnP paths or mountpoint strings. PnP-instance reuse, duplicate indices and duplicate composite identities are rejected. None of these identifiers is claimed globally unique or immutable: cheap USB bridges can spoof them, OS numbers may be recycled, and topology may change after a probe.

The current PowerShell provider **cannot attest all native multi-disk volume extents** and does not fully certify hibernation/crashdump roles. Therefore the probe deliberately sets `VolumeExtentsComplete=false` and `ProtectedRoleEvidenceComplete=false` for every live result. The report flags `native_volume_extents_unverified`; it must never be interpreted as a write authorization even if the identity itself is stable.

## Proposed future elevated broker (design only)

A subsequent, separately reviewed and publicly trusted **signed** broker would have to:

1. Run under narrowly scoped UAC elevation or a verified supported service, with strict per-user SID ACLs on a local named pipe. Reject untrusted callers, anonymous handles, unrecognized binaries, remote pipe access and unversioned messages.
2. Authenticate the invoking per-user agent and negotiate a short-lived, one-request capability bound to a random nonce, process session, exact helper version, operation, expected image SHA-256 and read-only preflight evidence. Do not pass the current `devices:read` token as write authority.
3. Enumerate SetupAPI device instances and device interfaces **inside** the broker, then validate physical device identity using Storage IOCTLs. Walk physical disk/partition/volume extents, Windows boot/system/pagefile/crashdump/hibernation, Storage Spaces/dynamic and other parent/child relationships, with unverified elements excluded.
4. Produce a bounded, canonical *proposed* operation plan (target generation, byte capacity, image digest, exact operation and intended partitions), then require a native, foreground **device-specific destructive consent**. Consent is one-shot, expires, and is invalidated by any topology drift.
5. Re-enumerate under broker authority and compare the plan again immediately before acquiring the device. Open only that exact physical target, enforce exclusive device/volume locking and no system-disk ancestry, and abort on USB replacement or index reuse.
6. Introduce disk mutation, actual device cache flush, read-back verification, cancellation and journaled recovery **only after** security review, sacrificial hardware acceptance and release-code-signing qualification. Until then the broker must have no write opcode or write-access handle.

Proposed future IPC message classes: `GetReadOnlySafetyReport`, `PreparePlan`, `RequestDestructiveConsent`, `ExecuteSignedPlan`, and `GetEvidence`. **Only the first exists conceptually today; no IPC listener or elevated broker is implemented.** A browser must never directly access these IPC messages.

## Tested now

- Pure Rust negative fixtures for disk index reuse, changed capacity, swapped PnP identity, partition changes, protected OS volumes, unknown metadata, duplicate PnP identities, malformed/oversized/unknown JSON fields and incomplete evidence.
- A stable two-snapshot fixture proves *only* consistent read-only evidence, while `physicalWriteAuthorized` remains false.
- Windows CI builds the dedicated release executable and runs `--probe` against live Windows Storage/CIM read-only provider results. It asserts no write authority, schema version 1 and the persistent native-extent denial reason for each disk. It also verifies that new safety/write HTTP paths remain 404.
- Existing Windows native-agent smoke, CI-only signed test-installer and production-code-signing rejection remain required.

**Limitations:** Windows CI runs without sacrificial USB drives. It cannot prove real USB ancestry, protected role coverage, safe raw-disk locking or physical write/read-back. Live provider availability is a test of read-only enumeration only. No public certificate has been obtained (see [issue #5](https://github.com/heidi-dang/bootnexa/issues/5)). Hardware and destructive safety gates are tracked by [issue #13](https://github.com/heidi-dang/bootnexa/issues/13).

**Hard guarantee for this milestone:** No code changes to BootNexa's real-disk writer permissions, no privileged process, and no physical media mutations.
