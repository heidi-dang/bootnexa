# Protected-volume ancestry and read-only helper protocol

**Milestone:** protected-volume risk propagation and a **test-only** authenticated protocol contract. There is **no elevated broker, named-pipe listener, process attestation, disk access, or write authority**.

## Protected-volume ancestry

The Rust analyzer in `agent/src/protected_ancestry.rs` cross-references two independent Windows Storage/CIM observations with two native SetupAPI/Storage-IOCTL volume-extent observations. It builds a disk-to-disk connectivity graph: when any volume spans multiple parent disks, every parent belongs to the same connected component. A boot/system disk or a partition marked boot, system or OS-protected makes *all connected parent disks* potentially protected. This is a conservative overapproximation, not a claim of complete Windows device identity.

Report fields include the disk number, whether protection was directly observed, whether it propagated from a shared volume, fixed sanitized risk codes, whether observations agree, and whether role evidence is complete. `ancestryVerifiedForWriting` and `physicalWriteAuthorized` **always remain false**, even for apparently consistent graphs.

The following conditions fail closed rather than being interpreted as permission: missing native volume extents, unknown parent disks, duplicate or drifting disk identities, incomplete Windows partition or role information, inaccessible volumes, mixed-disk extents and missing storage interfaces. The existing live PowerShell collector correctly reports `ProtectedRoleEvidenceComplete=false` because crashdump and hibernation relationships are not authoritatively attested. Consequently, production Windows observations must continue returning `protectedRoleEvidenceComplete=false` and `protected_roles_unverified`, including for USB devices that appear otherwise safe. **Do not use this module as an allowlist for writing.**

## Authenticated helper protocol — test-only contract

A separate Rust module `agent/src/helper_protocol.rs` is compiled **only for Rust tests**. This is intentional: there is not yet a trustworthy Windows named-pipe transport or authenticated process identity. The proposed wire envelope has strict JSON schema, version 1, a single read-only operation `read_only_safety_report`, short-lived challenge nonce, caller identity binding, expiry and HMAC-SHA256 proof. Verification rejects oversized messages, unknown fields, unsupported versions or opcodes, replay, tampering, expired/future requests and wrong identity bindings. Successful requests are single-use.

The protocol test creates a synthetic trusted peer and confidential key **within the test harness**; this is not Windows security attestation. HMAC alone cannot protect a broker if the calling process can obtain the key or impersonate a claimed SID.

A future real Windows broker must FIRST:

- be properly code-signed, least-privileged and narrowly scoped to the specific host user;
- create a local-only named pipe with restrictive SECURITY_DESCRIPTOR / SID ACL, prohibit remote clients, authenticate Windows token and process signature over the actual pipe connection via verified OS APIs, and bind a confidential secret to that channel;
- enforce hard message-size limits, version/downgrade rejection, single-use challenges and short timeouts;
- expose only a **read-only safety report** operation during first qualification, with no physical disk open-for-write, mounting, locking, format, partition or other destructive opcode;
- revalidate the underlying protection graph inside the broker and reject ambiguity, impersonation, disk number reuse and hot swap;
- undergo fresh Windows native/security CI, independent review and sacrificial hardware negative-case acceptance before any separately authorized destructive functionality is introduced.

**This milestone does not implement these future transport/security steps.** No caller can currently acquire a broker privilege, and the browser's existing read-only token is not a helper authorization.

## Regression evidence

- Synthetic multi-disk volumes propagate boot/system/partition protection transitively.
- Missing native extents, foreign parents, snapshots with changed disk size or topology, and unverified crashdump/hibernation role evidence are blocked.
- Versioning, MAC tampering, wrong identity, expired challenges, replay, unknown fields, and all attempted write/erase/prepare-plan opcodes are rejected in test-only protocol fixtures.
- On Windows CI, the separate development probe still uses zero-desired-access handles, validates and publishes only redacted read-only findings, and the end-user test installer does not include an elevated helper.
- Windows installer acceptance, production signing fail-closed checks and all browser smoke tests remain required.

Tracking remains open: <https://github.com/heidi-dang/bootnexa/issues/13> for hardware/authority safety and <https://github.com/heidi-dang/bootnexa/issues/5> for public code signing. Never infer physical USB readiness from these simulated or observational tests.
