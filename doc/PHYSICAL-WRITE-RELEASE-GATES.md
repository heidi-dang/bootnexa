# Hard release gates for physical USB writing

**Current state: BLOCKED.** All BootNexa physical disk writing, partitioning, formatting and destructive RPC routes are still disabled/absent. No virtual-media test can substitute for hardware qualification, operating-system privileged helper review or publicly trusted Windows code signing.

## Authority and device selection contract (not implemented)

- Windows SetupAPI/Configuration Manager + appropriate Storage IOCTLs must resolve a **unique** physical storage interface, device instance ID, bus type, immutable vendor/model/serial information if reliable, current capacity, system/boot and complete partition/volume ancestry.
- Inspect every attached volume extent, mount point, paging/crashdump/hibernation/BitLocker role and storage bridge relationship. Resolve ambiguity as a hard denial, not an allowed drive.
- Independently re-enumerate inside a narrowly scoped, brokered privileged helper immediately before any write; browser-provided opaque display IDs are never physical write authority.
- Bind a short-lived, one-shot native OS destructive approval to an immutable plan consisting of image SHA-256, target fingerprint/generation, exact expected capacity and intended operation. Read-only device approval may not be reused. No silent escalation, wildcard target or permanent root/admin lease.
- Obtain an actual target-exclusive lock and safe volume dismount under normal Windows safeguards; abort on hot-swap, index reuse, mount topology drift, locked volume, a disk that acquires protected extents or any identity mismatch.
- Implement bounded raw disk I/O, valid direct-I/O alignment, actual hardware cache flush, complete target read-back and digest matching before physical SUCCEEDED. Report cancellation or interrupted media as **incomplete** even when cleanup succeeds.
- Record authoritative helper evidence and enforce explicit rollback/recovery semantics. Do not infer that a cancelled write leaves bootable media.

## Validation matrix (not yet qualified)

- Physical Windows 10/11 desktops/laptops, USB 2/3 flash, USB SSD bridges, removable hard disks, fixed disks and cloned identifiers.
- Protected system/boot/pagefile volumes and multi-volume extents, stale disk-number reuse, drive removal/reinsertion while locking, sleep/wake, access denied, read-only switch, short/zero I/O, disconnect during write/flush/verify, power interruption.
- A trusted, exact-release signed agent executable and complete installer/uninstaller with publisher identity confirmed on a clean Windows machine.
- Security review of the privileged helper's capabilities, UAC prompt, lease duration, authentication, origin protections, provenance and verified version pinning.
- Controlled, sacrificial test drives with known backups. Pass an external reviewer hardware acceptance report before production activation.

## What is currently verified

Phases 3A, 3B, 4 and 5 virtual foundation provide conservative **read-only** inventory, browser-only image analysis, SQLite simulation journaling and file-backed virtual image copying and read-back. These tests can reproduce many software faults but **cannot establish actual physical media safety**.

## Release controls

GitHub [production code-signing issue #5](https://github.com/heidi-dang/bootnexa/issues/5) stays open until a publicly trusted provider accepts the maintainer and the exact release passes native Authenticode/installation qualification. The protected release workflow must remain fail-closed without real credentials. Do not fake completion, use developer test certificates for releases or enable USB write routes in lieu of provider enrollment.

The project must not merge physical disk-write implementation into an enabled-by-default end-user agent without separate explicit review/authorization and a passed hardware acceptance matrix.
