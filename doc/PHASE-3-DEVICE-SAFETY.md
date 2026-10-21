# Phase 3A — Windows device safety foundation

**Scope:** read-only candidate inventory, opaque identity, and fail-closed boot/system classification. **No disk-write authority is created.**

## Implemented

- Enumerate Windows storage using a fixed PowerShell script executing `Get-Disk` and read-only `Get-Partition`. There is no shell interpolation, raw disk handle, volume dismount, format, or write command.
- Ignore every disk not explicitly marked `USB`, and every disk marked boot/system, offline, or zero capacity.
- On each USB disk, inspect partitions for `IsBoot` and `IsSystem`. If partition inspection fails or is unavailable, exclude that drive instead of assuming it is safe.
- Require both a storage path and at least one of serial or storage unique ID for candidate display. Missing/ambiguous identity is excluded.
- Reject duplicate disk indices and duplicate composite identities within an inventory response.
- Build per-agent-process salted SHA-256 opaque display IDs from the composite identity and capacity, **never from `PhysicalDriveN` alone**. The same drive retains its display ID when the disk number changes, whereas replacement at the same disk number produces a different ID. IDs rotate after an agent restart. The browser receives no raw storage path, serial, or disk index.
- Preserve existing loopback-only transport, origin-bound read-only session, user approval, failure and timeout handling. All disk-writing capabilities remain disabled.

## Why this is only a preliminary inventory

The Windows Storage object properties are not authoritative proof that a volume can be erased. USB-attached boot devices, multi-disk bridges, SAN/virtual arrangements, ambiguous PnP paths, cloned serial numbers, pagefile/crashdump volumes, or dynamically changed volume mappings may present misleading metadata. A read-only inventory pass does **not** certify device safety.

A future **privileged writer** must **not accept these browser display IDs as write targets**. Before permitting any destructive operation, it must:

1. Re-enumerate the physical device using SetupAPI/Configuration Manager and storage IOCTLs, recording stable interface/instance ID, bus, serial, capacity and full storage/volume ancestry.
2. Map all partitions and extents, including dynamic volume mappings, mountpoints, boot/system/pagefile/crashdump relationships, virtual/BitLocker/VHD backing and other protected dependencies.
3. Require exact, unique and consistent device identity under a bounded in-process generation and a privileged recheck after lock acquisition.
4. Require a device-specific destructive approval bound to the immutable plan, image digest, disk fingerprint and expiry. Browser choices and remembered read-only approval are insufficient.
5. Abort on unplug/hot-swap, index reuse, duplicate identity, topology change, mismatch, write-protect, missing metadata or uncertain ownership.
6. Keep privileged operations unavailable in this milestone and defer real hardware qualification until representative Windows USB media can be tested.

## Verification

`cargo test --locked --all-targets` exercises same-device index renumbering, index reuse by another device, restart salt rotation, missing identity, duplicated identifiers, USB boot/system flags, protected partitions, failed partition metadata, offline/empty disks, malformed responses and response limits.

The normal CI Windows job additionally runs the **real** Windows `Get-Disk` and `Get-Partition` discovery path on a hosted Windows virtual machine. This confirms script/serialization compatibility, not actual physical USB hotplug safety.

The browser's `Start writing` button remains disabled; writing/erase/format API routes remain absent.

## Acceptance boundary

**Development foundation:** test and Windows CI green on exact merged SHA.

**Not qualified:** full Phase 3 privileged operation safety, real USB ancestry/hotplug checks, physical destructive acceptance, actual interactive consent on Windows hardware, public code signing (tracked in issue #5).

Next is **Phase 3B: read-only image inspection and signed/expiring preflight design**, followed by **Phase 4: durable job journal**. Image writing stays disabled until the isolated virtual-media tests and independent privileged safety checks are complete.
