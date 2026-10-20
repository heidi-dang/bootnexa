# Feature compatibility ledger

This file is the public record for supported, planned and explicitly unsupported behaviour. It is **not** a claim that BootNexa already matches Rufus.

**Baseline:** Rufus 4.15, 30 June 2026. Source: https://rufus.ie/ and https://github.com/pbatard/rufus. The ledger must be reconciled against upstream release notes, source and hardware tests at each BootNexa release.

**States:** `Preview` = visual interaction only; `Planned` = no implementation; `Development` = code exists but not qualified; `Qualified` = evidence-linked hardware/VM tests; `Limited` = explicitly constrained platform/version.

| Area | Capability | Target milestone | Current state | Minimum verification |
| --- | --- | --- | --- | --- |
| Web experience | Responsive workspace, dark/light theme, navigation | 0.1 | Preview | Build and browser interaction |
| Images | Local ISO/IMG/VHD/VHDX/FFU file picker | 0.1 | Preview | Browser File API, no upload |
| Images | ISO content/OS metadata inspection | 0.4 | Planned | Fixture corpus + malformed input |
| Devices | Live USB discovery and removable/fixed classification | 0.2 | Planned | Multi-drive Windows matrix |
| Devices | Stable identification, system disk protection, hot-swap defence | 0.2 | Planned | Destructive safety fixtures |
| Operations | Agent pairing, local origin enforcement | 0.2 | Planned | Threat model attack suite |
| Operations | Progress, recovery log, cancellation and replay | 0.3 | Planned | Injected crashes and unplug |
| Imaging | Raw IMG/DD streaming write | 0.3 | Planned | Read-back/hash test |
| Imaging | Image-to-target read-back verification | 0.3 | Planned | Real hardware |
| Partitioning | GPT/MBR layout | 0.4 | Planned | Geometry/property checks |
| Filesystems | FAT32, NTFS, exFAT | 0.4 | Planned | OS mount + boot |
| Firmware | UEFI and legacy BIOS boot media | 0.4 | Planned | OVMF + physical firmware |
| Firmware | Secure Boot-compatible boot configurations | 0.5 | Planned | Enabled-Secure-Boot hardware |
| Windows | Windows 10/11 USB installation media | 0.5 | Planned | Setup boots |
| Windows | Windows 11 setup customisation | 0.5 | Planned | Version-specific compatibility |
| Windows | Multiple WIM images and large install.wim handling | 0.5 | Planned | Media extraction and setup |
| Windows | Windows To Go | 0.7 | Planned | Portable installation tests |
| Linux | Hybrid ISO and distro-specific file extraction | 0.6 | Planned | Ubuntu/Debian/Fedora |
| Linux | Persistent installation data | 0.6 | Planned | Reboot persistence |
| Bootloaders | GRUB, Syslinux, UEFI:NTFS | 0.6 | Planned | Boot matrix + licence review |
| Bootloaders | FreeDOS/MS-DOS support where redistributable | 0.7 | Planned | Boot media and distribution rights |
| Compressed | gzip/xz/zip sources | 0.6 | Planned | Streaming limits and fuzz corpus |
| Advanced | VHD, VHDX, FFU read/write and backup image export | 0.7 | Planned | Round trip, fuzz + media |
| Advanced | Additional specialised filesystems | post-1.0 | Planned | Per-platform support |
| Diagnostics | MD5, SHA-1, SHA-256, SHA-512 hashes | 0.7 | Planned | Known vectors |
| Diagnostics | Bad blocks, capacity fraud, write/read health | 0.7 | Planned | Known-fault fixtures |
| Downloads | Official Windows ISO acquisition pathways | 0.5 | Planned | Source and licence validation |
| Platform | Windows 10/11 x64 native agent | 0.2–1.0 | Planned | Signed build + hardware suite |
| Platform | Linux native agent | 1.x | Planned | distro/polkit/udev matrix |
| Platform | macOS native agent | 1.x | Planned | Disk Arbitration/permissions |
| Platform | ARM64 / alternative architectures | 1.x | Planned | Architecture-specific tests |

## Parity audit procedure

1. Pin a Rufus release and tag in a compatibility audit issue.
2. Review official changes, source toggles and documented advanced behaviours.
3. Link every requirement to an internal issue and owner.
4. Implement with a written, OS-specific compatibility constraint.
5. Attach unit, integration and hardware evidence before changing state to `Qualified`.
6. Publish a release summary listing gaps and unsupported combinations.

Any feature not marked `Qualified` is not production-supported, regardless of whether its controls are visible in the UI. In particular, the initial repository cannot erase, partition, format, or flash a disk.
