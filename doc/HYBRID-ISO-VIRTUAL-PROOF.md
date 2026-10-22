# Experimental dual-format ISO9660 + GPT/FAT32 virtual copy

This is a **developer-only raw-hybrid virtual-image proof**, not a general-purpose Linux ISO/USB writer. BootNexa still has no physical USB write API.

## Narrow accepted profile

The read-only source must be a regular file between 80 MiB and 256 MiB, sector-aligned and containing: (1) valid ISO9660 primary volume descriptors and El Torito UEFI boot catalog, (2) a GPT protective MBR with BootNexa's supported 512-byte geometry, primary and backup GPT headers and 128-entry arrays that pass all CRC and reciprocal-location checks, (3) a readable FAT32 EFI System Partition, and (4) the **same x64 EFI PE/COFF application** at EFI/BOOT/BOOTX64.EFI in both the ISO9660 directory tree and the FAT32 ESP. The strict bounded ISO9660 directory parser must accept the tree. These conditions are stricter than most actual Linux hybrid ISOs.

Use the developer CLI with an existing real-directory output parent:

- `bootnexa-media build-hybrid-virtual /path/to/strictly-qualified-hybrid.iso /path/to/output-directory`

The output is **only a newly created regular .img file**, generated with a unique filename. The CLI verifies the source and its metadata, copies with a fixed 64 KiB buffer into a private anonymous regular file, flushes, verifies exact full-file SHA-256, rechecks the source hash and metadata, re-qualifies the anonymous image, then copies to an exclusive new output file and hashes the entire output again. An export failure removes the newly created partial output.

It never accepts a Windows PhysicalDrive, Linux /dev disk, mounted partition or existing output file. The JSON report always states physicalWriteAuthorized=false, linuxDistributionBootVerified=false, windowsSetupVerified=false and bootExecutionVerified=false; the last flag may be promoted only by separate witnessed QEMU hardware-emulator execution, not structural validation.

## Reproducible acceptance

The synthetic test fixture is created by taking BootNexa's already-built 96 MiB GPT/FAT32 virtual disk and adding independent ISO9660 primary/boot/terminator descriptors, a valid El Torito catalog, and a small ISO9660 tree with a second copy of the EFI marker application. This creates a dual-format **synthetic** file for controlled acceptance tests. Negative fixtures mutate GPT, El Torito catalog, ISO copy of the EFI application, and FAT32 boot metadata. Each must fail before being reported eligible. Linux CI boots the copied .img under QEMU/OVMF, requiring the debug-port marker from EFI execution, with no physical device attached and a temporary copy-on-write QEMU overlay.

## Still not implemented

This **does not qualify arbitrary Linux hybrid ISOs, Windows Setup, Windows WIM splitting, UDF or Rock Ridge extraction, BIOS boot, Secure Boot, physical boot-media creation, real USB hardware, or publicly trusted signing**. Specific official OS ISO samples and firmware/hardware matrices must be separately acquired, verified and qualified before the Windows 1.0 completion estimate increases substantially.
