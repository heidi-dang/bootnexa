# Pinned Alpine Linux virtual ISO acceptance

## Exact supported experimental profile

The developer-only command `bootnexa-media build-alpine-virtual <ISO> <existing-output-directory>` accepts **only** Alpine Linux virtual ISO **3.24.2 x86_64** whose image size equals **69,206,016 bytes** and whose complete SHA-256 equals:

`3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b`

The checksum was compared with Alpine's HTTPS-published SHA-256 for the release at the time of development. This is **not a GPG-signature verification** and should not be generalized to newer releases without independent review.

Publisher page: https://www.alpinelinux.org/downloads/
Version-pinned ISO: https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.2-x86_64.iso

## Native preflight and virtual-only execution

Before copying any bytes, the parser enforces a read-only regular-file source, an exact pinned digest, ISO9660/El Torito UEFI boot metadata, a valid MBR with exactly one non-empty EFI System Partition type 0xEF, bounded 512-byte partition extents, and a successfully opened FAT EFI fallback application `EFI/BOOT/BOOTX64.EFI`. The FAT partition is accessed through a read-only bounded stream adapter that rejects writes and out-of-bounds seeks; the x64 bootloader must have the correct PE/COFF EFI subsystem headers.

The entire source image is then copied to an anonymous regular file in fixed 64 KiB chunks; the source, staged copy and exported new .img file must all match the expected SHA-256. The export uses `create_new` with a random filename, refuses pre-existing or non-regular output targets, and removes a newly created partial result after failures. The original ISO, disk partitions and OS drives are never written.

## CI acceptance and limitations

A dedicated GitHub CI job downloads the exact official image, verifies the pinned digest, executes the file-backed virtual conversion and launches the output as a virtual hard disk in QEMU/OVMF using a temporary copy-on-write overlay with networking disabled. The job **must observe an actual Alpine/localhost Linux serial login prompt**, not merely an EFI header or bootloader banner. A passing test establishes boot-to-login for this one image, emulator, and firmware combination; it does not prove physical USB boot or installation success.

All library and CLI JSON fields for physical disk authority remain `false`. The per-image report also keeps `linuxDistributionBootVerified` and `bootExecutionVerified` false because **structural validation alone cannot assert those outcomes**; only independent CI evidence can qualify the full workflow.

This does not support arbitrary Alpine versions, arbitrary hybrid ISOs, UDF/Rock Ridge extraction, Windows Setup, BIOS or Secure Boot compatibility, vendor bootloader signing, physical USB writing or publicly trusted application signing. Hardware safety issue #13 and production signing issue #5 remain open.
