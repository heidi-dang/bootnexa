# Pinned Alpine Linux virtual ISO acceptance

## Exact supported experimental profiles

The developer-only command `bootnexa-media build-alpine-virtual <ISO> <existing-output-directory>` accepts **only** the following publisher-SHA-256-pinned Alpine Linux **virt x86_64** images. Each image must exactly match **both** byte length and complete SHA-256; same filename, release family or matching file size is insufficient.

| Pinned image | Exact bytes | Exact SHA-256 |
| --- | ---: | --- |
| Alpine virt 3.24.2 x86_64 | 69,206,016 | `3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b` |
| Alpine virt 3.24.1 x86_64 | 69,206,016 | `e73a6241bd5f3c5c2d4d38c02cc52c378c0415a7c888bd292066bf36e0f41a39` |

The checksums were compared with the official Alpine HTTPS-hosted `.sha256` files. This is **not GPG-signature verification** and does not generalize to another Alpine release or distribution.

Official images: https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/
Publisher: https://www.alpinelinux.org/downloads/

The 3.24.2 virtual-OS boot-to-login result is proven by earlier CI. The newly added 3.24.1 matrix job must pass a separate real QEMU/OVMF boot-to-login CI gate before the second profile may be considered boot-qualified.

## Native preflight and virtual-only execution

Before copying any bytes, the parser enforces a read-only regular-file source, an exact pinned digest, ISO9660/El Torito UEFI boot metadata, a valid MBR with exactly one non-empty EFI System Partition type 0xEF, bounded 512-byte partition extents, and a successfully opened FAT EFI fallback application `EFI/BOOT/BOOTX64.EFI`. The FAT partition is accessed through a read-only bounded stream adapter that rejects writes and out-of-bounds seeks; the x64 bootloader must have the correct PE/COFF EFI subsystem headers.

The entire source image is then copied to an anonymous regular file in fixed 64 KiB chunks; the source, staged copy and exported new .img file must all match the expected SHA-256. The export uses `create_new` with a random filename, refuses pre-existing or non-regular output targets, and removes a newly created partial result after failures. The original ISO, disk partitions and OS drives are never written.

## CI acceptance and limitations

A two-version GitHub CI matrix downloads each exact official image, verifies the pinned digest, executes the file-backed virtual conversion and launches the output as a virtual hard disk in QEMU/OVMF using a temporary copy-on-write overlay with networking disabled. The job **must observe an actual Alpine/localhost Linux serial login prompt**, not merely an EFI header or bootloader banner. A passing test establishes boot-to-login for each individually tested image, emulator, and firmware combination; it does not prove physical USB boot or installation success.

The CI gate additionally writes a machine-readable `test-results/alpine-virtual-boot/<pinned-version>/alpine-boot-evidence.json` receipt **only after** an observed Linux login and a second full-image read-back hash after QEMU execution. The receipt contains the source revision, pinned publisher digest, OVMF firmware hash, QEMU version, serial transcript SHA-256, and explicitly false physical USB and Secure Boot qualification. Bounded emulator logs from the dedicated vendor-image test are uploaded as a short-lived CI artifact when available, but a local hand-crafted JSON receipt is not a signed attestation. A dedicated negative-test suite rejects missing login, image corruption, non-pinned profiles, boot claims from the native structural parser, symlink logs, and physical-write assertions.

All library and CLI JSON fields for physical disk authority remain `false`. The per-image report also keeps `linuxDistributionBootVerified` and `bootExecutionVerified` false because **structural validation alone cannot assert those outcomes**; only independent CI evidence can qualify the full workflow.

This does not support arbitrary Alpine versions, arbitrary hybrid ISOs, UDF/Rock Ridge extraction, Windows Setup, BIOS or Secure Boot compatibility, vendor bootloader signing, physical USB writing or publicly trusted application signing. Hardware safety issue #13 and production signing issue #5 remain open.

## Browser read-only identification

The local ISO library recognises either individually pinned release only after its own streamed SHA-256 and byte length both match the Rust and CI allowlist. The CI-gated page displays the QEMU/OVMF boot-to-login qualification as an exact-image result, not a claim of general Linux ISO or physical USB compatibility. The browser performs no disk writing, local agent mutation, downloading or installer execution. Cross-language digest, version and size consistency are checked in CI.
