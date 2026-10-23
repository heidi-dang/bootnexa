# Phase 8 — Windows installation ISO preflight and virtual CD-ROM staging (experimental)

## Implemented, verified scope

`bootnexa-media inspect-windows-iso <ISO>` reads a **local regular file** and emits a metadata-only JSON envelope. It walks the primary ISO9660 tree with bounded depth (8), directory sizes (1 MiB), entry count (4096), path/extent validation and strict rejection of multi-extent, interleaved, Rock Ridge/SUSP, duplicate, overlapping or ambiguous directory records. Large WIM file extents can be examined **without** widening the previous small EFI extraction caps. The two APIs remain independently gated.

The Windows-specific classifier reads at most a WIM/ESD header per named file: `SOURCES/BOOT.WIM` plus either `SOURCES/INSTALL.WIM` or `SOURCES/INSTALL.ESD`. It checks MSWIM magic, a limited supported format version, header bounds, image-count sanity and rejects spanned archives. It verifies the x64 PE/COFF EFI subsystem header of `EFI/BOOT/BOOTX64.EFI`, presence of `SETUP.EXE` and an El Torito UEFI catalog, and observes UDF Volume Recognition Sequence signatures. **The metadata-only Windows Setup candidate check is not authentication, format-complete WIM parsing, Windows version identification, installer installation or guest boot evidence.** Synthetic fixtures can pass it by design.

`bootnexa-media stage-windows-virtual-cdrom <ISO> <existing-real-directory>` requires the candidate gates to pass and refuses UDF-recognised images until a separately reviewed UDF parser exists. It copies the entire source ISO in bounded 64 KiB chunks into a **new randomly named regular `.iso` file**, synchronizes output, independently hashes the source before/after copying and verifies the staged file by full SHA-256 read-back. It refuses symlink output directories, does not overwrite an existing output, and removes newly created partial outputs after failures. The output is a **virtual optical-disc image** and is NOT a GPT/FAT32 USB disk or a Windows installer. It can only be attached as an optical image to a VM in future tests.

The browser's local ISO library now shows Windows primary-directory payload type/bytes and a UDF recognition warning, while refusing any physical disk writer or Windows OS boot claim.

## Verified tests

- Synthetic MIT/open-source-only ISO9660 with x64 EFI-formatted stub, `SETUP.EXE` placeholder and fabricated WIM headers; no Microsoft binary or Windows image is shipped.
- Header corruption, spanned/zero-image WIM, tampered x64 EFI, incomplete Windows layout, UDF recognition (fail-closed staging), and symlink destination denial.
- Regular-file optical-image copy with three SHA-256 checks and unchanged source; 64 MiB sparse WIM extent is inspected without relaxing small virtual EFI extraction limits.
- Rust unit tests, browser Playwright UDF/Windows limitations, GitHub's Linux native preflight CI.
- **No real Microsoft Windows Setup boot has been attempted or proved in this test corpus.** A successful synthetic UEFI boot elsewhere in the repository is NOT a Windows Setup boot.

## Remaining to complete Phase 8

1. Build a bounded, fuzzed UDF directory translator (UDF 1.02/2.01 variants) with version/extent/metadata checks and cross-validate any ISO9660 and UDF directory-tree discrepancies. Recognizing an NSR signature is insufficient.
2. Verify actual `boot.wim` and `install.wim`/`install.esd` using a qualified WIM/ESD decoder (including compression methods, WIM resource integrity, image indexes, version and edition, encrypted ESD and multi-part cases). This phase only validates the fixed-size outer header.
3. Design the actual FAT32+NTFS Windows Setup virtual **USB disk** layout and a safe verified split-WIM (`install.swm`) or other proven UEFI strategy for files larger than FAT32's 4 GiB minus 1 byte maximum. Do not blindly copy oversized files to FAT32.
4. Obtain Windows ISO through [Microsoft's official download page](https://www.microsoft.com/en-au/software-download/windows11), verify its publisher-published SHA-256 for its language and version, then test Windows Setup launch in QEMU/OVMF using a read-only virtual ISO, with guest evidence and independent post-run checks. Do not download, bundle, commit or redistribute Microsoft images from BootNexa CI without appropriate licence and provenance.
5. Add per-image Secure Boot / legacy BIOS and Windows 11 hardware requirements matrix and human-operated sacrificial physical-media acceptance *only after* separate privileged helper, protected-device identity and production signing gates.

**Physical USB writing, target-drive selection, formatting, Windows Setup customization and installer provisioning remain disabled.** The only new write path creates a regular file in a user-supplied existing directory after strict format/safety checks. No disk-device handle is ever opened for writing.
