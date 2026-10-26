# Phase 8 — Official Windows 11 ISO acceptance gate

## Trust boundary

The new read-only intake verifies a legally acquired, locally stored Windows 11 ISO against the current locale-specific SHA-256 table fetched directly over verified HTTPS from Microsoft's official Australian download page:

https://www.microsoft.com/en-au/software-download/windows11

The publisher URL is pinned in code; non-Microsoft redirects, unknown locales, absent/ambiguous checksum rows, and mismatched ISO bytes fail closed. Only English 64-bit and English International 64-bit are enabled so far. Microsoft ISO download links are typically session-specific and expire. Bootnexa does not bypass that download flow, download proprietary media automatically, or embed Windows binaries. A matching hash proves agreement with Microsoft's published bytes for that locale; it does NOT independently prove edition, release/build, license, installer compatibility, or Windows Setup boot success.

## Steps after obtaining an official image

Install a trusted 7zip executable (7z). Create a private local evidence directory and run this command, replacing the local file path with the ISO downloaded using Microsoft's website:

    mkdir -p "$HOME/bootnexa-windows-evidence"
    python3 tests/virtual-media/windows_iso_publisher_manifest.py --iso /safe/local/Win11_x64.iso --locale "English International 64-bit" --evidence-parent "$HOME/bootnexa-windows-evidence"

The intake retrieves the exact Microsoft locale row over certificate-validated HTTPS; computes the ISO SHA-256; lists all real ISO9660/UDF filesystem files with 7-Zip; streams every file directly to an SHA-256 hasher without writing file contents onto the host; hashes the complete original ISO again; and creates an access-restricted manifest.json with publisher reference URL, fetched-page hash, file sizes, full per-file SHA-256 values and failure-closed flags. The [BOOT] records shown by 7-Zip are synthetic optical boot views rather than ISO filesystem paths and are excluded from the file-name manifest; the complete-image SHA-256 still covers them.

Default limits: ISO length 512 MiB to 24 GiB, at most 4096 files, a 240-byte path budget, 16 path components, individual files up to 16 GiB, and 24 GiB of total listed file bytes. Unsafe traversal paths, symlinks, ambiguous or case-conflicting names, unrecognized ISO formats and unsupported properties fail closed. Legitimate unusual UDF media may fail these conservative checks; do not weaken the gate to force an arbitrary image through.

## Deterministic virtual installer layout feasibility (no disk write)

Once a publisher-checksum-matched ISO manifest has been captured, the read-only layout planner can produce a comprehensive **non-actionable proposal** for a GPT disk of 1–24 GiB. For example:

    python3 tests/virtual-media/windows_installer_layout_plan.py --manifest "$HOME/bootnexa-windows-evidence/<manifest-directory>/manifest.json" --disk-gib 16

The input file is only a locally saved, **untrusted snapshot** of the manifest, not a signed publisher statement. The planner checks its schema, metadata assertions, official Microsoft URL/locale/hash binding, all file paths/lengths/hashes, Windows Setup file names and FAT32 namespace collisions. It assigns EFI/ files to the **proposed 256 MiB FAT32 EFI partition**, and other installer files to the **proposed FAT32 payload partition**, with aligned GPT LBAs, filesystem headroom and conservative occupied-byte estimates. It rejects path traversal, reserved DOS device names, file-as-directory collisions and unsupported sizes. Files larger than FAT32's 4 GiB-minus-one limit are blocking, except INSTALL.WIM where **wimlib splitting is only proposed** with an illustrative 3,800 MiB part target and capacity estimate. The plan explicitly does *not* produce SWM files or verify future part sizes/hashes, nor can it convert oversized ESD. No NTFS support is assumed.

All plans report manifestAssertionsTrusted=false, virtualDiskGenerated=false, actualSplitWimArtifactsVerified=false, windowsSetupBootVerified=false, physicalWriteAuthorized=false and actionable=false. The plan remains **non-executable** even if the estimated capacity fits. True staging requires fresh Microsoft/source SHA evidence, real WIM resource verification, a qualified multi-GiB SWM conversion, filesystem image construction and independent read-back, and witnessed Windows Setup boot.

## Bounded direct ISO→anonymous virtual GPT/FAT32 staging (synthetic qualification)

A developer-only `windows_iso_virtual_fat32_stream.py --iso /safe/local/Win11_x64.iso --locale "English International 64-bit" --disk-gib 8` entry point fetches Microsoft's checksum, re-verifies every optical ISO file, streams file content **directly from 7-Zip stdout to a Rust process over a framed stdin protocol**, writes inside an anonymous Linux-only GPT disk with separate FAT32 EFI and payload partitions, independently reopens and SHA-256 verifies each FAT32 file, then rehashes the entire source ISO. The disk is **never exported** or saved to a path. This safety-limited iteration caps transfers to **128 MiB per file, 384 MiB total and 128 files**, so genuine large Windows 11 install.WIM and BOOT.WIM files will be rejected. The transfer entrypoint first checks anonymous temporary-storage free space (at least 512 MiB free, increased for requested payload size), and conservatively budgets FAT32 payload capacity; this is a point-in-time admission check, **not a guarantee against concurrent filesystem exhaustion**. CI now stages a genuine 48 MiB file from a synthetic ISO9660 image and checks independent FAT32 SHA-256 readback. The purpose is to qualify the verification and transfer mechanics, not produce installable Windows media.

The Rust subprocess transfer now uses nonblocking, deadline-governed stdin writes rather than indefinitely blocking buffered writes, and bounded, concurrent draining of its stdout/stderr (1 MiB/64 KiB caps) under the same overall 900-second staging deadline. Stalled readers, exited workers, oversized reports, and delayed output termination fail closed and terminate the child; isolated Python adversarial tests cover these cases. The 900-second limit applies after source-manifest verification begins staging; publisher lookup and full preflight have their own existing limits. It is **not** a filesystem-space reservation, process-tree sandbox, or production Windows media qualification.

The CI fixture supplies a **synthetic fake publisher reference strictly in the test code** and fake Windows-shaped ISO file bytes; the production command has no bypass for live Microsoft checksum lookup. This separation ensures that synthetic CI cannot be reported as real Microsoft publisher or Windows Setup boot evidence. It refuses malformed framing, truncated streams, hash mismatches, FAT32 name conflicts, symlinks, invalid nominal capacity, oversized source data and unexpected file counts. The Rust agent rejects all malformed streams and never opens a physical storage device.

The receipt explicitly records `physicalWriteAuthorized=false`, `windowsSetupBootVerified=false`, `installerCompatibleVerified=false`, `fullDiskSha256Verified=false`, `persistentDiskImageProduced=false`, `actualWimResourcesVerified=false` and `fullSizeWindowsInstallerSupported=false`. Large installer payload streaming, verified SWM replacement, exportable disk-image construction, QEMU Windows Setup GUI evidence and Secure Boot/TPM matrix remain separate release gates.

## Optional read-only QEMU evidence

Once the official ISO passes full manifest validation, the existing QEMU/OVMF runner can independently recheck the live Microsoft checksum before booting the unmodified optical ISO:

    python3 tests/virtual-media/windows_setup_ovmf_gate.py --iso /safe/local/Win11_x64.iso --sha256 <actual-64-char-ISO-SHA256> --microsoft-locale "English International 64-bit" --evidence-parent "$HOME/bootnexa-windows-evidence" --seconds 180

This emulator has no guest networking or physical drives, uses private OVMF variables and bounded local QMP screenshots, and leaves publisherProvenanceVerified and windowsSetupBootVerified false pending further review. The optional publisherChecksumMatched value attests only a matching live Microsoft checksum, not a witnessed Windows Setup GUI. The current QEMU profile is not a production Windows 11 Secure Boot and TPM 2.0 qualification.

## Synthetic CI and unresolved gates

CI uses only a fake Windows-shaped optical ISO and a mocked checksum in its internal test helper. It verifies the 7-Zip file-listing/streaming implementation, the full-file manifest, source-before/source-after integrity, safety refusals, and the new QEMU publisher-hash mismatch gate. Synthetic CI never claims official publisher provenance or Windows Setup success.

Remaining before genuine installer qualification: acquire and authenticate a real official Windows 11 ISO; verify its UDF and actual WIM/ESD resource data; safely stage and hash multi-gigabyte installer payloads (the current demo's 64 MiB per SWM and 256 MiB total limit is insufficient); export and independently verify a bootable virtual disk; test the complete OVMF/Secure Boot/TPM matrix; witness Windows Setup GUI and record the specific image/guest evidence. Physical USB operations remain disabled and require a separate authorization and hardware safety review.

No official Windows 11 ISO was present in the engineering workspace during this milestone; no genuine Windows Setup boot has been claimed.
