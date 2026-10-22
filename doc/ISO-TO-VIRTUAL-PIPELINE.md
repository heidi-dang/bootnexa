# ISO9660-to-virtual EFI pipeline (experimental)

## Implemented

The bootnexa-media plan-iso command walks bounded primary ISO9660 directories (8 levels, 512 files, 60 MiB total, 1 MiB per directory, 48 MiB per file). It cross-checks the extent little/big-endian fields, checks bounds and disjointness, detects aliases, duplicate case-insensitive paths, unsafe filenames, overflows, and malformed records. Unsupported Joliet, UDF-only, Rock Ridge/SUSP, symlink, interleaved and multi-extent semantics are rejected. These cases do not silently fall back to unsafe extraction.

The bootnexa-media build-from-iso command accepts a read-only regular-file ISO no larger than 256 MiB and an existing directory for unique regular-file output. Only a small, supported plain-ISO9660 x64 EFI application profile can be copied to an anonymous 96 MiB GPT/FAT32 virtual disk. The x64 EFI executable is structurally verified. Every included file is streamed in 64 KiB chunks, hashed and compared against an independent FAT32 read-back; both GPT headers and entry arrays are verified and the final exported file is SHA-256 checked. No physical disk or existing output file can be selected.

Linux and Windows installation ISO candidates are **recognized but rejected**: WIM/ESD processing, installer bootloaders, UDF/Joliet extraction, vendor licensing and actual setup success are not yet qualified. Oversized WIM/ESD files are not split. Reporting an ISO as a Windows/Linux candidate is not a claim of installer compatibility.

## Verification

Rust tests cover safe and malicious directories, endian mismatch, corrupt extents, duplicate names, traversal and refusal of unqualified operating system media. Dedicated CI generates a synthetic ISO9660 containing an open-source EFI marker application and README, extracts it into FAT32, reopens both files and boots the **ISO-derived virtual disk** in QEMU/OVMF. The gate requires a debug-port marker from genuine UEFI execution. No Microsoft or third-party proprietary installer image is included in the fixture.

## Remaining

This is virtual-file-only, developer-only technology. The browser cannot write physical USB; this code never grants destructive permissions. Further work needs genuine licensed ISO fixture corpora, UDF/Joliet/Rock Ridge and bootloader support, Windows WIM split/reconstruction, Linux version compatibility, real Windows Setup/Linux boot acceptance, UI progress/cancellation, hardware safety issue #13, and production signing issue #5. This alone is **not** a 10–15 percentage point advancement to finished Windows 1.0.
