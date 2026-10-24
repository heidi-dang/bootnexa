# Phase 8 — verified SWM creation and real Windows Setup acceptance gate

## Current implementation

The developer-only command is:

```text
bootnexa-media split-wim-virtual <local-regular-source.wim> <existing-real-output-directory> [part-size-MiB]
```

The optional part size defaults to **3800 MiB**, is constrained to 1–3800 MiB, and **does not guarantee an output part will fit**; wimlib can emit an oversized part when a compressed WIM resource is indivisible. The program independently refuses any actual part larger than FAT32's exact 4,294,967,295-byte per-file limit. It supports WIM sources with bounded lengths (max 16 GiB) and up to 64 split parts with aggregate capacity capped at 20 GiB. **These are parser/regular-file budgets, not a commitment to provision an equivalent bootable disk.**

The operation uses an installed and administrator-provisioned `wimlib-imagex` verifier. It never invokes a shell. It first checks the WIM's compressed blob/metadata integrity using `wimlib-imagex verify`, then splits to a newly created, random temporary directory under an already existing real directory. It runs `wimlib-imagex split ... --check`, validates the complete and contiguous `install.swm`, `install2.swm`, ... names, FAT32 part sizes and SHA-256 read-back, then verifies the entire split archive using `wimlib-imagex verify install.swm --ref=install*.swm`. The source's SHA-256 and length must be unchanged after splitting; each output part is hashed again before the temporary directory is retained. Tool execution is subject to a fixed 30-minute per-operation deadline; failure removes temporary output artifacts on normal controlled error paths.

The JSON receipt explicitly marks `virtualOnly: true`, `physicalWriteAuthorized: false`, `installerCompatibleVerified: false` and `windowsSetupBootVerified: false`. This command **does not** create, modify, format, partition or select a physical drive. The output is a folder of SWM regular files, not a Windows USB installer or QEMU bootable medium. The external wimlib binary must come from a trusted installation; Bootnexa currently lacks its own signed runtime broker for that dependency.

## Automated proof

The CI suite generates 14 pseudo-random synthetic files without Microsoft binaries, captures them into a **real standards-compliant WIM using wimlib**, and invokes the new CLI to split them into multiple SWM parts. It independently reruns the verifier, hashes all parts, checks the source before/after SHA, and rejects a malformed WIM, invalid part-size arguments, symlink input/output and unexpected output directories. This is real WIM and SWM **format qualification**, not Microsoft Windows Setup boot evidence.

Previous stages independently verified a synthetic multi-extent UDF source into a 96 MiB anonymous GPT/FAT32 file-backed disk. **The SWM artifacts are not yet integrated into a full-size Windows installer virtual disk.**

## Remaining Windows installer exit gates

1. **Provenance:** obtain an unmodified and appropriately licensed official Microsoft Windows 11 ISO outside the repository, record its publisher-provided digest, language, edition, size and acquisition URL/date. No official Microsoft installer binary may be included in repo fixtures or distributed with this project.
2. **Compatibility:** safely stream genuine ISO UDF file contents across real UDF variants and independently validate WIM/ESD resources, including the `sources/boot.wim` boot image and `sources/install.wim` or `install.esd`. Unsupported variants fail closed, including encrypted ESD and multi-part forms without verified tool support.
3. **Installer layout:** generate a genuine large-capacity GPT FAT32 or FAT32+NTFS **virtual** disk image with all Windows Setup files and an appropriate UEFI bootloader. If WIM splitting is needed, keep all `install*.swm` files in `SOURCES` and verify each part; don't simply byte-split WIMs. Verify exact source/read-back hashes and full filesystem consistency.
4. **Actual guest boot:** use licensed official ISO or a proven full-size virtual disk, QEMU/OVMF without network or host physical disks, a bounded ephemeral VM, and capture image digest, QEMU firmware/configuration, timestamp, guest serial/video evidence, and a witnessed Windows Setup interface. A firmware boot splash or a synthetic EFI boot alone cannot set `windowsSetupBootVerified=true`.
5. **Hardware/production:** Secure Boot matrix, TPM requirements, WinPE/Windows Setup behavior on supported Windows releases, signing, privileged Windows helper, protected-drive identity confirmation and sacrificial hardware testing all require separate acceptance. Until then USB selection and physical writes remain disabled.

### Evidence status

| Gate | Status |
| --- | --- |
| Format-valid synthetic WIM/SWM verifier and SHA receipts | Passed locally, CI required |
| Restricted synthetic UDF to 96 MiB GPT/FAT32 artifact | CI-qualified in PR #32 |
| More-than-4GiB real official WIM split and FAT32 staging | Not tested |
| Genuine Windows 11 Setup guest boot | Not tested — official media unavailable |
| Secure Boot and physical USB writes | Disabled and unqualified |

Microsoft's documentation explains the split archive install format and the requirement that all SWM parts are in the same folder:
- https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/split-a-windows-image--wim--file-to-span-across-multiple-dvds
- https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe--use-a-single-usb-key-for-winpe-and-a-wim-file---wim
- https://wimlib.net/man1/wimsplit.html
- https://wimlib.net/man1/wimverify.html
