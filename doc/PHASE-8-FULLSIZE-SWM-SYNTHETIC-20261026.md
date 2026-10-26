# Phase 8 acceptance — real >4 GiB synthetic WIM/SWM virtual staging

**Outcome: PASS for the synthetic WIM/SWM-to-anonymous-FAT32 data path only.**
Observed 26 October 2026 via CPTR GCloud Linux workspace; test command completed with exit code 0. These results do **not** establish official Windows installer compatibility, genuine Windows Setup boot, signed production release readiness, or physical USB-writing safety.

## Executed qualification

- BootNexa source base: `d746a81c03fc47d9105691bf319234f54f8866eb` (merged PR #45); native `bootnexa-media` compiled with Rust `--release --locked` from this source.
- Host: Ubuntu 26.04.1 LTS, isolated regular-file scratch on the host's persistent filesystem. The default `/tmp` tmpfs was deliberately *not* used. Approximately 57 GiB of host storage was available before full-size staging, and a minimum of approximately 48 GiB remained at peak occupancy (observed `df -h`; rounded, not an atomic allocation guarantee).
- Verifier: Ubuntu-packaged wimlib-imagex 1.14.5, extracted under an owned, temporary user directory; no root permission or system-wide installation.
- Source fixture: 17 nonproprietary synthetic random files totaling **4,352 MiB**, captured into a genuine *uncompressed* WIM using `wimlib-imagex capture`. This source is **not** a Microsoft ISO or installation image.
- WIM SHA-256 verified before splitting and after transfer; wimlib verified the whole WIM and contiguous split archive before and after the anonymous virtual-media stage.
- Target: anonymous sparse **8 GiB GPT/FAT32** virtual disk, never exposed as an output image or physical device. Staging used the explicit `--experimental-virtual-only` profile and the native FAT32 per-file and aggregate admission limits.
- Full native transfer and **independent readback** returned `verifiedReadback=true`, with unchanged source digest and no persistent disk image. The temporary split directory and anonymous virtual disk were cleaned up as part of the controlled process.

## Recorded numeric receipt

| Field | Measured result |
| --- | --- |
| Source WIM bytes | `4,563,407,190` |
| Source WIM SHA-256 | `0c1cbbf39a9c3dd08c9567f8fbcfb7abec88f5ccf37de1059668a490d3202773` |
| SWM parts | `2` |
| SWM bytes staged and independently read back | `4,563,417,032` (greater than 4 GiB) |
| Nominal virtual disk | `8 GiB` |
| Operator-helper scratch threshold | `16,911,447,042` bytes |
| Native host-storage admission | Passed (`fstatvfs` against actual anonymous-disk descriptor) |
| Independent FAT32 file SHA-256 readback | **Passed** |
| Python qualification command exit | `0` |

The SHA-256 digest identifies the ephemeral synthetic WIM bytes created in the session. It is **not** Microsoft publisher provenance. These measurements derive from the successful real execution, rather than an estimated model or synthetic mock acceptance receipt.

### Explicitly false or unverified

`publisherProvenanceVerified=false`, `installerCompatibleVerified=false`, `windowsSetupBootVerified=false`, `fullDiskSha256Verified=false`, `physicalWriteAuthorized=false`, `persistentDiskImageProduced=false`.

The capability still lacks complete ISO file-tree reconstruction, genuine bootloader/setup resources, a Windows Setup guest acceptance witness, and physical-drive write qualifications. The operator-only large-file test is not run on normal PR CI; standard CI covers the smaller real-format synthetic WIM/SWM path, policy/unit tests, Windows agent, and UEFI/Linux boot regressions.

## Reproduction

The opt-in generator `tests/virtual-media/qualify-generated-4gib-swm.py` produces the same fixture size/class and executes the operator-only pipeline with a selected optimized CLI. See `doc/WINDOWS-SWM-SETUP-QUALIFICATION.md` for the exact commands and scratch limits. Random fixture bytes are deliberately not kept in Git; a new invocation will produce a different digest. The recorded successful session generated a WIM using the generator and then used `qualify-fullsize-swm-virtual.py` to complete the >4 GiB split, FAT32 staging and readback with the release executable.
