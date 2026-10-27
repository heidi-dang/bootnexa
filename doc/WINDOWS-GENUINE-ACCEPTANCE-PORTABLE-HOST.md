# Genuine Windows 11 acceptance: isolated host-tool provisioning and guest safety

## GCloud qualification, 27 October 2026

On an unprivileged Ubuntu 26.04.1 GCloud host, BootNexa qualified a **user-owned toolchain** from the standard Ubuntu package repository, without root access, system package installation, service changes or guest activation. Tools were downloaded with the host's authenticated apt package metadata and extracted into a private directory; their wrappers set a scoped library search path without editing the global environment. The tested executables were:

- 7-Zip 26.00, local archive decoder
- wimlib-imagex 1.14.5, split-WIM verification
- QEMU system x86_64 10.2.1, software-only emulator
- Ubuntu OVMF generic 4M UEFI firmware (CODE and VARS files)

All four were reachable from a short-lived scoped PATH and firmware override. QEMU's direct `--version` smoke succeeded, including the dynamic libraries unpacked into the user directory. **No QEMU guest was launched**, because the host's measured `MemAvailable` was approximately 2.41 GiB while the existing guest command requests a 2 GiB guest. A conservative policy now requires **at least 3.5 GiB MemAvailable** (2 GiB guest plus 1.5 GiB margin) immediately before execution. This is point-in-time admission, not a reservation; production or shared hosts may require a substantially larger margin.

The pinned Microsoft Australia Windows 11 checksum page responded with independently available x64 English and English International reference SHA-256 values. **No official ISO was available in the repository or owned scratch volumes.** No Microsoft disk image was downloaded or hashed on the host, no source-bound official-media transfer occurred, and genuine Setup compatibility is untested.

### Supported environment controls

A user-supplied, absolute **real** firmware directory can be declared using `BOOTNEXA_OVMF_DIR`, with the exact pairs `OVMF_CODE_4M.fd` / `OVMF_VARS_4M.fd` or `OVMF_CODE.fd` / `OVMF_VARS.fd`. Neither a symlinked override directory nor symlinked firmware file is accepted. Without an override the normal host directories are used. The QEMU process remains networkless with read-only ISO block-devices and a copied, private writable OVMF variable template.

A per-process PATH may select a private 7z, wimlib-imagex and QEMU executable, with no need for global tool installation. Neither the working tree nor the user's repository contains downloaded Ubuntu package binaries or any Microsoft media. The developer-only native BootNexa CLI continues to require the existing explicit anonymous-virtual-only staging flag and never receives physical media targets.

The read-only readiness check reports `guestHostMemAvailableBytes` and `guestMinimumHostMemAvailableBytes`, and blocks `guestEvidenceHostReady` with `host_memavailable_below_qemu_safety_floor` when needed. The active QEMU witness also independently calls this memory gate immediately before launching, preventing bypass by a stale readiness receipt.

### Completing authentic Setup guest acceptance

1. Obtain the **original** Windows 11 x64 ISO through the official [Microsoft Windows 11 download flow](https://www.microsoft.com/en-au/software-download/windows11). Select the exact English / English International language matching the live checksum reference. Do not use mirrors, rewritten ISOs, pre-extracted Microsoft images, or a checksum supplied only by the operator.
2. Stage that ISO as a regular file on a dedicated test host or an authorized supported volume, with adequate scratch space. Keep the source outside Git.
3. Use `windows_genuine_iso_readiness.py` with scoped user-owned tool PATH and (when needed) `BOOTNEXA_OVMF_DIR`. Admission must show `publisherReferenceFromLiveMicrosoft=true`, `isoSha256MatchedReference=true`, and no data-transfer blockers. Run a guest only when its **separate** memory and QEMU/OVMF gates pass.
4. Run the source-bound combined WIM/SWM anonymous GPT/FAT32 qualification. Retain the SHA receipt but do not claim this temporary disk can boot Windows.
5. Run the original-ISO source guest witness on an adequately provisioned, isolated host (at least 3.5 GiB *available*, preferably 8+ GiB total RAM). Review the captured Setup frames and exact source hash. The witness **does not** boot the anonymous combined media, install to a guest disk, or automatically assert Windows Setup acceptance.

Physical USB writes, disk export, root-level privileged writers, Setup compatibility flags and production deployment remain disabled.
