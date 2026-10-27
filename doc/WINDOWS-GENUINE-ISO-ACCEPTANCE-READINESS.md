# BootNexa genuine Windows 11 ISO acceptance — live readiness and blockers

## Current state (27 October 2026)

**No genuine Windows ISO was provided to this workspace.** Authentic Windows Setup guest boot and full source-bound official-media staging have **not** been executed. The source-bound data path passes synthetic end-to-end CI, and the live pinned Microsoft Australia SHA-256 lookup was confirmed operational for both supported English x64 locale variants.

The GCloud development VM has approximately 60.5 GiB available on its persistent filesystem. Its default /tmp is a much smaller tmpfs and is **not** appropriate for large WIM staging. The VM does **not** currently have 7z, wimlib-imagex, qemu-system-x86_64 or OVMF installed as host tools. We intentionally did not perform privileged package installation or root operations to change that environment. CI supplies the necessary open-source test dependencies on ephemeral runner VMs.

The project's native release media CLI was rebuilt from the working tree, and a new read-only `capabilities` operation confirms it supports BNXI0002 combined SWM/ISO staging. This prevents a previously existing, outdated release executable from being considered ready. The readiness JSON records its SHA-256; this identifies the executable bytes but **does not** constitute publisher signing or attest the Git revision it was compiled from.

### Read-only readiness verification

The CLI below makes no installation media, extracts no ISO content, launches no virtual machine and performs no persistent media writes. It retrieves fresh reference hashes from Microsoft's pinned HTTPS download page, inspects host tooling, validates scratch space and optionally hashes an existing local ISO.

~~~sh
# Check tools, host scratch, native capability and live Microsoft checksum
python3 tests/virtual-media/windows_genuine_iso_readiness.py \
  --scratch-parent /path/to/large-existing-scratch \
  --locale 'English International 64-bit'

# After obtaining an authentic local Windows ISO from Microsoft:
python3 tests/virtual-media/windows_genuine_iso_readiness.py \
  --iso /secure/path/to/operator-acquired/Windows11.iso \
  --scratch-parent /path/to/large-existing-scratch \
  --locale 'English International 64-bit'
~~~

The command returns exit 2 while blocked, exit 1 for invalid arguments or unrecoverable errors, and exit 0 only when the exact locally hashed ISO matches the **live** Microsoft checksum, sufficient preliminary free space exists, and the current source-bound CLI, 7z and wimlib are present. A successful **readiness** result is not evidence of ISO processing, Windows Setup boot, full-media compatibility, or physical write safety. Guest capture has separate `guestEvidenceBlockers` and requires both QEMU and OVMF.

An operator-controlled `BOOTNEXA_OVMF_DIR` may point to a real absolute user-owned directory containing a matching `OVMF_CODE_4M.fd` / `OVMF_VARS_4M.fd` pair; symlinks are refused. Private tools may be passed through a scoped PATH. QEMU guest execution additionally requires at least **3.5 GiB available host memory**, enforced again immediately before starting the guest. See [portable host qualification and resource admission](WINDOWS-GENUINE-ACCEPTANCE-PORTABLE-HOST.md) for measured GCloud results and the isolated toolchain approach.

Local ISO acquisition is an operator step from the [official Microsoft Windows 11 download page](https://www.microsoft.com/en-au/software-download/windows11); never substitute third-party ISO mirrors, guessed checksums or unverified external downloads. Ensure ISO locale exactly matches the selected checksum. No ISO content, installer license or extracted proprietary binary is committed to Git.

### Native binary capability receipt

~~~sh
cargo build --release --locked --manifest-path agent/Cargo.toml --bin bootnexa-media
agent/target/release/bootnexa-media capabilities
~~~

The read-only JSON must contain `schema=bootnexa-native-virtual-capabilities-v1`, `supportsCombinedIsoSwmStream=true`, `combinedIsoStreamMagic=BNXI0002`, `requiresExperimentalVirtualConfirmation=true`, and all physical-write, persistent-disk and Windows Setup assertions false. This command does **not** grant permissions or authorize a physical output target. Binary existence without an accepted capabilities receipt is explicitly blocked.

## Once authentic media is available

With an accepted readiness receipt, use the source-bound operator-only staging command detailed in [Windows source-bound combined ISO](WINDOWS-SOURCE-BOUND-COMBINED-ISO.md). Independently review the native transfer result. For guest evidence, opt in separately to its QEMU/OVMF original-source-ISO witness. This boot witness uses an isolated, network-disabled guest, attaches the original ISO read-only, saves bounded QMP frames and logs, and **never automatically marks genuine Setup boot as passed**. It does not boot or export the anonymous combined media.

To close the real Setup acceptance gate, an authorized reviewer must independently verify authentic Windows Setup UI in captured guest frames, correlate hashes and source-reference provenance, and repeat the test under controlled Windows edition, firmware, Secure Boot and TPM configurations as relevant. That remains a separate witnessed milestone; no current automated success flag claims it was completed.

**Physical USB writes, privileged writer activation, persistent disk-image export, and production deployment remain prohibited and unmodified.**
