# Source-bound official ISO → SWM → anonymous FAT32 (operator-only)

Run the [read-only genuine Windows ISO and host readiness check](WINDOWS-GENUINE-ISO-ACCEPTANCE-READINESS.md) first. It requires a matching live Microsoft SHA and verifies that the release binary actually advertises the BNXI0002 combined path; merely finding an executable is not sufficient.

## Execution contract

BootNexa has a separate Linux-only operator command for constructing an **anonymous** virtual Windows-shaped layout from a locally acquired ISO:

~~~
python3 tests/virtual-media/windows_source_bound_combined_iso.py \
  --iso /secure/path/Windows.iso \
  --locale 'English International 64-bit' \
  --scratch-parent /path/to/existing-private-large-filesystem \
  --disk-gib 16 --part-mib 3800 \
  --confirm-anonymous-virtual-only
~~~

Requirements: local 7z, wimlib-imagex, the BootNexa release CLI built from the checkout, an existing regular ISO file and an existing non-symlink scratch parent with ample free space. This command cannot accept a self-supplied publisher checksum or previously saved JSON manifest. It obtains the language-specific SHA-256 from the pinned Microsoft.com HTTPS reference path using the existing redirect and byte-limit policy and requires an exact match with the entire original ISO.

1. Rehash the complete ISO, list each ISO9660/UDF file through 7-Zip, and independently stream/hash every listed file to build a fresh bounded manifest. Ignore only the synthetic El Torito [BOOT] listing, never ordinary files.
2. Require a single install.WIM (not ESD, existing SWMs, or conflicting names), mandatory EFI/BOOT/BOOTX64.EFI, SOURCES/BOOT.WIM and SETUP.EXE names, safe FAT32 paths, a maximum of 4096 files, and no case-insensitive file/directory collisions. Additional ISO file constraints: at most 1 GiB each and 2 GiB total, with conservative projected FAT32 disk capacity.
3. Check the free space on the selected scratch filesystem. A temporary install.WIM is extracted into an exclusively owned, private scratch directory through a bounded stream, checked against its exact ISO-manifest length and SHA-256, then split via the existing wimlib-verified native SWM API. Temporary artifacts are deleted when the operation finishes, including on failure.
4. Launch the explicit BNXI0002 combined virtual-only native command with a private temporary directory inherited as TMPDIR. Stream all non-install ISO files directly from 7z into its stdin with monotonic deadlines, bounded memory, exact lengths and source SHA-256. The native writer independently verifies file hashes and rereads every FAT32 file, all SWM parts, GPT and both FAT32 partitions.
5. Verify the source install.WIM, every SWM part and the **entire original ISO again**, after staging. Return a JSON evidence summary without persistent disk images, extracted binaries, or source file paths.

Host free-space admission is conservative and point-in-time, **not a reservation** against competing processes; run on isolated infrastructure with controlled concurrent disk allocation. Splitting/WIM scanning is computationally expensive. Ordinary PR CI uses only a small synthetic ISO with non-Microsoft files, real uncompressed WIM/BOOT.WIM fixtures, and real wimlib SWM files. The measured >4 GiB synthetic SWM acceptance remains documented separately.

## Guest boot evidence — strictly separate opt-in

The same operator command can optionally invoke the existing **read-only** QEMU/OVMF boot witness against the original source ISO, after successful source-bound combined staging. Example flags:

~~~
--capture-iso-ovmf-evidence \
--evidence-parent /path/to/private-guest-evidence \
--ovmf-seconds 180
~~~

The witness attaches the original ISO as read-only CD-ROM, boots OVMF with software emulation and **no guest network or host writable disk**, captures QMP graphical frames and serial/QEMU logs in a separate operator-selected directory, and rehashes the original ISO afterward. This guest evidence is for the original ISO, **not** a boot test of the anonymous combined disk. Human review of screenshots is required to determine whether genuine Windows Setup actually appeared. Even a successful graphical capture leaves windowsSetupBootVerified, genuineWindowsSetupObserved and installerCompatibleVerified **false** by design. No genuine Windows Setup boot has been observed or accepted by automation.

## Remaining gates

- The command supports ISO sources containing a single install.WIM; ESD, install WIMs over 16 GiB, ISO remainder files over 1 GiB, or remainder totals over 2 GiB are refused. No NTFS fallback is enabled.
- A live Microsoft-published ISO checksum binds source **bytes**, but does not establish firmware signatures, EFI trust chain, Secure Boot, TPM compatibility, or installer runtime correctness.
- The combined output is anonymous, discarded, and not exported as a bootable device; complete-disk SHA and actual combined-media guest boot remain unqualified.
- Independent manual Windows Setup acceptance against real, licensed media is pending an operator-supplied ISO, a supported isolated guest environment, and explicit evidence review. There is no included Microsoft content.
- USB/physical-media writing, privileged helper access and production deploy remain disabled/unmodified.

This capability must not be represented as a Windows Setup-ready USB installer.
