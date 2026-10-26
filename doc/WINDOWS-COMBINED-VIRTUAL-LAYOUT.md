# Combined installer-shaped virtual layout — experimental acceptance

The developer-only Linux native CLI now stages a wimlib-verified SWM archive and a separate bounded stream of all the remaining installer-shaped files into the **same anonymous 8–24 GiB GPT disk**. The 256 MiB EFI partition is FAT32 and the Microsoft basic data payload partition is FAT32. This is synthetic virtual-file qualification, **not a complete Microsoft installer, physical media writer or Windows Setup boot proof**.

Command:

~~~text
bootnexa-media stage-combined-windows-tree-virtual <8-24-GiB> <verified-swm-directory> --experimental-virtual-only
~~~

The command reads BNXI0002-framed data from stdin (same per-file structure as BNXI0001: 8-byte magic, LE u16 file count, then per file LE u16 path-byte length, UTF-8 path, LE u64 byte length, raw 32-byte SHA-256, and exact file contents). It never accepts raw-device paths or exports the anonymous virtual disk.

The ISO-remainder stream is capped at 4096 files, 1 GiB per file and 2 GiB aggregate, with safe, case-insensitively unique FAT32 paths. A verified SWM set has a separate 64-part, 16 GiB aggregate limit and FAT32 per-file limits. The combined layout rejects any ISO-stream name in the SOURCES/install.wim, SOURCES/install.esd or SOURCES/install*.swm namespace, preserving the separately wimlib-verified SWM archive. The paths EFI/BOOT/BOOTX64.EFI, SOURCES/BOOT.WIM and SETUP.EXE must be present in the remainder; path existence is a structural check and does not establish software provenance, resource authenticity or boot capability.

The stage independently hashes each ISO-remainder file while copying and from FAT32 afterwards; all SWM parts are independently reread from FAT32 after the other files are staged, and wimlib verifies the SWM archive before and after. GPT, FAT32, partition bounds and conservative host free-space admission are checked. An invalid source, collision, SHA mismatch or capacity error refuses without a persistent disk image. Admission is not a reservation against other host processes. The previous BNXI0001 command remains limited to 128 files, 128 MiB per file and 384 MiB total.

The expanded synthetic CI fixture generates genuine-format, non-Microsoft WIM and SWM archives, a separate small real-format synthetic BOOT.WIM, PE-shaped EFI and SETUP stubs and other installer-like files, then verifies the complete layout plus refusal of missing confirmation and invalid disk sizes. A synthetic PE header is not a trusted Windows bootloader.

## Official ISO compatibility gate — read-only only

~~~text
python3 tests/virtual-media/windows_official_compatibility_gate.py --manifest /path/to/verified-manifest.json --disk-gib 16
~~~

This validates a stored ISO manifest snapshot and reports whether its file counts, sizes, kinds and estimated partition budgets fit the new combined profile. It always returns safeToExecute=false, completeVirtualInstallerProduced=false, publisher provenance untrusted, and physicalWriteAuthorized=false. It does not fetch Microsoft hashes, access an actual ISO, split WIMs, create virtual media or grant authority from saved manifest assertions.

**Not qualified:** No actual licensed official Windows ISO was supplied or assembled in this milestone. The production-provenance ISO producer for the new BNXI0002 combined mode is not yet implemented; the existing official ISO streamer remains a bounded BNXI0001 demonstration. A future milestone must reverify live Microsoft provenance and every source byte, verify genuine BOOT.WIM/install.WIM resources and EFI structures, produce source-bound SWM output, stage all ISO files with a real source integrity ledger, and witness genuine Windows Setup in networkless QEMU/OVMF. NTFS alternatives, Secure Boot/TPM and physical USB writes remain separately gated. No readiness flag is promoted.
