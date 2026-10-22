# BootNexa v0.4 — Virtual GPT/MBR + FAT32 EFI media

**Scope:** Virtual-media-only. No physical USB writer, privileged helper modification, destructive API, or shipped executable.

## Implemented

- GPT primary and backup headers, protective MBR, 128 GPT entries, CRC-32 verification, reciprocal header pointers, partition alignment and capacity checks.
- MBR EFI partition alternative with verified geometry.
- Anonymous regular-file virtual disks with FAT32 formatted only through a partition-bounded seek/write adapter. EFI PE/COFF x64 application is structurally checked before writing EFI/BOOT/BOOTX64.EFI. The full payload is reopened, compared and SHA-256 verified; this alone does not prove boot execution.
- Explicit developer-only regular-file export by unique filename, with exclusive create_new and full exported file hash read-back. No arbitrary physical disk target can be supplied to the CLI.
- Bounded read-only ISO9660/UDF recognition and El Torito BIOS/UEFI catalog inspection (not extraction, Windows/Linux identification or hybrid ISO compatibility proof).
- Synthetic open-source x64 UEFI smoke fixture writes BOOTNEXA_UEFI_BOOT_OK to QEMU debugcon. A dedicated CI gate installs QEMU/OVMF, builds a fresh virtual GPT/FAT32 image, boots it and requires the actual firmware marker.

## Developer commands

Install the Rust UEFI target (for the test fixture), compile the fixture, and create a file-backed image:

- rustup target add x86_64-unknown-uefi
- rustc --target x86_64-unknown-uefi -C panic=abort -C opt-level=s tests/fixtures/bootnexa-uefi-marker.rs -o /tmp/BOOTX64.EFI
- cargo run --manifest-path agent/Cargo.toml --locked --bin bootnexa-media -- build-virtual /tmp/BOOTX64.EFI /tmp gpt
- cargo run --manifest-path agent/Cargo.toml --locked --bin bootnexa-media -- inspect-iso /path/to/locally-owned.iso

The developer CLI creates a newly named 96 MiB regular .img file under a real directory. It never accepts a target disk, USB handle or existing output file.

## Verification boundaries

ISO classification is inspection only, limited to 64 descriptor sectors and one catalog; it does not extract ISO/UDF directory contents or make operating-system install media. A matching PE header does not prove bootability. QEMU boot verification, once passing in CI, covers this **synthetic EFI application only** in a virtual firmware environment, not BIOS/Secure Boot or physical hardware. GPT/MBR and FAT32 are verified by independent reads; it is not a full-image unused-sector comparison.

Production code signing issue #5 and hardware safety issue #13 remain open. All physical USB writes remain disabled.
