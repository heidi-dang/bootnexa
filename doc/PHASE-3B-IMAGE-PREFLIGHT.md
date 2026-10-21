# Phase 3B — Local image inspection and read-only preflight

**Status:** Implemented as browser-side preliminary checks. No disk-write capability.

## User workflow

1. Select a local ISO, IMG, IMA or DD image. Other file types are explicitly unsupported for this milestone.
2. A browser Web Worker reads a bounded header sample to identify ISO 9660 primary volume descriptors or recognizable GPT, MBR and FAT boot-sector structures. ISO dimensions are checked for consistency between little- and big-endian fields.
3. The worker hashes the entire source using SHA-256 and 4 MiB sequential chunks, reporting progress. Users can cancel and retry. Neither the native agent nor a cloud service receives file bytes.
4. Optionally supply a trusted publisher-provided SHA-256. Invalid length/characters or a mismatch block preflight.
5. Select a currently eligible drive from the read-only Windows inventory. The web UI rejects a byte-count overflow and a drive reporting write protection.
6. Review individual preflight checks. Even successful preliminary checks never enable USB writing or issue a disk-write authorization.

## Security boundary

- **Recognized format does not mean bootable.** The inspector does not verify ISO El Torito/UEFI boot records, GPT/MBR partition integrity, boot code, mounted filesystems, or OS compatibility.
- **Capacity check does not certify safety.** Advertised size may be unreliable; the native privileged helper must independently revalidate physical identity and topology before any future write.
- **File object is not a trusted native source path.** The UI binds a result to the selected File snapshot (name, size, last modification). Replacing or resetting the file invalidates the UI result. The browser cannot guarantee an underlying disk file stays unchanged; a future privileged operation must reopen and verify the source.
- **Read-only display ID is not disk authority.** No browser preflight result is signed, expiring or privileged, and no write, erase, format, mount or job endpoint exists.
- **Untrusted inputs remain bounded.** Compressed ZIP/GZ/XZ and VHD/VHDX/FFU are not decoded. Unrecognized, truncated, inconsistent and empty structures fail the format check. Hashing may still run for integrity analysis.
- **Cancellation and responsiveness.** A dedicated worker does incremental hashing off the UI thread. Changing files or cancelling terminates the old worker, and its late messages are ignored.

## Verification

- Chromium browser acceptance uses deterministic ISO, GPT, MBR and malformed fixtures with hashes independently calculated using Node SHA-256.
- Regression tests cover more than two 4 MiB chunks, checksum mismatch, malformed checksum, insufficient device capacity, write-protected USB entries, corrupted ISO descriptors, disguised ZIP inputs, empty images, and changed selection.
- Existing Linux/Windows Rust tests, native Windows read-only inventory, CI-only signed installer and uninstall smoke remain required gates.
- No files are uploaded or sent to the native agent. USB writing remains disabled in the UI and absent from the agent API.

## Next

Phase 4: a durable SQLite job journal and file-backed simulation with failure injection. Real destructive USB operations remain blocked by privileged disk safety validation, explicit device-specific consent and physical Windows hardware acceptance. Public signing enrollment is tracked in issue #5.
