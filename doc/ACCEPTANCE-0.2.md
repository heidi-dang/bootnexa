# Milestone 0.2 — Automated acceptance and evidence boundary

This document defines the automated acceptance scope for BootNexa's read-only Windows agent when physical Windows hardware is unavailable.

## Goal

Verify that the browser and Rust service can discover each other, authorise device enumeration through a **mocked native consent decision**, return a deterministic USB inventory, and reject unauthorised or destructive operations. Run a native **Windows VM** build and a real read-only Windows Storage cmdlet, not merely a Linux cross-compile.

## Test layers

| Layer | Execution environment | Checks | Evidence |
| --- | --- | --- | --- |
| Rust protocol unit tests | Linux and Windows | Strict origin/host, token lifecycle, denial and rate limit, protected disk filtering and JSON parsing | Cargo test results |
| Rust loopback HTTP end-to-end | Linux and Windows | Real TCP/HTTP, simulated native approval, multiple sessions, revocation, inventory fixtures, native denial, concurrent prompt guard and no write routes | `agent/src/smoke_tests.rs` |
| Windows-native API smoke | GitHub Windows VM | Runs `Get-Disk` without writes; exercises the actual parser behind `device::discover` | Windows `cargo test` |
| Windows agent executable | GitHub Windows VM | Starts compiled `bootnexa-agent.exe`, queries HTTP health/capabilities, checks 401/403/404 and stops process safely | `tests/windows/smoke.ps1` |
| Browser acceptance | GitHub Ubuntu Chromium and local Playwright | Offline state, simulated approval/denial, device inventory UI, refresh, revoke, protocol mismatch, reconnect and disabled write action | `tests/browser/agent.spec.ts` |
| Build and static review | Linux and Windows | TypeScript, Vite production build, Rust formatter, Clippy warnings-as-errors | CI job results |

All mock decisions and fixture devices exist only in test code. The released agent does not offer an environment variable, HTTP endpoint or command-line switch to bypass native approval or inject fake devices.

## Commands

```bash
npm ci
npx playwright install chromium
npm run build
npm run test:smoke -- --workers=1

cargo fmt --manifest-path agent/Cargo.toml --check
cargo test --manifest-path agent/Cargo.toml --locked --all-targets
cargo clippy --manifest-path agent/Cargo.toml --locked --all-targets -- -D warnings
```

On Windows CI, the workflow additionally builds the **release Windows executable** and invokes `pwsh -File tests/windows/smoke.ps1` without consent or disk writing.

## Mandatory pass criteria

- Host and foreign-origin requests cannot obtain an access token or list drives.
- The simulated native approval grants only `devices:read`; denial and revocation fail closed.
- Two browser tabs can have separate session tokens without unexpectedly revoking each other.
- Protected boot/system devices, non-USB buses, offline and zero-capacity drives are filtered.
- Missing agent, unsupported protocol and failed Windows enumeration never display an authenticated drive.
- Physical write, format, partition, mount, erase and job routes do not exist in 0.2.
- A real Windows build launches and responds with accurate capabilities.
- Browser snapshots show no enabled **Start writing** action.

## Explicitly **not** covered by these tests

- **Actual Windows UI confirmation:** the native `MessageBoxW` system dialog is compiled, but a human has not confirmed it appears on a local Windows desktop or that clicking Yes/No works end-to-end. Injecting an approval callback tests service state, *not* real desktop interaction.
- **Physical removable USB enumeration:** Windows CI runs on a virtual machine with whatever synthetic virtual disks the runner supplies. No physical USB hotplug, device removal, serial stability, USB bridge behaviour or multi-disk edge case is qualified.
- **Code-signing and installer distribution:** packaging now has CI-only test signing with native Windows install/uninstall checks, but there is no trusted production certificate, published trusted installer, or authenticated update chain. See [WINDOWS-INSTALLER.md](WINDOWS-INSTALLER.md).
- **Hosted website→localhost browser permission:** automated Chromium tests mock network responses. Cross-origin HTTPS to localhost needs additional real-browser policy qualification against the public production origin.
- **Disk operations:** intentional and correct for milestone 0.2. No partitioning, formatting, erasure or image writing exists.

## Release decision

**Automated acceptance** may be considered passed only when all CI jobs are green on the same exact SHA. **Hardware acceptance and signing remain open.** Do not label milestone 0.2 “fully Windows hardware qualified” on the basis of mocks or Windows CI alone.

When a physical Windows computer is available, use [agent/README.md](../agent/README.md) and record actual consent interaction (user approves/denies), USB insertion/hotplug enumeration, identity classification, and signed installer validation before declaring full hardware qualification.

Windows read-only PowerShell device discovery has a bounded 30-second timeout to accommodate cold Storage-provider startup. A timeout fails closed, never returns an empty successful inventory.
