# BootNexa local agent (milestone 0.2)

A read-only companion process for **Windows**, written in Rust. This is a read-only native agent. A per-user Windows installer and fail-closed production signing workflow are available, but no trusted production signing certificate or public release is configured. It exposes a small, origin-restricted HTTP API bound only to `127.0.0.1:43627`.

## Run on Windows

Install Rust using the official rustup installer. Then, from the BootNexa repository root, in an **interactive Windows user session**:

```powershell
$env:BOOTNEXA_ALLOWED_ORIGIN = 'http://127.0.0.1:5173'
cargo run --manifest-path agent/Cargo.toml
```

In a second terminal:

```powershell
npm ci
npm run dev
```

Open `http://127.0.0.1:5173/`. The page discovers the local agent automatically. A **native Windows Yes/No prompt** asks whether BootNexa may *view connected removable USB drives*. Choose **Yes** to view the read-only inventory; choose **No** to deny access. No manual pairing codes are required.

Consent remains valid until the agent process exits or the session is explicitly revoked. Subsequent connections during the same process receive fresh, 30-minute, read-only tokens without repeating the prompt. After an agent restart, another native approval is required.

`BOOTNEXA_ALLOWED_ORIGIN` must be an exact canonical HTTPS origin or local HTTP origin. Do not use a wildcard. A deployed site needs a separate reviewed allowlist configuration.

## API surface

| Method | Path | Access | Purpose |
| --- | --- | --- | --- |
| GET | `/v1/health` | Public, restricted-origin CORS | Agent version, protocol and platform |
| GET | `/v1/capabilities` | Public, restricted-origin CORS | Capability support, explicitly `diskWrite=false` |
| POST | `/v1/access/request` | Exact browser origin + native consent | Issue read-only session |
| POST | `/v1/access/revoke` | Read-only bearer | Revoke the session and reset consent |
| GET | `/v1/devices` | Read-only bearer + exact browser origin | Enumerate eligible USB devices |

There are **no** write, erase, format, partition, mount, image-inspect or privileged-helper endpoints. Optional, opt-in Phase 4 simulation-history GET endpoints are documented below.

## Discovery policy

On Windows, the agent launches a fixed read-only PowerShell Storage cmdlet (`Get-Disk`) through `powershell.exe` without shell interpolation. It includes only explicitly `USB` drives that are online, non-system, non-boot, and have nonzero capacity. The response contains display-only opaque IDs, friendly model, capacity, bus, layout and read-only status. It does not expose raw paths or give write authority.

The system-disk exclusions here are **UI filtering only**; future destructive operations must independently revalidate the complete disk ancestry inside a privileged helper.

Linux builds can run the HTTP endpoints for development, but `/v1/access/request` returns 501 and device discovery remains unsupported. Full platform support is independent future work.

## Security properties

- Loopback-only binding, strict Host and browser Origin policy, no wildcard CORS
- Private Network Access preflight response for the configured origin
- Windows native Yes/No approval with default set to **No**
- Five rejected approvals per agent process before rate limiting
- In-memory 256-bit random bearer grant; scope `devices:read`; up to eight concurrently valid tokens; 30-minute expiry
- Token and consent revocation; fresh prompt after agent restart
- No default cloud traffic, no privileged disk operation

The native prompt **must run inside an interactive user session**, not as a Windows Session 0 service. For this milestone, native prompt and hardware tests still need validation on physical Windows computers; GitHub CI provides Windows compile and mocked-consen​t tests, not real physical-device acceptance.

## Validate

```bash
cargo fmt --manifest-path agent/Cargo.toml --check
cargo test --manifest-path agent/Cargo.toml --locked --all-targets
cargo clippy --manifest-path agent/Cargo.toml --locked --all-targets -- -D warnings
```

The browser never transfers ISO bytes or drive contents in this milestone. Native write and erase approval are designed as distinct, stronger authorisations in [the roadmap](../doc/ROADMAP.md).

## Automated validation without a physical Windows computer

See [milestone 0.2 acceptance](../doc/ACCEPTANCE-0.2.md) for a test matrix covering a native Windows CI runner, real read-only Get-Disk invocation, test-only native-consent simulation, actual HTTP loopback calls, and browser acceptance. These tests cannot prove the visible Windows MessageBox or physical USB hotplug behaviour.

## Installer and signing

See [Windows installer and signed-release process](../doc/WINDOWS-INSTALLER.md) for per-user installation, start-on-login, test certificate isolation, production signing secrets, signature checks and uninstall verification. The production release workflow cannot publish an installer without a trusted code-signing certificate.

## Phase 4 simulation journal

A separate Rust module and command-line tool now exercise a **simulation-only** durable SQLite job engine. See [Phase 4 journal and CLI instructions](../doc/PHASE-4-JOB-ENGINE.md). To view synthetic snapshots or persisted events in the agent's read-only API, set both BOOTNEXA_ENABLE_SIMULATIONS=1 and BOOTNEXA_SIMULATION_DB to an owned SQLite file path before starting an interactive agent. These disabled-by-default routes are GET-only, require the existing origin-bound bearer and expose simulations/{id}, simulations/{id}/events and simulations/{id}/stream as SSE. The CLI can generate synthetic jobs in the database; no HTTP mutation endpoints exist. Native disk writing remains disabled.
