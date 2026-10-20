# BootNexa local agent (milestone 0.2)

A read-only companion process for **Windows**, written in Rust. This is developer software, **not a signed installer**. It exposes a small, origin-restricted HTTP API bound only to `127.0.0.1:43627`.

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

There are **no** write, erase, format, partition, mount, image-inspect or privileged-helper endpoints.

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
