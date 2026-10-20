# Windows agent installer and signed-release process

## Scope and status

BootNexa Agent 0.2 is a **read-only** Windows x64 companion. This milestone delivers a per-user Inno Setup installer, package identity, auto-launch options, Authenticode code-signing support, fail-closed trusted release gates, and install/uninstall smoke coverage on ephemeral Windows CI machines.

**No disk writing, formatting, erasing, elevated helper, or administrative Windows service is installed.**

The release pipeline cannot publish a production installer until a valid externally issued code-signing certificate has been configured. A CI-only development certificate tests the complete installer-signing machinery; it is **not trusted on other computers** and CI-built test installers are never uploaded as public releases.

## Installation UX

1. Download the trusted, published installer from GitHub Releases, after signature publication is enabled.
2. Check the Windows Authenticode signer and displayed application name. Windows SmartScreen reputation may still take time to build; a signature alone does not guarantee absence of warnings.
3. Install to `%LOCALAPPDATA%\Programs\BootNexa Agent`. No UAC administrator elevation is requested.
4. Choose whether to start BootNexa at each sign-in (checked by default). The installer can launch the agent immediately after installation; silent CI installations explicitly suppress launch.
5. Open the BootNexa website configured in the agent's allowed-origin policy; its browser discovers `127.0.0.1:43627` automatically.
6. Approve the **native Windows prompt** to list connected USB devices read-only. This approval never grants erase/write authority.
7. Uninstall through Windows Settings → Installed Apps. The installer removes the application files and its owned autostart entry.

The executable runs as the current Windows user and hides its console window in release builds. To configure an external HTTPS site origin, set `BOOTNEXA_ALLOWED_ORIGIN` to one exact canonical origin before launching the agent. **The default remains the local development origin** `http://127.0.0.1:5173`; a public website has not been wired in as the production origin. Installer signing does not itself enable a deployed web site.

## Source and build inputs

| Artifact | Purpose |
| --- | --- |
| `packaging/windows/BootNexaAgent.iss` | Stable AppId, per-user installer, icon, shortcuts, startup option, embedded signed uninstaller |
| `packaging/windows/bootnexa.ico` | Multi-resolution icon generated from original BootNexa SVG |
| `scripts/windows/Signing.Common.ps1` | Certificate checks, SDK SignTool lookup, Authenticode verification |
| `scripts/windows/Sign-Artifact.ps1` | Signs the agent EXE; uses SHA-256 and an RFC 3161 timestamp for production |
| `scripts/windows/Build-Installer.ps1` | Locks package version to Cargo, signs EXE, signs setup/uninstaller and verifies outcome |
| `scripts/windows/New-TestCertificate.ps1` | One-day, non-exportable CI-only test certificate for isolated Windows runners |
| `scripts/windows/Import-ReleaseCertificate.ps1` | Fail-closed temporary import of trusted signing credentials |
| `tests/windows/installer-smoke.ps1` | Signed installer validation, silent per-user install, installed binary/API smoke, uninstall cleanup |
| `.github/workflows/web.yml` | Normal PR/main package smoke (no release upload) |
| `.github/workflows/release-agent.yml` | Manual protected trusted signing and release upload; requires configured credentials |

Build the Rust agent:

```powershell
cargo test --manifest-path agent/Cargo.toml --locked --all-targets
cargo build --manifest-path agent/Cargo.toml --release --locked
```

Install Inno Setup 6.7.1 and a Windows SDK containing `signtool.exe`. The build script requires a code-signing certificate already installed in `Cert:\CurrentUser\My` and takes its thumbprint. There is deliberately no `--allow-unsigned-release` flag.

**The `-Mode Test` signing operation must never be distributed as a public release.** It is for disposable CI validation only and is not equivalent to a production signature.

## Production release: required setup

A trusted production code-signing certificate must be acquired and backed by secure key custody. Preferred long-term approaches are a managed/HSM-backed signing service or delegated sign service. The included current workflow supports PFX import on a disposable, protected Windows runner.

1. Create and protect the GitHub `production` environment (required reviewers and restricted allowed branches/tags are recommended).
2. Store the base64-encoded PFX in the environment secret `BOOTNEXA_CODESIGN_PFX_B64`. Store its password in environment secret `BOOTNEXA_CODESIGN_PFX_PASSWORD`.
3. Pin the public signing-certificate thumbprint in environment variable `BOOTNEXA_CODESIGN_THUMBPRINT` (40 hex characters).
4. Limit environment access to trusted maintainers. Protect the `main` branch and tag creation.
5. Create an annotated `vX.Y.Z` tag pointing to a commit on `main`, where `X.Y.Z` exactly matches `agent/Cargo.toml`.
6. Manually dispatch **Signed BootNexa Windows agent release** with that existing tag. The action refuses untrusted/expired/test certificates, missing secrets, mismatched tags, a failed build, an unsigned/incorrectly signed file, or missing production timestamps.
7. Only after verification does the workflow publish the setup EXE and its SHA-256 manifest to GitHub Releases.

**No production certificate is currently configured in GitHub.** No production signed release can be created until that is completed. Never place a PFX/private key in source control, chat, runner artifacts, logs, or build parameters visible to third parties.

## Signature assertions

- Both agent EXE and setup/uninstaller are signed under the same pinned identity.
- Production uses SHA-256 and an RFC 3161 timestamp; installed code signing certificate must be valid and trusted.
- `Get-AuthenticodeSignature` must return `Valid`, with the expected thumbprint.
- In production Windows SDK `signtool verify /pa` must return success. Test mode checks Authenticode signer identity and requires the status to be either `Valid` or `NotTrusted` (not a hash mismatch); it never installs a test certificate as a trusted root.
- Inno signs its embedded uninstaller, not merely the outer setup EXE.
- Installation and uninstallation tests confirm a hash-identical installed agent and no startup entry after uninstall.
- PR CI generates an ephemeral self-signed signer on the runner only and validates the same packaging and verification mechanisms. This **does not** qualify real-world trust/SmartScreen reputation.
- The test certificate remains untrusted on Windows and is never imported into the Trusted Root store. The release job is manually triggered, checks a stable version tag on `main`, and requires signing credentials before producing any published artifacts.

## Explicit open items

- Acquire trusted production signing credentials; current repo secrets/variables are empty.
- Validate SmartScreen/Defender and actual Windows UAC/user journey on a real physical Windows machine.
- Validate interactive notification/tray lifecycle and native approval popup on a real logged-on Windows desktop.
- Configure and verify the HTTPS website origin, browser local-network permission, and installer user guidance.
- Build hardened auto-update with signed manifests and rollback protection (not implemented in 0.2).
- Obtain physical removable USB and hotplug coverage before claiming hardware acceptance.

Installer packaging is one readiness gate, not a substitute for these validations.
