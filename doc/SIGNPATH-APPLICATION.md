# SignPath Foundation — BootNexa application dossier

**Status: NOT SUBMITTED / provider approval pending.** This dossier contains public project information only. It intentionally does not contain contact identity, credentials, signing tokens, or an assertion that SignPath has accepted BootNexa.

## Project profile

| Field | Value |
| --- | --- |
| Project name | BootNexa Agent |
| Source repository | https://github.com/heidi-dang/bootnexa |
| Source license | MIT — https://github.com/heidi-dang/bootnexa/blob/main/LICENSE |
| Primary platform | Windows 10/11 x64 |
| Language and build | Rust/Tokio, Cargo.lock, Windows GitHub Actions, Inno Setup |
| Product purpose | Read-only, locally installed companion that exposes eligible USB storage metadata to a consented BootNexa browser UI |
| Intended signed files | `bootnexa-agent.exe`, `BootNexa-Agent-*-windows-x64-Setup.exe`, signed Inno Setup embedded uninstaller |
| Code signing policy | https://github.com/heidi-dang/bootnexa/blob/main/doc/CODE-SIGNING-POLICY.md |
| Privacy policy | https://github.com/heidi-dang/bootnexa/blob/main/doc/PRIVACY.md |
| Installation and uninstall | https://github.com/heidi-dang/bootnexa/blob/main/doc/WINDOWS-INSTALLER.md |
| Acceptance evidence | https://github.com/heidi-dang/bootnexa/blob/main/doc/ACCEPTANCE-0.2.md |
| Signing blocker | https://github.com/heidi-dang/bootnexa/issues/5 |
| Official application | https://signpath.org/apply.html |

## Product description suitable for an application

BootNexa is an MIT-licensed, browser-first bootable-media utility in active development. Its current companion application is a Windows x64, per-user native process that performs *read-only* USB storage enumeration following an explicit native permission prompt. It does not yet include disk-writing, formatting, privilege escalation, cloud image upload, or telemetry. Source code, build scripts, a code-signing policy, security design, and automated Windows installer and uninstall tests are public on GitHub. A Windows release build is produced by controlled GitHub Actions. The project seeks publicly trusted code signing for its native executable and installer/uninstaller, with audited build provenance and manual release approval.

## Actual eligibility assessment

- **MIT licence / public source:** available; confirm any future dependencies, installers and binaries continue to satisfy Foundation terms.
- **Active maintenance:** GitHub commits and CI are available; ongoing external reputation is not established solely by a new repository.
- **Previously released binary:** **not met**. No publicly distributed Windows installer release has been published. SignPath requires an existing released application in the form intended to be signed. Ask SignPath whether a clearly labelled unsigned developer prerelease qualifies *before* publishing one. Do not describe a source-only commit as a released Windows binary.
- **Code signing policy, roles and privacy:** documented. Verify the responsible GitHub maintainer has 2FA enabled; API read access does not establish 2FA state.
- **Trusted build system and publisher identity:** CI is implemented. SignPath organization, project, release policy, origin attestation, approval roles, and managed certificate must be issued/configured by SignPath after enrollment.
- **Potential future scope change:** planned USB-write/Windows-installation customization may prompt additional eligibility and safety review. Apply with accurate current product scope and notify SignPath before materially expanding signed capabilities.

## SignPath-specific policy details

If SignPath Foundation accepts the project, use the required attribution in the public signing policy and release notes:

> Free code signing provided by SignPath.io, certificate by SignPath Foundation.

Do not present that sentence as a claim of current sponsorship or signed releases while the application remains pending. SignPath Foundation—not BootNexa—is the certificate publisher for free OSS signatures.

For provider-side policy, request: trusted GitHub Actions build verification; repository and ref restrictions; version/product metadata restrictions; separate release signing policy; human approval on every signing request; SHA-256 provenance; signing of the complete executable + Inno Setup installer + embedded uninstaller. Do not reuse the current PFX import workflow with SignPath's HSM private keys.

## What must be provided by the authorized maintainer

1. A real maintainer contact name and reachable email address in SignPath's application form, supplied to the provider directly.
2. Any mandatory identity, source-control MFA, organization, or external account confirmations.
3. Acceptance of provider agreements/terms under the maintainer's own authority.
4. Confirmation of the prerequisite released Windows binary or an explicit provider waiver/approved alternative.
5. After SignPath approval: the provider-issued organization ID, project slug, signing policy slug, approved CI integration method and scoped API token placed only in the GitHub protected production environment.

The submission form is a third-party HubSpot embedded form; it requires personal contact information and agreement handling. No application or legal agreement is submitted by creating this dossier.

## Production acceptance

A signing-provider onboarding task is **complete only when** the provider explicitly accepts the project and a Windows CI release successfully obtains a trusted, timestamped signature over the agent, setup and uninstaller. The installed payload must pass Authenticode verification, provenance and tamper tests; the exact version-tagged GitHub release must be approved and published.

Until then, the release workflow must remain blocked. Never close issue #5 solely because a mock/test certificate passes CI.
