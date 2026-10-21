# BootNexa code signing policy

BootNexa binaries are released only from reviewed source and verifiable CI builds. The purpose of the signature is to establish the software publisher, preserve integrity, and identify the source revision that produced each distributed Windows package.

## Release authority

**Source repository:** https://github.com/heidi-dang/bootnexa

**Allowed source:** An immutable `vX.Y.Z` tag pointing at the **current `main` HEAD** when signing starts. Releases from unmerged branches, forks, pull requests, stale tags, arbitrary workflow revisions, or unverifiable binaries are prohibited.

**Build host:** GitHub-hosted Windows runner using Cargo's checked-in lockfile and a pinned Inno Setup compiler. The executable, installer and embedded uninstaller must all bear an approved, publicly trusted Authenticode signature.

**Human release approval:** The protected GitHub `production` environment requires an explicitly approved deployment before any signing credentials can be read. Administrators cannot bypass the environment protection rule. SignPath Foundation (if approved) will additionally require its own signing approval/origin verification policy.

**Integrity verification:** The signer certificate is pinned; chain and code-signing EKU are checked; production timestamps are required; the installed EXE and uninstaller must verify under the same publisher identity; installation/uninstallation and read-only runtime smoke tests must pass. A SHA-256 manifest accompanies the release.

**Versioning:** Product name is **BootNexa Agent**, package version is the Cargo version and Git tag, and the release record identifies the exact Git commit. Never sign software from unrelated or upstream projects using BootNexa's certificate.

**Security:** No keys, exported private certificates, provider tokens or passwords are committed to the repository, build artifacts, package archive, support logs or pull request output. Production signing requires a trusted provider and restricted runner identity; an unsigned or test-signed artifact is never an acceptable public-release fallback.

**Fail closed:** Missing/expired credentials, failed human review, unsigned/changed payload, untrusted or mismatched signing identity, timestamp failure, stale source or CI failure block publication. Do not tell users that a test-signed artifact is publicly trusted.

## Signing responsibilities and privacy

**Maintainer / author:** [heidi-dang](https://github.com/heidi-dang), repository owner, responsible for maintained source and CI definitions.

**Commit reviewer:** [heidi-dang](https://github.com/heidi-dang); external contributions must be reviewed by the repository owner before merging. Repository permissions and documented review requirements are authoritative and must be verified before a public signed release.

**Release approver:** [heidi-dang](https://github.com/heidi-dang), configured as the required reviewer of GitHub's protected `production` environment. If SignPath Foundation accepts BootNexa, each signing request additionally requires the provider-configured human approver. The publishing workflow may not bypass that approval.

**MFA requirement:** All maintainers and signers must use multi-factor authentication on GitHub and the signing provider. GitHub's connected API did not establish whether MFA is enabled for this account; maintainer verification is outstanding.

**Privacy:** [BootNexa privacy policy](PRIVACY.md). The current local agent does not transmit device information to an external networked system; only authorised loopback metadata access is implemented. GitHub-hosted services and optional web hosting have separate data policies.

**SignPath Foundation applicant status:** The project is preparing an application, not yet approved. If accepted, the signing policy and releases will include: *Free code signing provided by SignPath.io, certificate by SignPath Foundation.* No current public executable is signed by that foundation.

## Public distribution status

As of 21 October 2026, the native agent remains read-only and the production code-signing certificate/provider has **not been enrolled**. CI exercises the complete package pipeline using an ephemeral, untrusted test signer; **no publicly trusted Windows installer has been released**.

## Applying for a publicly trusted signature

The project is public and MIT licensed. The preferred initial review is the [SignPath Foundation open-source signing programme](https://signpath.org/apply), subject to independent programme approval and its release, maintenance, multi-factor authentication, repository, publisher metadata, manual approval and attested build policies. Provider approval is not automated or guaranteed. SignPath's remote signing infrastructure and HSM keys are preferable to distributing private keys to build machines.

After acceptance, integrate and independently qualify the provider-approved signing path—including Inno Setup's signed embedded uninstaller—before enabling the public release workflow. The existing PFX route is an opt-in alternative **only for certificates whose secure issuance and permitted key custody support a protected CI import**. Newly issued public code-signing certificates generally use hardware-protected keys; do not export one merely to satisfy this pipeline.

See [Windows installer and signing](WINDOWS-INSTALLER.md), [release workflow](../.github/workflows/release-agent.yml), and [SignPath Foundation conditions](https://signpath.org/terms.html).
