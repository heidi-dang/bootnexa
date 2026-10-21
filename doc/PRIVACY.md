# BootNexa privacy policy

_Last updated: 21 October 2026_

## What the current application does

BootNexa is a web interface with an optional local, read-only Windows companion. The current agent can enumerate eligible removable USB disks after a Windows user confirms an operating-system prompt. BootNexa cannot format, erase, write, partition, or inspect the contents of a physical disk in its current release.

**The local agent does not transfer information to any external networked system.** It accepts requests only from the explicitly configured browser origin and listens on the local loopback interface (`127.0.0.1:43627`). The browser communicates directly with that local agent to display approved read-only USB device metadata: model, capacity, partition style, bus type, and an ephemeral display identifier.

The browser's image picker now reads a bounded header sample for local format inspection and streams the entire selected file through an in-browser Web Worker to calculate its SHA-256. Files and image contents are not uploaded to a BootNexa server or transferred to the native agent. The SHA-256 result, structure classification and optional publisher-provided checksum are displayed only in the page.

## Data and network boundaries

- **USB information:** Exposed only through the local agent's origin-restricted loopback API, after native Windows approval. Device content is not read or transmitted.
- **Agent access tokens:** Ephemeral, scoped to read-only device discovery and kept in the agent's memory and the current browser page's memory. They are not deliberately sent to cloud services or persisted by BootNexa.
- **Web hosting:** Visiting a publicly hosted BootNexa site will involve the hosting provider receiving ordinary network requests and potentially standard server logs. BootNexa cannot guarantee the logging or retention policy of a future third-party host that has not been selected.
- **Third-party destinations:** Links to GitHub, documentation, and other external services are separate websites subject to their own privacy policies. GitHub hosts source, issues, releases, and CI.
- **Analytics / telemetry:** The current BootNexa source does not implement an analytics SDK, crash-reporting uploader, account registration, or cloud image-upload service. Future features must document network traffic and require opt-in where appropriate.
- **Local diagnostic logs:** The Windows agent currently writes startup notices locally; operations and testing may produce local logs. Do not share logs with private device identifiers unless needed for support.
- **Permissions:** Native approval for read-only discovery is independent of any future destructive disk-operation consent. Revoking access discards active agent tokens.

## Retention and deletion

The companion stores access grants only for the lifetime of the agent process and expires sessions after a bounded interval. Stopping the agent or revoking access invalidates its in-memory grants. No BootNexa cloud account database is part of the current product.

## Changes and support

If local image handling, telemetry, updates, remote diagnostics, or signed distribution introduce new external network operations, this policy and the installation consent text must be reviewed and updated before those features are published.

Security and privacy questions may be raised through the project's [GitHub issues](https://github.com/heidi-dang/bootnexa/issues); do not include credentials or private disk contents in public issues.

This policy applies to the software shipped from [BootNexa's source repository](https://github.com/heidi-dang/bootnexa). It does not override the privacy terms of separately operated GitHub or web-hosting services.

## Optional Phase 4 simulation history

When the native agent is explicitly started with the Phase 4 simulation flag and a user-selected SQLite database path, it stores synthetic job phases, hashed mock identifiers, timestamps, byte counts, and sanitized failure codes on local disk. These records are not uploaded to a BootNexa service. The read-only loopback history routes require the usual origin-bound session token; remove the local SQLite file when you no longer need the simulator history. The feature is disabled by default and has no raw-media privileges.
