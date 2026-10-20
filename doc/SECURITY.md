# Security model

BootNexa is a disk modification utility. It must be designed as destructive software from day one, even while the current repository remains an interface preview.

## Trust boundaries

1. **Untrusted browser origin:** May request user-interface operations but cannot decide protected-disk identity or privileged disk paths.
2. **Untrusted images:** ISO/IMG/VHD/VHDX/FFU files may contain malicious headers, corrupted tables or decompression bombs.
3. **Unprivileged local agent:** Authenticates sessions, classifies images, inventories devices and produces proposed plans; no permanent elevated privileges.
4. **Privileged helper:** Receives only approved, expiring, single-use operation plans through OS-authenticated IPC.
5. **Physical disk:** Identity can change, disappear, fail, lie about removability or be remapped by the operating system.

## Primary threats and mandatory controls

| Threat | Control |
| --- | --- |
| Arbitrary site invokes `localhost` agent | Strict `Origin`/`Host`/remote-peer checks, explicit pairing, session-bound tokens, reject cross-site upgrades |
| DNS rebinding and PNA bypass | Loopback listener, host allowlist, no hostname-only trust, modern browser permission tests |
| CSRF and ambient credential abuse | No cookie-only auth, nonce/replay defence, every mutation authenticated |
| Replay of old erase approval | Bind token to target identity, generation, image digest, layout digest, user confirmation and expiry |
| OS disk selected as removable USB | Enumerate system volumes and ancestors; recheck inside privileged helper; fail closed on ambiguity |
| Hot swap between preview and write | Exclusive handle + identity revalidation before any modifying syscall |
| Unbounded filesystem/ISO parser input | Fuzzing, integer and range checks, parser isolation and output size limits |
| Path/symlink injection | Canonical trusted handles; do not execute shell commands from user strings |
| Incomplete write shown as complete | Durable state journal; flush and actual read-back checks required |
| Poisoned updater | Signed metadata and binary, pinned keys, secure rollback, no unsigned helper loading |
| Leaked private media | Local-only media transfer, scoped file handles, redacted logs, opt-in support export |

## Mandatory UX controls

Before an erase operation, show the *exact* selected device model, capacity, serial suffix if available, filesystem/partition changes, image name and irreversible effect. Require an affirmative action after agent-level preflight; do not preserve consent when the drive changes. Fixed/internal disks require a separately designed elevated risk flow and are disabled by default.

The browser must never offer a working "Start" action without the agent confirming sufficient privileges, a still-valid target identity, supported format and a fresh consent token.

## Vulnerability handling

Do not publish exploit details affecting real disk erasure until a patch is available. Report suspected problems through the repository's security advisory channel. Never attach private disk images or device identifiers to a public issue.

## Distribution and licensing

The original browser UI can be distributed under this repository's licence. Rufus is GPLv3-or-later; incorporating its code into distributed binaries creates corresponding obligations. Selective reuse, bootloader redistribution, wimlib, Windows tools and operating-system image acquisition require a recorded legal/technical review *before* introducing dependencies. No third-party proprietary binaries are bundled by default.

## Minimum security release tests

- hostile origins; forged headers; WebSocket and SSE authentication; expired tokens; revoked sessions
- parallel jobs, stale preflight, USB disconnect/reconnect, index reuse and forged capacity
- system volume exclusions; protected partition mapping; mountpoint races and cross-user privilege boundaries
- archive/ISO fuzz corpus; integer overflows; symlink and path canonicalisation
- privileged helper RPC schema fuzzing; time-of-check/time-of-use attacks
- agent updater tampering; signature mismatch; downgrade and partial upgrades
- real hardware fault injection on sacrificial media, never production drives
