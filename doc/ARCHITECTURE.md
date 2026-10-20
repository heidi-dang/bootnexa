# Architecture

## Overview

BootNexa is two cooperating products: a static browser-delivered application and an installed local Windows agent. The website never writes directly to disk, and the native agent never needs an account in a remote cloud.

```text
HTTPS web app (React / TypeScript)
  ├── workflow state and capability-aware controls
  ├── local image selection; no server upload
  ├── pairing / origin-bound agent session
  └── progress replay + operation reports
                │ loopback only
                ▼
Agent service (Rust / Tokio, unprivileged)
  ├── session authentication / origin policy
  ├── capability discovery and image inspection
  ├── device inventory and protected-disk classification
  ├── preflight plan / confirmation issuer
  ├── durable job journal and event stream
  └── per-device operation scheduler
                │ narrow local IPC / OS ACL
                ▼
Privileged disk helper (Rust + native Windows APIs)
  ├── verify caller and single-use plan
  ├── validate disk identity + operating-system-disk exclusion
  ├── lock and dismount exclusively
  ├── apply layout / write / flush / verify
  └── release locks + report evidence
                │
                ▼
       user-selected physical media
```

An optional web hosting service distributes static assets and public documentation only. It does not receive USB contents, disk image files or privileged operation requests.

## Authoritative state

The native agent, not React, is authoritative for devices, consent, job progress and verification. React state controls only UI presentation and requested preferences. A reconnect fetches the current job snapshot and replays events from the last acknowledged sequence. A progress percentage must be derived from bytes actually processed at the active stage.

```text
UI REQUEST -> validate inputs -> agent preflight -> explicit consent
  -> privileged recheck -> exclusive lock -> write -> flush -> verify
  -> release resources -> signed/recorded report -> UI outcome
```

The operation engine uses an explicit state machine and single-writer-per-device lock. User-initiated cancellation is a request, not evidence of immediate cancellation. The UI displays "cancelling" until the agent confirms cleanup.

## Image handling

A pipeline of `reader -> classifier -> planner -> writer -> verifier` separates format knowledge from physical I/O. Raw IMG writing is an early vertical slice; extracting ISO files, writing WIM components and integrating bootloaders are separate verified workflows. All decompression is size-bounded and parsing is hardened.

UI image selection via the browser File API is currently local-only. Phase 2 must define how bytes are streamed across the browser↔loopback boundary or selected via a trusted agent-native file picker. Arbitrary client-supplied file paths are forbidden.

## Data contracts

Suggested canonical objects:
- `AgentCapabilities { protocolVersion, agentVersion, platform, features[], limitations[] }`
- `DeviceSnapshot { opaqueId, model, bus, capacityBytes, removability, protected, generation }`
- `ImageAnalysis { digest, byteLength, format, bootEntries[], architecture?, warnings[] }`
- `PreflightPlan { nonce, imageDigest, deviceFingerprint, layoutDigest, expiresAt, warnings[] }`
- `JobEvent { jobId, sequence, phase, completedBytes, totalBytes?, code, timestamp }`
- `JobReport { jobId, result, imageDigest, deviceFingerprint, verificationCoverage, warnings[], evidence[] }`

Opaque IDs must expire with device enumeration revisions. Browser-facing payloads never include unrestricted physical device paths, command strings or OS admin tokens.

## Initial directory strategy

The initial project intentionally uses a single Vite application at repository root. When native engineering starts, move the UI to `apps/web`, add Rust `apps/agent` and `crates/` workspaces, and generate protocol types in `packages/contracts`. Avoid accidental backwards-incompatible API changes and protect every schema migration with integration fixtures.

## Failure model

| Failure | Required behaviour |
| --- | --- |
| Agent unavailable | Disable hardware actions; retain interface preview |
| Session expired | Re-pair; cannot reuse past consent |
| Target removed | Terminate job; media incomplete; report |
| Target identity changed | Refuse operation; require new selection and consent |
| Insufficient permissions | Guided local elevation; no silent bypass |
| Source file replaced | Detect identity/digest change and abort |
| Write short/error | Retry within bounded policy or fail with bytes written |
| Browser closed | Agent retains authoritative job and safe lifecycle |
| Agent restart | Restore journal to truthful interrupted/resumable state |
| Verification mismatch | Explicit failure, never "success with warning" |

## Observability

Jobs contain append-only redacted evidence: protocol version, device class/size, image digest, planned layout digest, operation timings, write/verify byte totals and stable error identifiers. User-controlled diagnostic export must redact serials, local usernames, file paths and media contents by default. Any optional telemetry is opt-in.

Read the detailed delivery gates in [ROADMAP.md](ROADMAP.md) and threat controls in [SECURITY.md](SECURITY.md).
