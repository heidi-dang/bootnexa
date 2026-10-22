# Windows read-only authenticated named-pipe diagnostic

**Status:** Developer/CI-only, one-connection, non-elevated diagnostic; not a production privileged helper, not installed with the end-user agent, and never authorized to write physical media.

## Threat boundary

The separate Windows binary `bootnexa-readonly-broker.exe --serve-once` creates an unpredictable per-run pipe name and a protected Windows DACL granting access only to LocalSystem and the current user's token SID. The pipe requests a first-instance name and rejects remote clients. Every connection is checked against the client process ID supplied by Windows, the process token SID and Windows logon session. After reading its request frame, the broker impersonates the pipe client, checks the thread token SID independently against both the server and client process SID, and reverts impersonation on all control paths. Failures deny service; no caller-controlled target, disk or privilege exists.

A fixed 20-byte version/challenge response is followed by one 21-byte request frame containing protocol magic, read-only operation code and the fresh 128-bit challenge. Invalid, unsupported, tampered or destructive operation codes are rejected. The broker uses the preexisting read-only Storage/CIM and SetupAPI/IOCTL safety collector, bounds the JSON result to 1 MiB, and serves one request before exiting. The CLI client outputs only a redacted summary. This **does not** authenticate a signed application binary: another same-user same-session process may also request read-only evidence.

This is a **development safety experiment**, not a production-ready Windows service. The synchronous IPC currently lacks overlapped timeouts and Windows executable Authenticode identity checks. Windows platform hardening, cross-user/low-integrity ACL testing and independent security review remain necessary before production packaging. The separately defined test-only HMAC request protocol remains test-only; the native transport currently relies on OS-verified process/thread token and a random challenge, not on that HMAC protocol.

## Qualification

Windows CI executes `tests/windows/pipe-smoke.ps1` against the real release-built binary. It verifies a legitimate local read-only report and rejection of unsupported operation, altered challenge, invalid version, arbitrary pipe namespace and a disk-writing command. The existing test installer must **exclude** both the developer safety probe and read-only IPC binary. The Windows agent still exposes no destructive route, no write-capable physical disk handle, no elevation or formatting operation.

**Release blockers remain open:** [physical USB safety #13](https://github.com/heidi-dang/bootnexa/issues/13) and [trusted production code signing #5](https://github.com/heidi-dang/bootnexa/issues/5). A pipe authorization does not constitute destructive device consent or physical media qualification.


## Pipe lifecycle detail

After writing the length-prefixed report, the broker calls Win32 FlushFileBuffers **on the named pipe** to ensure the client has drained its response before DisconnectNamedPipe destroys buffered data. This is local IPC synchronization; it is NOT a USB storage flush, disk write, or a relaxation of Windows process/token authentication.

## Adversarial Windows hardening milestone (developer-only)

The read-only one-shot broker has a bounded overall **30-second** lifetime, including blocked Win32 ConnectNamedPipe, ReadFile, the diagnostic safety-report provider and pipe-only FlushFileBuffers. The diagnostic command supports a **test-only bounded deadline override** between 750 ms and 30 seconds. A watchdog exits the one-shot process with status 124 on expiry; blocked synchronous Win32 operations cannot outlive the process. This is fail-closed but is **not equivalent** to a production service using cancelable overlapped I/O.

The Windows CI adversarial acceptance creates an ephemeral temporary local Windows user, obtains its real Windows logon token and impersonates that user to attempt native CreateFile access to the currently active protected named pipe. Access must fail with ACCESS_DENIED (5); the temporary user is removed in a finally block. A separately restricted low-integrity token must likewise be denied writable pipe access. The original same-user client must still retrieve a read-only report. Independently, the one-shot watchdog is checked against no-client, silent-client and partial-frame stalls; all must exit 124 inside a bounded test window.

This proves only the specific temporary-user and low-integrity token cases on the GitHub Windows runner. It does not establish a complete Windows security review, signed executable identity, production-safe deadline cancellation or destructive operation authority. **Real USB writing remains disabled.**
