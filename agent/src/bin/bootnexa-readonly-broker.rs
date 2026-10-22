#[cfg(windows)]
mod windows {
    //! Developer-only, one-shot read-only Windows named pipe.
    //! Windows enforces the pipe DACL, remote-client rejection, token SID and session.
    //! No write-capable device handles, service installation, or elevation exist.
    use bootnexa_agent::safety_report::collect;
    use std::{
        ffi::c_void,
        io::{self, Write},
        mem::size_of,
        ptr::{null, null_mut},
        slice,
    };
    type Handle = *mut c_void;
    const INVALID: Handle = !0usize as Handle;
    const TOKEN_QUERY: u32 = 0x0008;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PIPE_ACCESS_DUPLEX: u32 = 3;
    const PIPE_TYPE_MESSAGE: u32 = 4;
    const PIPE_READMODE_MESSAGE: u32 = 2;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;
    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const FILE_SHARE_NONE: u32 = 0;
    const OPEN_EXISTING: u32 = 3;
    const MAX_REPORT: usize = 1024 * 1024;
    const PROTOCOL_MAGIC: &[u8; 4] = b"BNX1";
    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit: i32,
    }
    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn OpenThreadToken(
            thread: Handle,
            access: u32,
            open_as_self: i32,
            token: *mut Handle,
        ) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut c_void,
            length: u32,
            return_len: *mut u32,
        ) -> i32;
        fn EqualSid(one: *const c_void, two: *const c_void) -> i32;
        fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            length: *mut u32,
        ) -> i32;
        fn ImpersonateNamedPipeClient(pipe: Handle) -> i32;
        fn RevertToSelf() -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn GetCurrentThread() -> Handle;
        fn GetCurrentProcessId() -> u32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        fn GetLastError() -> u32;
        fn LocalFree(ptr: *mut c_void) -> *mut c_void;
        fn CreateNamedPipeW(
            path: *const u16,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_buffer: u32,
            in_buffer: u32,
            timeout: u32,
            attributes: *const SecurityAttributes,
        ) -> Handle;
        fn ConnectNamedPipe(pipe: Handle, overlap: *mut c_void) -> i32;
        fn DisconnectNamedPipe(pipe: Handle) -> i32;
        fn GetNamedPipeClientProcessId(pipe: Handle, pid: *mut u32) -> i32;
        fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
        fn CreateFileW(
            path: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn ReadFile(
            file: Handle,
            buffer: *mut c_void,
            size: u32,
            read: *mut u32,
            overlap: *mut c_void,
        ) -> i32;
        fn WriteFile(
            file: Handle,
            buffer: *const c_void,
            size: u32,
            written: *mut u32,
            overlap: *mut c_void,
        ) -> i32;
    }
    struct OwnedHandle(Handle);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    impl OwnedHandle {
        fn wrap(handle: Handle) -> io::Result<Self> {
            if handle.is_null() || handle == INVALID {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(handle))
            }
        }
    }
    fn utf16(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn sid_bytes(token: Handle) -> io::Result<Vec<u64>> {
        let mut bytes = 0u32;
        unsafe {
            GetTokenInformation(token, 1, null_mut(), 0, &mut bytes);
        }
        if !(size_of::<SidAndAttributes>()..=4096).contains(&(bytes as usize)) {
            return Err(io::Error::other("invalid token user info size"));
        }
        let mut info = vec![0u64; (bytes as usize).div_ceil(8)];
        if unsafe { GetTokenInformation(token, 1, info.as_mut_ptr().cast(), bytes, &mut bytes) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }
    fn process_token(pid: Option<u32>) -> io::Result<OwnedHandle> {
        let process = if let Some(pid) = pid {
            OwnedHandle::wrap(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?
        } else {
            OwnedHandle(unsafe { GetCurrentProcess() })
        };
        // The pseudo-handle must never be closed.
        let mut token = null_mut();
        let ok = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) };
        if pid.is_none() {
            std::mem::forget(process);
        }
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::wrap(token)
    }
    fn user_sid(token: Handle) -> io::Result<Vec<u64>> {
        sid_bytes(token)
    }
    fn sid_pointer(info: &[u64]) -> *const c_void {
        unsafe { (*(info.as_ptr().cast::<SidAndAttributes>())).sid }
    }
    fn same_sid(a: &[u64], b: &[u64]) -> bool {
        unsafe { EqualSid(sid_pointer(a), sid_pointer(b)) != 0 }
    }
    fn sid_sddl(info: &[u64]) -> io::Result<String> {
        let mut text = null_mut();
        if unsafe { ConvertSidToStringSidW(sid_pointer(info), &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if text.is_null() {
            return Err(io::Error::other("no SID"));
        }
        let mut len = 0usize;
        unsafe {
            while len < 256 && *text.add(len) != 0 {
                len += 1;
            }
        }
        let value = String::from_utf16(unsafe { slice::from_raw_parts(text, len) })
            .map_err(|_| io::Error::other("invalid SID UTF16"));
        unsafe {
            LocalFree(text.cast());
        }
        value
    }
    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    fn secure_descriptor(owner_sid: &[u64]) -> io::Result<Descriptor> {
        let sid = sid_sddl(owner_sid)?;
        // Protected DACL: LocalSystem and exact current-user SID only.
        let sddl = utf16(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"));
        let mut desc = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut desc,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(desc))
    }
    fn current_session(pid: u32) -> io::Result<u32> {
        let mut id = 0;
        if unsafe { ProcessIdToSessionId(pid, &mut id) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(id)
        }
    }
    fn verify_client(pipe: Handle, owner_sid: &[u64]) -> io::Result<()> {
        let mut pid = 0u32;
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid == 0 {
            return Err(io::Error::other("missing client PID"));
        }
        if current_session(pid)? != current_session(unsafe { GetCurrentProcessId() })? {
            return Err(io::Error::other("cross-session client denied"));
        }
        let process = process_token(Some(pid))?;
        let process_sid = user_sid(process.0)?;
        if !same_sid(owner_sid, &process_sid) {
            return Err(io::Error::other("client process SID mismatch"));
        }
        // Impersonation must happen AFTER ReadFile has received the client's
        // message, otherwise Windows can report an inappropriate security level.
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(io::Error::last_os_error());
        }
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() } == 0 {
                    // Cannot safely resume with unknown impersonation context.
                    std::process::abort();
                }
            }
        }
        let _revert = Revert;
        let mut thread_token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let thread = OwnedHandle::wrap(thread_token)?;
        let thread_sid = user_sid(thread.0)?;
        if !same_sid(owner_sid, &thread_sid) || !same_sid(&process_sid, &thread_sid) {
            return Err(io::Error::other("client impersonation SID mismatch"));
        }
        Ok(())
    }
    fn read_fixed(pipe: Handle, output: &mut [u8]) -> io::Result<()> {
        let mut read = 0;
        let ok = unsafe {
            ReadFile(
                pipe,
                output.as_mut_ptr().cast(),
                output.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        if ok == 0 || read as usize != output.len() {
            return Err(io::Error::other("invalid pipe frame"));
        }
        Ok(())
    }
    fn write_all(pipe: Handle, bytes: &[u8]) -> io::Result<()> {
        for part in bytes.chunks(4096) {
            let mut written = 0;
            let ok = unsafe {
                WriteFile(
                    pipe,
                    part.as_ptr().cast(),
                    part.len() as u32,
                    &mut written,
                    null_mut(),
                )
            };
            if ok == 0 || written as usize != part.len() {
                return Err(io::Error::other("pipe write failed"));
            }
        }
        Ok(())
    }
    fn pipe_name() -> String {
        format!(r"\\.\pipe\bootnexa-ro-{}", uuid::Uuid::new_v4().simple())
    }
    fn validate_pipe_name(value: &str) -> bool {
        let Some(suffix) = value.strip_prefix(r"\\.\pipe\bootnexa-ro-") else {
            return false;
        };
        suffix.len() == 32 && suffix.bytes().all(|c| c.is_ascii_hexdigit())
    }
    fn denied(operation: u8) -> bool {
        operation != 1
    }
    async fn serve() -> io::Result<()> {
        let self_token = process_token(None)?;
        let owner = user_sid(self_token.0)?;
        let descriptor = secure_descriptor(&owner)?;
        let attrs = SecurityAttributes {
            length: size_of::<SecurityAttributes>() as u32,
            descriptor: descriptor.0,
            inherit: 0,
        };
        let path = pipe_name();
        let wide = utf16(&path);
        let pipe = OwnedHandle::wrap(unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                8192,
                8192,
                10000,
                &attrs,
            )
        })?;
        println!("{path}");
        io::stdout().flush()?;
        // One session and one request. Service installation is deliberately absent.
        if unsafe { ConnectNamedPipe(pipe.0, null_mut()) } == 0 && unsafe { GetLastError() } != 535
        {
            // ERROR_PIPE_CONNECTED is a normal race after publishing the
            // unpredictable endpoint and before ConnectNamedPipe.
            return Err(io::Error::last_os_error());
        }
        let result = async {
            let nonce: [u8; 16] = rand::random();
            let mut hello = [0u8; 20];
            hello[..4].copy_from_slice(PROTOCOL_MAGIC);
            hello[4..].copy_from_slice(&nonce);
            write_all(pipe.0, &hello)?;
            let mut request = [0u8; 21];
            read_fixed(pipe.0, &mut request)?;
            verify_client(pipe.0, &owner)?;
            if &request[..4] != PROTOCOL_MAGIC || denied(request[4]) || request[5..] != nonce {
                return Err(io::Error::other("invalid or destructive operation denied"));
            }
            let body = serde_json::to_vec(&collect().await.map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
            if body.len() > MAX_REPORT {
                return Err(io::Error::other("oversized safety report"));
            }
            let length = (body.len() as u32).to_le_bytes();
            write_all(pipe.0, &length)?;
            write_all(pipe.0, &body)?;
            Ok(())
        }
        .await;
        unsafe {
            DisconnectNamedPipe(pipe.0);
        }
        result
    }
    fn client(path: &str, mode: &str) -> io::Result<()> {
        if !validate_pipe_name(path) {
            return Err(io::Error::other("invalid pipe name"));
        }
        let wide = utf16(path);
        let pipe = OwnedHandle::wrap(unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_NONE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        })?;
        let mut hello = [0u8; 20];
        read_fixed(pipe.0, &mut hello)?;
        if &hello[..4] != PROTOCOL_MAGIC {
            return Err(io::Error::other("unsupported protocol"));
        }
        let mut req = [0u8; 21];
        req[..4].copy_from_slice(PROTOCOL_MAGIC);
        req[4] = if mode == "--client-invalid-op" { 2 } else { 1 };
        req[5..].copy_from_slice(&hello[4..]);
        if mode == "--client-bad-nonce" {
            req[5] ^= 0x80;
        }
        if mode == "--client-invalid-version" {
            req[3] ^= 1;
        }
        write_all(pipe.0, &req)?;
        let mut prefix = [0u8; 4];
        read_fixed(pipe.0, &mut prefix)?;
        let len = u32::from_le_bytes(prefix) as usize;
        if len == 0 || len > MAX_REPORT {
            return Err(io::Error::other("invalid response length"));
        }
        let mut data = vec![0u8; len];
        // Message-mode pipes need one read per message, not partial ReadFile.
        for segment in data.chunks_mut(4096) {
            read_fixed(pipe.0, segment)?;
        }
        let value: serde_json::Value = serde_json::from_slice(&data).map_err(io::Error::other)?;
        if value["physicalWriteAuthorized"] != false
            || value["protectedAncestry"]["physicalWriteAuthorized"] != false
            || value["protectedAncestry"]["protectedRoleEvidenceComplete"] != false
        {
            return Err(io::Error::other(
                "safety report falsely grants write authority",
            ));
        }
        println!(
            "{}",
            serde_json::json!({"readOnly":true,"physicalWriteAuthorized":false,
        "authenticatedWindowsPeer":true,"request":"read_only_safety_report",
        "protectedDiskCount":value["protectedAncestry"]["disks"].as_array().map_or(0,|v|v.len())})
        );
        Ok(())
    }
    #[tokio::main]
    pub async fn run() {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let result = match args.as_slice() {
            [flag] if flag == "--serve-once" => serve().await,
            [flag, name]
                if [
                    "--client",
                    "--client-invalid-op",
                    "--client-bad-nonce",
                    "--client-invalid-version",
                ]
                .contains(&flag.as_str()) =>
            {
                client(name, flag)
            }
            _ => {
                eprintln!("read-only usage: --serve-once or --client <generated-pipe-name>");
                std::process::exit(2);
            }
        };
        if let Err(e) = result {
            eprintln!("read-only pipe refused request: {}", e.kind());
            std::process::exit(1);
        }
    }
}
#[cfg(windows)]
fn main() {
    windows::run();
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows read-only IPC unavailable");
    std::process::exit(1);
}
