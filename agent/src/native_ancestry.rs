//! Windows-only, read-only native SetupAPI + Storage IOCTL topology evidence.
//! No target is supplied by a caller. Device handles use desired-access = 0,
//! and the ONLY IOCTLs permitted here query device numbers and volume extents.
//! This evidence is advisory and never grants write authority.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NativeExtent {
    pub disk_number: u32,
    pub starting_offset: u64,
    pub extent_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NativeVolume {
    /// A volume may span multiple disks; grouping must not be lost.
    pub extents: Vec<NativeExtent>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NativeObservation {
    pub disk_interface_numbers: Vec<u32>,
    pub volumes: Vec<NativeVolume>,
    pub interfaces_complete: bool,
    pub volumes_complete: bool,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeAncestryReport {
    pub read_only: bool,
    pub physical_write_authorized: bool,
    pub two_snapshots_agree: bool,
    pub native_ancestry_complete: bool,
    pub disk_interfaces: usize,
    pub scanned_volumes: usize,
    pub mapped_extents: usize,
    pub risk_codes: Vec<&'static str>,
}
/// Pure Rust, adversarially testable evidence evaluation. Even a perfect
/// native snapshot is NOT the OS-protected-roles proof required for a writer.
pub fn assess_native(
    known_disks: &BTreeSet<u32>,
    first: &NativeObservation,
    second: &NativeObservation,
) -> NativeAncestryReport {
    let mut codes = vec![];
    let mut count = HashSet::new();
    if first
        .disk_interface_numbers
        .iter()
        .any(|x| !count.insert(*x))
    {
        codes.push("duplicate_disk_interface");
    }
    let numbers: BTreeSet<_> = first.disk_interface_numbers.iter().copied().collect();
    if numbers.iter().any(|x| !known_disks.contains(x)) {
        codes.push("unknown_interface_disk");
    }
    if known_disks.iter().any(|x| !numbers.contains(x)) {
        codes.push("disk_interface_missing");
    }
    if first.disk_interface_numbers.len() > 128 || first.volumes.len() > 1024 {
        codes.push("native_inventory_too_large");
    }
    if !first.interfaces_complete
        || !first.volumes_complete
        || !second.interfaces_complete
        || !second.volumes_complete
    {
        codes.push("native_query_incomplete");
    }
    let mut attached = HashSet::<u32>::new();
    let mut edges = 0usize;
    for volume in &first.volumes {
        if volume.extents.is_empty() || volume.extents.len() > 256 {
            codes.push("invalid_volume_extents");
        }
        let unique = volume
            .extents
            .iter()
            .map(|e| e.disk_number)
            .collect::<HashSet<_>>();
        if unique.len() > 1 {
            codes.push("multi_disk_volume_needs_protected_role_mapping");
        }
        for e in &volume.extents {
            edges += 1;
            attached.insert(e.disk_number);
            if e.extent_bytes == 0 || e.starting_offset.checked_add(e.extent_bytes).is_none() {
                codes.push("invalid_volume_extents");
            }
            if !numbers.contains(&e.disk_number) || !known_disks.contains(&e.disk_number) {
                codes.push("unknown_volume_parent_disk");
            }
        }
    }
    // SetupAPI disk interfaces can include virtual storage; any uncertainty
    // is preserved for the eventual elevated device policy.
    if edges > 16384 {
        codes.push("native_inventory_too_large");
    }
    if known_disks.iter().any(|x| !attached.contains(x)) {
        codes.push("disk_without_mapped_volume");
    }
    let stable = first == second;
    if !stable {
        codes.push("native_topology_changed");
    }
    codes.sort_unstable();
    codes.dedup();
    NativeAncestryReport {
        read_only: true,
        physical_write_authorized: false,
        two_snapshots_agree: stable,
        native_ancestry_complete: codes.is_empty(),
        disk_interfaces: numbers.len(),
        scanned_volumes: first.volumes.len(),
        mapped_extents: edges,
        risk_codes: codes,
    }
}

#[cfg(windows)]
mod win {
    use super::{NativeExtent, NativeObservation, NativeVolume};
    use std::{
        ffi::c_void,
        mem::{size_of, zeroed},
        ptr::{null, null_mut},
    };
    type Handle = *mut c_void;
    const INVALID: Handle = !0usize as Handle;
    const DIGCF_PRESENT: u32 = 0x02;
    const DIGCF_DEVICEINTERFACE: u32 = 0x10;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const ERROR_NO_MORE_FILES: u32 = 18;
    const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002d1080;
    const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x00560000;
    const FILE_SHARE_ALL: u32 = 0x01 | 0x02 | 0x04;
    const OPEN_EXISTING: u32 = 3;
    const MAX_IFACES: u32 = 128;
    const MAX_VOLUMES: u32 = 1024;
    #[repr(C)]
    struct Guid {
        d1: u32,
        d2: u16,
        d3: u16,
        d4: [u8; 8],
    }
    // GUID_DEVINTERFACE_DISK, defined by ntddstor.h
    const DISK_GUID: Guid = Guid {
        d1: 0x53f56307,
        d2: 0xb6bf,
        d3: 0x11d0,
        d4: [0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b],
    };
    #[repr(C)]
    struct InterfaceData {
        cb_size: u32,
        guid: Guid,
        flags: u32,
        reserved: usize,
    }
    #[link(name = "setupapi")]
    unsafe extern "system" {
        fn SetupDiGetClassDevsW(
            guid: *const Guid,
            enumerator: *const u16,
            parent: Handle,
            flags: u32,
        ) -> Handle;
        fn SetupDiEnumDeviceInterfaces(
            set: Handle,
            info: *const c_void,
            guid: *const Guid,
            index: u32,
            data: *mut InterfaceData,
        ) -> i32;
        fn SetupDiGetDeviceInterfaceDetailW(
            set: Handle,
            data: *const InterfaceData,
            detail: *mut c_void,
            size: u32,
            required: *mut u32,
            info: *mut c_void,
        ) -> i32;
        fn SetupDiDestroyDeviceInfoList(set: Handle) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            path: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        fn DeviceIoControl(
            h: Handle,
            code: u32,
            inbuf: *const c_void,
            inlen: u32,
            outbuf: *mut c_void,
            outlen: u32,
            bytes: *mut u32,
            overlap: *mut c_void,
        ) -> i32;
        fn FindFirstVolumeW(name: *mut u16, len: u32) -> Handle;
        fn FindNextVolumeW(iter: Handle, name: *mut u16, len: u32) -> i32;
        fn FindVolumeClose(iter: Handle) -> i32;
        fn GetLastError() -> u32;
    }
    struct File(Handle);
    impl File {
        fn open(path: &[u16]) -> Option<Self> {
            // SAFETY: A valid NUL-terminated UTF-16 string and zero desired
            // access; sharing does not acquire a lock or writable handle.
            let h = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    0,
                    FILE_SHARE_ALL,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            (h != INVALID && !h.is_null()).then_some(Self(h))
        }
        fn ioctl(&self, code: u32, out: &mut [u64]) -> Option<usize> {
            let mut returned = 0u32;
            // SAFETY: The output buffer is aligned and length-bounded. The
            // IOCTL code is fixed to one of the two read-only queries above.
            let ok = unsafe {
                DeviceIoControl(
                    self.0,
                    code,
                    null(),
                    0,
                    out.as_mut_ptr().cast(),
                    (out.len() * 8) as u32,
                    &mut returned,
                    null_mut(),
                )
            };
            (ok != 0 && returned as usize <= out.len() * 8).then_some(returned as usize)
        }
    }
    impl Drop for File {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    fn utf16(path: &[u16]) -> Vec<u16> {
        let end = path.iter().position(|x| *x == 0).unwrap_or(path.len());
        let mut output = path[..end].to_vec();
        output.push(0);
        output
    }
    fn interfaces() -> (Vec<u32>, bool) {
        // SAFETY: SetupAPI is queried with a fixed class GUID and present-only
        // interface flag. Its handles are closed on every return path.
        let set = unsafe {
            SetupDiGetClassDevsW(
                &DISK_GUID,
                null(),
                null_mut(),
                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
            )
        };
        if set == INVALID || set.is_null() {
            return (vec![], false);
        }
        let mut disk_numbers = vec![];
        let mut complete = true;
        for index in 0..=MAX_IFACES {
            if index == MAX_IFACES {
                complete = false;
                break;
            }
            // SAFETY: repr(C) struct with required size, populated by Win32.
            let mut interface: InterfaceData = unsafe { zeroed() };
            interface.cb_size = size_of::<InterfaceData>() as u32;
            let ok = unsafe {
                SetupDiEnumDeviceInterfaces(set, null(), &DISK_GUID, index, &mut interface)
            };
            if ok == 0 {
                if unsafe { GetLastError() } != ERROR_NO_MORE_ITEMS {
                    complete = false;
                }
                break;
            }
            let mut required = 0u32;
            unsafe {
                SetupDiGetDeviceInterfaceDetailW(
                    set,
                    &interface,
                    null_mut(),
                    0,
                    &mut required,
                    null_mut(),
                );
            }
            if !(8..=8192).contains(&required) {
                complete = false;
                continue;
            }
            // Vec<u64> provides alignment >= DWORD while carrying UTF-16.
            let mut detail = vec![0_u64; required.div_ceil(8) as usize];
            let pointer = detail.as_mut_ptr().cast::<u8>();
            // SP_DEVICE_INTERFACE_DETAIL_DATA_W.cbSize is 8 on x64.
            unsafe {
                pointer.cast::<u32>().write_unaligned(8);
            }
            let ok = unsafe {
                SetupDiGetDeviceInterfaceDetailW(
                    set,
                    &interface,
                    detail.as_mut_ptr().cast(),
                    required,
                    &mut required,
                    null_mut(),
                )
            };
            if ok == 0 {
                complete = false;
                continue;
            }
            let wchar_count = (required as usize).saturating_sub(4) / 2;
            // SAFETY: detail holds required allocated bytes, and we use its
            // designated WCHAR path offset, bounded to its allocation.
            let path =
                unsafe { std::slice::from_raw_parts(pointer.add(4).cast::<u16>(), wchar_count) };
            let Some(device) = File::open(&utf16(path)) else {
                complete = false;
                continue;
            };
            let mut response = [0u64; 2];
            match device.ioctl(IOCTL_STORAGE_GET_DEVICE_NUMBER, &mut response) {
                Some(n) if n >= 12 => {
                    let ptr = response.as_ptr().cast::<u32>();
                    // SAFETY: 12 returned bytes, three aligned u32 values.
                    let (device_type, number) = unsafe { (*ptr, *ptr.add(1)) };
                    if device_type == 7 && number != u32::MAX {
                        disk_numbers.push(number);
                    } else {
                        complete = false;
                    }
                }
                _ => complete = false,
            }
        }
        unsafe {
            SetupDiDestroyDeviceInfoList(set);
        }
        disk_numbers.sort_unstable();
        (disk_numbers, complete)
    }
    fn volumes() -> (Vec<NativeVolume>, bool) {
        let mut name = [0u16; 1024];
        // SAFETY: Fixed-size WCHAR buffer, Win32 enumeration only.
        let iter = unsafe { FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
        if iter == INVALID || iter.is_null() {
            return (vec![], false);
        }
        let mut all = vec![];
        let mut complete = true;
        for index in 0..=MAX_VOLUMES {
            if index == MAX_VOLUMES {
                complete = false;
                break;
            }
            // Windows volume names end in '\'; CreateFile requires no tail slash.
            let mut path = utf16(&name);
            if path.len() < 3 || path[path.len() - 2] != b'\\' as u16 {
                complete = false;
            } else {
                path.remove(path.len() - 2);
                let result = File::open(&path);
                if let Some(volume) = result {
                    let mut output = [0u64; 1024];
                    match volume.ioctl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, &mut output) {
                        Some(n) if n >= 32 => {
                            let bytes = unsafe {
                                std::slice::from_raw_parts(output.as_ptr().cast::<u8>(), n)
                            };
                            let count =
                                u32::from_ne_bytes(bytes[0..4].try_into().unwrap()) as usize;
                            if count == 0 || count > 256 || 8 + 24 * count > n {
                                complete = false;
                            } else {
                                let mut extents = vec![];
                                for i in 0..count {
                                    let offset = 8 + i * 24;
                                    let disk = u32::from_ne_bytes(
                                        bytes[offset..offset + 4].try_into().unwrap(),
                                    );
                                    let start = i64::from_ne_bytes(
                                        bytes[offset + 8..offset + 16].try_into().unwrap(),
                                    );
                                    let length = i64::from_ne_bytes(
                                        bytes[offset + 16..offset + 24].try_into().unwrap(),
                                    );
                                    if start < 0 || length <= 0 {
                                        complete = false;
                                        extents.clear();
                                        break;
                                    }
                                    extents.push(NativeExtent {
                                        disk_number: disk,
                                        starting_offset: start as u64,
                                        extent_bytes: length as u64,
                                    });
                                }
                                if !extents.is_empty() {
                                    all.push(NativeVolume { extents });
                                }
                            }
                        }
                        _ => complete = false,
                    }
                } else {
                    complete = false;
                }
            }
            name.fill(0);
            let more = unsafe { FindNextVolumeW(iter, name.as_mut_ptr(), name.len() as u32) };
            if more == 0 {
                if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
                    complete = false;
                }
                break;
            }
        }
        unsafe {
            FindVolumeClose(iter);
        }
        // Sort so order-only Win32 enumeration changes are not drift.
        for v in &mut all {
            v.extents
                .sort_by_key(|x| (x.disk_number, x.starting_offset, x.extent_bytes));
        }
        all.sort_by(|a, b| {
            let left = a
                .extents
                .iter()
                .map(|x| (x.disk_number, x.starting_offset, x.extent_bytes))
                .collect::<Vec<_>>();
            let right = b
                .extents
                .iter()
                .map(|x| (x.disk_number, x.starting_offset, x.extent_bytes))
                .collect::<Vec<_>>();
            left.cmp(&right)
        });
        (all, complete)
    }
    pub fn capture() -> NativeObservation {
        let (disk_interface_numbers, interfaces_complete) = interfaces();
        let (volumes, volumes_complete) = volumes();
        NativeObservation {
            disk_interface_numbers,
            volumes,
            interfaces_complete,
            volumes_complete,
        }
    }
}
#[cfg(windows)]
pub fn capture_native() -> NativeObservation {
    win::capture()
}
