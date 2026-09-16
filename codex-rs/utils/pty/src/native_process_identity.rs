use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeProcessIdentityValidationResult {
    Match,
    ProcessExited,
    PidMismatch,
    CreationTimeMismatch,
    ExecutableMismatch,
    ParentIdentityMismatch,
    IdentityUnavailable,
    PartialIdentity,
    Unsupported,
    InternalError,
}

/// Immutable OS identity captured while the native child handle is still owned.
///
/// `creation_time` values are platform-native. On Windows they are the 100ns
/// intervals since 1601 returned by `GetProcessTimes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeProcessIdentity {
    pub os_pid: u32,
    pub creation_time: Option<u64>,
    pub executable_identity: Option<PathBuf>,
    pub parent_pid: Option<u32>,
    pub parent_creation_time: Option<u64>,
    pub platform: &'static str,
}

#[cfg(windows)]
pub(crate) fn capture_native_process_identity(
    os_pid: u32,
    process_handle: std::os::windows::io::RawHandle,
) -> NativeProcessIdentity {
    use std::os::windows::ffi::OsStringExt;

    use winapi::shared::minwindef::FILETIME;
    use winapi::shared::ntdef::HANDLE;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::GetProcessTimes;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
    use winapi::um::tlhelp32::PROCESSENTRY32W;
    use winapi::um::tlhelp32::Process32FirstW;
    use winapi::um::tlhelp32::Process32NextW;
    use winapi::um::tlhelp32::TH32CS_SNAPPROCESS;
    use winapi::um::winbase::QueryFullProcessImageNameW;
    use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;

    fn filetime_value(value: FILETIME) -> u64 {
        (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
    }

    fn creation_time(handle: HANDLE) -> Option<u64> {
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = creation;
        let mut kernel = creation;
        let mut user = creation;
        (unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } != 0)
            .then(|| filetime_value(creation))
    }

    fn executable(handle: HANDLE) -> Option<PathBuf> {
        let mut buffer = vec![0u16; 32_768];
        let mut len = u32::try_from(buffer.len()).ok()?;
        if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len) } == 0 {
            return None;
        }
        buffer.truncate(usize::try_from(len).ok()?);
        Some(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
    }

    fn parent_pid(os_pid: u32) -> Option<u32> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).ok()?;
        let mut found = None;
        if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
            loop {
                if entry.th32ProcessID == os_pid {
                    found = Some(entry.th32ParentProcessID);
                    break;
                }
                if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }
        unsafe { CloseHandle(snapshot) };
        found.filter(|pid| *pid != 0)
    }

    fn parent_creation_time(parent_pid: Option<u32>) -> Option<u64> {
        let pid = parent_pid?;
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let value = creation_time(handle);
        unsafe { CloseHandle(handle) };
        value
    }

    let handle = process_handle.cast();
    let creation_time = creation_time(handle);
    let executable_identity = executable(handle);
    let parent_pid = parent_pid(os_pid);
    let parent_creation_time = parent_creation_time(parent_pid);
    NativeProcessIdentity {
        os_pid,
        creation_time,
        executable_identity,
        parent_pid,
        parent_creation_time,
        platform: "windows",
    }
}

#[cfg(windows)]
pub(crate) fn duplicate_process_handle(
    handle: std::os::windows::io::RawHandle,
) -> std::io::Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::FromRawHandle;
    use winapi::um::handleapi::DuplicateHandle;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::DUPLICATE_SAME_ACCESS;

    let current = unsafe { GetCurrentProcess() };
    let mut duplicate = std::ptr::null_mut();
    let success = unsafe {
        DuplicateHandle(
            current,
            handle.cast(),
            current,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if success == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(duplicate.cast()) })
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_native_process_identity(os_pid: u32) -> NativeProcessIdentity {
    capture_linux_process_identity(os_pid).unwrap_or(NativeProcessIdentity {
        os_pid,
        creation_time: None,
        executable_identity: None,
        parent_pid: None,
        parent_creation_time: None,
        platform: "linux",
    })
}

#[cfg(target_os = "linux")]
fn parse_linux_stat(value: &str) -> Option<(u32, u64)> {
    let fields = value
        .get(value.rfind(')')? + 1..)?
        .split_whitespace()
        .collect::<Vec<_>>();
    let parent_pid = fields.get(1)?.parse().ok()?;
    let start_time = fields.get(19)?.parse().ok()?;
    Some((parent_pid, start_time))
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_linux_process_identity(
    os_pid: u32,
) -> std::io::Result<NativeProcessIdentity> {
    let proc_root = PathBuf::from("/proc").join(os_pid.to_string());
    let stat = std::fs::read_to_string(proc_root.join("stat"))?;
    let (parent_pid, creation_time) = parse_linux_stat(&stat).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed process stat")
    })?;
    let executable_identity = std::fs::read_link(proc_root.join("exe"))?;
    let parent_creation_time = if parent_pid == 0 {
        None
    } else {
        let parent_stat = std::fs::read_to_string(
            PathBuf::from("/proc")
                .join(parent_pid.to_string())
                .join("stat"),
        )?;
        Some(
            parse_linux_stat(&parent_stat)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed parent stat")
                })?
                .1,
        )
    };
    Ok(NativeProcessIdentity {
        os_pid,
        creation_time: Some(creation_time),
        executable_identity: Some(executable_identity),
        parent_pid: (parent_pid != 0).then_some(parent_pid),
        parent_creation_time,
        platform: "linux",
    })
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub(crate) fn capture_native_process_identity(os_pid: u32) -> NativeProcessIdentity {
    NativeProcessIdentity {
        os_pid,
        creation_time: None,
        executable_identity: None,
        parent_pid: None,
        parent_creation_time: None,
        platform: std::env::consts::OS,
    }
}

pub(crate) fn compare_native_process_identity(
    expected: &NativeProcessIdentity,
    current: &NativeProcessIdentity,
) -> NativeProcessIdentityValidationResult {
    use NativeProcessIdentityValidationResult::*;
    if expected.platform != current.platform {
        return Unsupported;
    }
    if expected.os_pid != current.os_pid {
        return PidMismatch;
    }
    let (Some(expected_creation), Some(current_creation)) =
        (expected.creation_time, current.creation_time)
    else {
        return PartialIdentity;
    };
    if expected_creation != current_creation {
        return CreationTimeMismatch;
    }
    let (Some(expected_executable), Some(current_executable)) =
        (&expected.executable_identity, &current.executable_identity)
    else {
        return PartialIdentity;
    };
    if expected_executable != current_executable {
        return ExecutableMismatch;
    }
    match (
        expected.parent_pid,
        expected.parent_creation_time,
        current.parent_pid,
        current.parent_creation_time,
    ) {
        (Some(expected_pid), Some(expected_time), Some(current_pid), Some(current_time)) => {
            if expected_pid != current_pid || expected_time != current_time {
                return ParentIdentityMismatch;
            }
        }
        (None, None, None, None) => {}
        _ => return PartialIdentity,
    }
    Match
}

#[cfg(test)]
#[path = "native_process_identity_tests.rs"]
mod tests;
