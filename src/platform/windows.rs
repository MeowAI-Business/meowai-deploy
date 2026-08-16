use std::{
    env,
    ffi::{OsString, c_void},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    thread,
    time::Duration,
};

use rand::Rng;
use windows_sys::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_SUCCESS, GetLastError,
            INVALID_HANDLE_VALUE, LocalFree,
        },
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            Authorization::{
                EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
                SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
                TRUSTEE_W,
            },
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
            GetSecurityDescriptorControl, GetTokenInformation, NO_INHERITANCE,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
            SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
        },
        Storage::FileSystem::{
            FILE_ALL_ACCESS, MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_IGNORE_MERGE_ERRORS,
            ReplaceFileW,
        },
        System::{
            Com::CoTaskMemFree,
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            SystemServices::ACCESS_ALLOWED_ACE_TYPE,
            Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken},
        },
        UI::Shell::{FOLDERID_Profile, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    },
    core::PWSTR,
};

pub fn user_profile_directory() -> Option<PathBuf> {
    if let Some(path) = env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(path));
    }
    known_profile_directory().ok()
}

pub fn launched_from_desktop_shell() -> bool {
    parent_process_name()
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case("explorer.exe"))
}

fn parent_process_name() -> Option<String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }
    let current_pid = unsafe { GetCurrentProcessId() };
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut parent_pid = None;
    let mut process_name = None;
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while has_entry {
        if entry.th32ProcessID == current_pid {
            parent_pid = Some(entry.th32ParentProcessID);
        }
        if parent_pid == Some(entry.th32ProcessID) {
            process_name = wide_process_name(&entry.szExeFile);
        }
        if parent_pid.is_some() && process_name.is_some() {
            break;
        }
        has_entry = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    if process_name.is_none() {
        let Some(parent_pid) = parent_pid else {
            unsafe { CloseHandle(snapshot) };
            return None;
        };
        entry = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while has_entry {
            if entry.th32ProcessID == parent_pid {
                process_name = wide_process_name(&entry.szExeFile);
                break;
            }
            has_entry = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
    }
    unsafe { CloseHandle(snapshot) };
    process_name
}

fn wide_process_name(value: &[u16]) -> Option<String> {
    let length = value.iter().position(|character| *character == 0)?;
    Some(String::from_utf16_lossy(&value[..length]))
}

pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_private_acl(path)?;
    verify_private_acl(path)
}

pub fn open_private_append(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    set_private_acl(path)?;
    verify_private_acl(path)?;
    Ok(file)
}

pub fn write_private_file(path: &Path, content: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = unique_temporary_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        set_private_acl(&temporary)?;
        verify_private_acl(&temporary)?;
        replace_file(&temporary, path)?;
        verify_private_acl(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn private_path_is_restricted(path: &Path, _directory: bool) -> io::Result<bool> {
    Ok(verify_private_acl(path).is_ok())
}

fn known_profile_directory() -> io::Result<PathBuf> {
    let mut raw: PWSTR = null_mut();
    let status = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_Profile,
            KF_FLAG_DEFAULT as u32,
            null_mut(),
            &mut raw,
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    if raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Windows profile directory is unavailable",
        ));
    }
    let mut length = 0;
    unsafe {
        while *raw.add(length) != 0 {
            length += 1;
        }
    }
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, length)
    }));
    unsafe { CoTaskMemFree(raw.cast()) };
    Ok(path)
}

fn set_private_acl(path: &Path) -> io::Result<()> {
    let current_user = current_user_sid()?;
    let system = system_sid()?;
    let mut entries = [
        explicit_access(current_user.as_ptr().cast_mut().cast(), TRUSTEE_IS_USER),
        explicit_access(system.as_ptr().cast_mut().cast(), TRUSTEE_IS_USER),
    ];
    let mut acl: *mut ACL = null_mut();
    let status =
        unsafe { SetEntriesInAclW(entries.len() as u32, entries.as_mut_ptr(), null(), &mut acl) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let mut wide = wide_path(path);
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null_mut(),
        )
    };
    unsafe { LocalFree(acl.cast()) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

fn verify_private_acl(path: &Path) -> io::Result<()> {
    let current_user = current_user_sid()?;
    let system = system_sid()?;
    let mut owner = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let mut wide = wide_path(path);
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let result = (|| {
        if acl.is_null() || owner.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private ACL is missing",
            ));
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private ACL still inherits permissions",
            ));
        }
        let mut information = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        if unsafe {
            GetAclInformation(
                acl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if information.AceCount != 2 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private ACL contains unexpected entries",
            ));
        }
        let mut user_ok = false;
        let mut system_ok = false;
        for index in 0..information.AceCount {
            let mut raw_ace: *mut c_void = null_mut();
            if unsafe { GetAce(acl, index, &mut raw_ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let ace = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
            if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
                || ace.Mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private ACL does not grant full control",
                ));
            }
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            if unsafe { EqualSid(sid, current_user.as_ptr().cast_mut().cast()) } != 0 {
                user_ok = true;
            } else if unsafe { EqualSid(sid, system.as_ptr().cast_mut().cast()) } != 0 {
                system_ok = true;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private ACL grants access to an unexpected principal",
                ));
            }
        }
        if user_ok && system_ok {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private ACL is missing the current user or SYSTEM",
            ))
        }
    })();
    unsafe { LocalFree(descriptor) };
    result
}

fn explicit_access(sid: *mut c_void, trustee_type: i32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: trustee_type,
            ptstrName: sid.cast(),
        },
    }
}

fn current_user_sid() -> io::Result<Vec<u8>> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut needed = 0u32;
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        copy_sid(token_user.User.Sid)
    })();
    unsafe { CloseHandle(token) };
    result
}

fn system_sid() -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut size = buffer.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(size as usize);
    Ok(buffer)
}

fn copy_sid(sid: *mut c_void) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::{GetLengthSid, IsValidSid};
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows SID",
        ));
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
}

fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    let temporary = wide_path(temporary);
    let destination = wide_path(destination);
    for attempt in 0..5 {
        let succeeded = if destination_exists(destination.as_ptr()) {
            unsafe {
                ReplaceFileW(
                    destination.as_ptr(),
                    temporary.as_ptr(),
                    null(),
                    REPLACEFILE_IGNORE_MERGE_ERRORS,
                    null_mut(),
                    null_mut(),
                )
            }
        } else {
            unsafe {
                MoveFileExW(
                    temporary.as_ptr(),
                    destination.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            }
        };
        if succeeded != 0 {
            return Ok(());
        }
        let error = unsafe { GetLastError() };
        if attempt == 4 || !matches!(error, ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION) {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        thread::sleep(Duration::from_millis(40 * (attempt + 1) as u64));
    }
    unreachable!()
}

fn destination_exists(path: *const u16) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};
    unsafe { GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES }
}

fn unique_temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("private");
    let random = rand::thread_rng().r#gen::<u64>();
    path.with_file_name(format!(".{name}.tmp-{}-{random:016x}", std::process::id()))
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_directory_and_file_have_restricted_acls() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("state");
        ensure_private_directory(&root).expect("private directory");
        let path = root.join("session.json");
        write_private_file(&path, b"old").expect("initial private file");
        assert!(private_path_is_restricted(&root, true).expect("directory ACL"));
        assert!(private_path_is_restricted(&path, false).expect("file ACL"));

        write_private_file(&path, b"new").expect("replace private file");
        assert_eq!(fs::read(&path).expect("private content"), b"new");
        assert!(private_path_is_restricted(&path, false).expect("replacement ACL"));
    }
}
