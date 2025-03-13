#![cfg(target_os = "windows")]

use windows_sys::Win32::{
    Foundation::*,
    Security::*,
};

const SE_BACKUP_NAME:  &[u8]  = b"SeBackupPrivilege\0";
const SE_RESTORE_NAME: &[u8]  = b"SeRestorePrivilege\0";

unsafe fn enable_privilege(name: &[u8]) -> bool {
    let mut token: HANDLE = 0;
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut token,
    ) == 0 { return false; }

    let mut luid: LUID = std::mem::zeroed();
    if LookupPrivilegeValueA(
        std::ptr::null(),
        name.as_ptr(),
        &mut luid,
    ) == 0 {
        CloseHandle(token);
        return false;
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    let r = AdjustTokenPrivileges(
        token,
        FALSE,
        &tp,
        std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    CloseHandle(token);
    r != 0
}

pub fn enable_backup_restore() -> Result<(), String> {
    unsafe {
        let b = enable_privilege(SE_BACKUP_NAME);
        let r = enable_privilege(SE_RESTORE_NAME);
        if b && r { Ok(()) } else { Err("Could not enable SeBackupPrivilege/SeRestorePrivilege".into()) }
    }
}
