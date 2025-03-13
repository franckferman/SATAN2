#![cfg(target_os = "windows")]

use windows_sys::Win32::{
    Foundation::*,
    System::Services::*,
};
use std::ffi::CString;

pub fn disable_vss() -> Result<(), String> {
    unsafe {
        let scm = OpenSCManagerA(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ALL_ACCESS,
        );
        if scm == 0 {
            return Err(format!("OpenSCManager: err={}", GetLastError()));
        }

        let name = CString::new("VSS").unwrap();
        let svc = OpenServiceA(scm, name.as_ptr() as *const u8, SERVICE_ALL_ACCESS);
        if svc == 0 {
            CloseServiceHandle(scm);
            return Err(format!("OpenService(VSS): err={}", GetLastError()));
        }

        // Stop the service
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        ControlService(svc, SERVICE_CONTROL_STOP, &mut status);

        // Disable (prevent restart)
        let change = ChangeServiceConfigA(
            svc,
            SERVICE_NO_CHANGE,
            SERVICE_DISABLED, // start type
            SERVICE_NO_CHANGE,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);

        if change == 0 {
            return Err(format!("ChangeServiceConfig: err={}", GetLastError()));
        }
        Ok(())
    }
}
