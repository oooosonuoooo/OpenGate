//! Protected DACLs are mandatory for machine-scope DPAPI service state.
use anyhow::{Context, Result, bail, ensure};
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree},
    Security::{
        self,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SE_FILE_OBJECT, SetNamedSecurityInfoW,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
        LookupAccountNameW, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

pub fn is_system_dir(path: &Path) -> Result<bool> {
    let Some(program_data) = std::env::var_os("ProgramData") else {
        return Ok(false);
    };
    let expected = std::path::PathBuf::from(program_data).join("OpenGate");
    if !expected.exists() {
        return Ok(false);
    }
    Ok(path
        .canonicalize()?
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.canonicalize()?.to_string_lossy()))
}

struct LocalAllocation(*mut std::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper owns a LocalAlloc result from Windows security APIs.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
struct Handle(*mut std::ffi::c_void);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the wrapper owns a handle opened by OpenProcessToken.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn sid_string(sid: Security::PSID) -> Result<String> {
    let mut text = ptr::null_mut();
    // SAFETY: caller supplies a valid SID; API allocates the returned string.
    ensure!(
        unsafe { ConvertSidToStringSidW(sid, &mut text) } != 0,
        "cannot format security identity"
    );
    let _allocation = LocalAllocation(text.cast());
    let mut len = 0;
    // SAFETY: successful conversion returns a null-terminated UTF-16 string.
    unsafe {
        while *text.add(len) != 0 {
            len += 1;
        }
        Ok(String::from_utf16(std::slice::from_raw_parts(text, len))?)
    }
}
fn current_user() -> Result<String> {
    let mut token = ptr::null_mut();
    // SAFETY: pointers refer to live storage and the process pseudo-handle is valid.
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "cannot query process identity"
    );
    let _handle = Handle(token);
    let mut length = 0;
    // SAFETY: this first call requests the required buffer size only.
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length);
    }
    ensure!(length > 0 && length < 65536, "invalid token identity size");
    // usize backing provides the alignment required by TOKEN_USER and its SID.
    let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: buffer is suitably aligned and contains at least length writable bytes.
    ensure!(
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        } != 0,
        "cannot read process identity"
    );
    // SAFETY: successful TokenUser query initialized TOKEN_USER in the buffer.
    sid_string(unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid })
}
fn service_sid() -> Result<String> {
    let account = wide(OsStr::new("NT SERVICE\\OpenGate"));
    let mut sid_length = 0;
    let mut domain_length = 0;
    let mut use_kind = 0;
    // SAFETY: first lookup requests required buffer lengths without writing data.
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &mut sid_length,
            ptr::null_mut(),
            &mut domain_length,
            &mut use_kind,
        );
    }
    ensure!(
        sid_length > 0 && sid_length < 65536,
        "OpenGate service identity is unavailable; install the Windows service before initializing system state"
    );
    let mut sid = vec![0usize; (sid_length as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut domain = vec![0u16; domain_length as usize];
    // SAFETY: both buffers are allocated using the lengths returned by Windows.
    ensure!(
        unsafe {
            LookupAccountNameW(
                ptr::null(),
                account.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut sid_length,
                domain.as_mut_ptr(),
                &mut domain_length,
                &mut use_kind,
            )
        } != 0,
        "cannot resolve OpenGate service identity"
    );
    sid_string(sid.as_mut_ptr().cast())
}

pub fn restrict(path: &Path, directory: bool) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).context("checking protected Windows state")?;
    ensure!(
        metadata.file_attributes() & 0x400 == 0,
        "protected state cannot be a Windows reparse point"
    );
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "protected state has wrong file type"
    );
    let parent = if directory {
        path
    } else {
        path.parent().context("protected state has no parent")?
    };
    let principal = if is_system_dir(parent)? {
        service_sid()?
    } else {
        current_user()?
    };
    let inheritance = if directory { "OICI" } else { "" };
    let sddl = format!(
        "D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)(A;{inheritance};FA;;;{principal})"
    );
    let sddl = wide(OsStr::new(&sddl));
    let mut descriptor = ptr::null_mut();
    // SAFETY: SDDL is null-terminated; API allocates a self-relative descriptor.
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } != 0,
        "cannot construct protected state ACL"
    );
    let _descriptor = LocalAllocation(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = ptr::null_mut();
    // SAFETY: descriptor is live and initialized by the successful conversion above.
    ensure!(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            != 0
            && present != 0
            && !acl.is_null(),
        "protected state ACL is invalid"
    );
    let path = wide(path.as_os_str());
    // SAFETY: path and ACL are valid for the duration of the call. No owner is changed.
    let result = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if result != 0 {
        bail!(
            "cannot protect Windows state ACL (Windows error {result}); system management requires an elevated administrator"
        )
    }
    Ok(())
}
