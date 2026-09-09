//! Service installation and dispatch helpers.  These helpers never delete state
//! directories, identities, or trusted-device databases.
use anyhow::{anyhow, bail, Context, Result};
use opengate_core::Config;
use std::{ffi::OsString, path::Path, process::Command};
use tokio_util::sync::CancellationToken;

pub const WINDOWS_SERVICE_NAME: &str = "OpenGate";

pub fn linux_unit(executable: &Path, dir: &Path, system: bool) -> String {
    let executable = unit_quote(executable);
    let dir = unit_quote(dir);
    let mut unit = String::from("[Unit]\nDescription=OpenGate secure remote access daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\n");
    if system {
        unit.push_str("User=opengate\nGroup=opengate\nStateDirectory=opengate\nStateDirectoryMode=0700\n");
    }
    unit.push_str(&format!("ExecStart={executable} --data-dir {dir} daemon\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nReadWritePaths={dir}\nCapabilityBoundingSet=\nLockPersonality=true\nMemoryDenyWriteExecute=true\n\n[Install]\nWantedBy={}\n", if system { "multi-user.target" } else { "default.target" }));
    unit
}

/// Installs the current executable as a service. System services need elevation;
/// user services are managed with `systemctl --user` on Linux.
pub fn install(executable: &Path, dir: &Path, system: bool, full_admin: bool) -> Result<()> {
    if !executable.is_file() { bail!("OpenGate executable does not exist: {}", executable.display()); }
    if system && !is_elevated() { bail!("system service installation requires elevation; use the platform installer or run from an elevated administrator shell"); }
    if full_admin {
        if !system { bail!("Full Admin Access requires an explicitly installed system service"); }
        let config = Config::load_or_create(dir)?;
        if !config.allow_admin { bail!("Full Admin Access is disabled in config.toml; an owner must set allow_admin = true before installing a privileged service"); }
    }
    #[cfg(target_os = "linux")]
    { return install_linux(executable, dir, system, full_admin); }
    #[cfg(windows)]
    { return install_windows(executable, dir, system, full_admin); }
    #[allow(unreachable_code)]
    bail!("service installation is currently supported on Linux and Windows")
}

pub fn uninstall(system: bool) -> Result<()> {
    if system && !is_elevated() { bail!("system service removal requires elevation"); }
    #[cfg(target_os = "linux")]
    { return uninstall_linux(system); }
    #[cfg(windows)]
    { return uninstall_windows(system); }
    #[allow(unreachable_code)]
    bail!("service removal is currently supported on Linux and Windows")
}

#[cfg(unix)]
pub fn is_elevated() -> bool { unsafe { libc::geteuid() == 0 } }
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::{Foundation::CloseHandle, Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY}, System::Threading::{GetCurrentProcess, OpenProcessToken}};
    let mut token = std::ptr::null_mut();
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0;
    let opened = unsafe { OpenProcessToken(unsafe { GetCurrentProcess() }, TOKEN_QUERY, &mut token) };
    if opened == 0 { return false; }
    let ok = unsafe { GetTokenInformation(token, TokenElevation, (&mut elevation as *mut TOKEN_ELEVATION).cast(), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut size) };
    unsafe { CloseHandle(token); }
    ok != 0 && elevation.TokenIsElevated != 0
}
#[cfg(not(any(unix, windows)))]
pub fn is_elevated() -> bool { false }

#[cfg(target_os = "linux")]
fn install_linux(executable: &Path, dir: &Path, system: bool, _full_admin: bool) -> Result<()> {
    use std::fs;
    if system {
        if !dir.is_absolute() || !dir.starts_with("/var/lib/opengate") { bail!("system services require an empty dedicated state path under /var/lib/opengate (for example /var/lib/opengate)"); }
        if !command_ok(Command::new("getent").args(["passwd", "opengate"]))? {
            run(Command::new("useradd").args(["--system", "--home-dir", "/var/lib/opengate", "--shell", "/usr/sbin/nologin", "opengate"]))?;
        }
        fs::create_dir_all(dir)?;
        run(Command::new("chown").arg("opengate:opengate").arg(dir))?;
        fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        fs::write("/etc/systemd/system/opengate.service", linux_unit(executable, dir, true))?;
        run(Command::new("systemctl").args(["daemon-reload"]))?;
        run(Command::new("systemctl").args(["enable", "--now", "opengate.service"]))?;
    } else {
        let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set; cannot install user service"))?;
        let path = Path::new(&home).join(".config/systemd/user/opengate.service");
        fs::create_dir_all(path.parent().expect("user unit parent"))?;
        fs::write(&path, linux_unit(executable, dir, false))?;
        run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
        run(Command::new("systemctl").args(["--user", "enable", "--now", "opengate.service"]))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_linux(system: bool) -> Result<()> {
    use std::fs;
    if system {
        let _ = Command::new("systemctl").args(["disable", "--now", "opengate.service"]).status();
        let path = Path::new("/etc/systemd/system/opengate.service");
        if path.exists() { fs::remove_file(path)?; }
        run(Command::new("systemctl").args(["daemon-reload"]))?;
    } else {
        let _ = Command::new("systemctl").args(["--user", "disable", "--now", "opengate.service"]).status();
        let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set; cannot remove user service"))?;
        let path = Path::new(&home).join(".config/systemd/user/opengate.service");
        if path.exists() { fs::remove_file(path)?; }
        run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
    }
    Ok(())
}

#[cfg(windows)]
fn install_windows(executable: &Path, dir: &Path, system: bool, full_admin: bool) -> Result<()> {
    if !system { bail!("Windows background operation is installed as the OpenGate Windows service; use --system from an elevated administrator shell"); }
    let account = if full_admin { "LocalSystem" } else { "NT AUTHORITY\\LocalService" };
    let binary = format!("\"{}\" --data-dir \"{}\" service", executable.display(), dir.display());
    let _ = Command::new("sc.exe").args(["stop", WINDOWS_SERVICE_NAME]).status();
    let _ = Command::new("sc.exe").args(["delete", WINDOWS_SERVICE_NAME]).status();
    run(Command::new("sc.exe").args(["create", WINDOWS_SERVICE_NAME, "binPath=", &binary, "start=", "auto", "obj=", account]))?;
    run(Command::new("sc.exe").args(["failure", WINDOWS_SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000"]))?;
    run(Command::new("sc.exe").args(["start", WINDOWS_SERVICE_NAME]))?;
    Ok(())
}
#[cfg(windows)]
fn uninstall_windows(_system: bool) -> Result<()> {
    let _ = Command::new("sc.exe").args(["stop", WINDOWS_SERVICE_NAME]).status();
    run(Command::new("sc.exe").args(["delete", WINDOWS_SERVICE_NAME]))
}

fn run(command: &mut Command) -> Result<()> {
    let display = format!("{command:?}");
    let status = command.status().with_context(|| format!("launching {display}"))?;
    if !status.success() { bail!("{display} failed with {status}"); }
    Ok(())
}
#[cfg(target_os = "linux")]
fn command_ok(command: &mut Command) -> Result<bool> { Ok(command.status()?.success()) }

fn unit_quote(path: &Path) -> String {
    let text = path.to_string_lossy().replace(['\n', '\r'], "_");
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The callback passed by the executable runs the actual daemon and must stop when
/// the supplied token is cancelled by the Service Control Manager.
pub type ServiceCallback = fn(Vec<OsString>, CancellationToken) -> Result<()>;

#[cfg(windows)]
mod windows_dispatcher {
    use super::*;
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_service::{define_windows_service, service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType}, service_control_handler::{self, ServiceControlHandlerResult}, service_dispatcher};

    static CALLBACK: OnceLock<ServiceCallback> = OnceLock::new();
    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch(callback: ServiceCallback) -> Result<()> {
        CALLBACK.set(callback).map_err(|_| anyhow!("Windows service dispatcher was already configured"))?;
        service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main).context("connecting to the Windows Service Control Manager")?;
        Ok(())
    }

    fn status(state: ServiceState) -> ServiceStatus {
        ServiceStatus { service_type: ServiceType::OWN_PROCESS, current_state: state, controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP } else { ServiceControlAccept::empty() }, exit_code: ServiceExitCode::Win32(0), checkpoint: 0, wait_hint: Duration::default(), process_id: None }
    }
    fn service_main(arguments: Vec<OsString>) {
        let _ = run_service(arguments);
    }
    fn run_service(arguments: Vec<OsString>) -> Result<()> {
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let status_handle = service_control_handler::register(WINDOWS_SERVICE_NAME, move |event| match event {
            ServiceControl::Stop => { stop.cancel(); ServiceControlHandlerResult::NoError }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        status_handle.set_service_status(status(ServiceState::Running))?;
        let result = CALLBACK.get().ok_or_else(|| anyhow!("Windows service callback was not configured"))?(arguments, cancellation);
        status_handle.set_service_status(status(ServiceState::Stopped))?;
        result
    }
}

#[cfg(windows)]
pub use windows_dispatcher::dispatch;
#[cfg(not(windows))]
pub fn dispatch(_callback: ServiceCallback) -> Result<()> { bail!("Windows service dispatch is only available on Windows") }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn user_unit_is_restricted_and_uses_user_target() {
        let unit = linux_unit(Path::new("/opt/OpenGate/opengate"), Path::new("/home/alice/.local/share/opengate"), false);
        assert!(unit.contains("NoNewPrivileges=true")); assert!(unit.contains("ProtectHome=true")); assert!(unit.contains("WantedBy=default.target")); assert!(!unit.contains("User=opengate"));
    }
    #[test]
    fn system_unit_uses_dedicated_identity() {
        let unit = linux_unit(Path::new("/usr/bin/opengate"), Path::new("/var/lib/opengate"), true);
        assert!(unit.contains("User=opengate")); assert!(unit.contains("StateDirectoryMode=0700")); assert!(unit.contains("WantedBy=multi-user.target"));
    }
}
