//! Service installation and dispatch helpers.  These helpers never delete state
//! directories, identities, or trusted-device databases.
use anyhow::{Context, Result, anyhow, bail};
use opengate_core::Config;
use opengate_protocol::{ErrorCode, OpenGateError};
#[cfg(windows)]
use std::path::PathBuf;
use std::{ffi::OsString, path::Path, process::Command};
use tokio_util::sync::CancellationToken;

pub const WINDOWS_SERVICE_NAME: &str = "OpenGate";

/// Render the least-privileged Linux unit.  System-wide Full Admin mode is
/// intentionally opt-in through [`linux_unit_with_mode`].
pub fn linux_unit(executable: &Path, dir: &Path, system: bool) -> String {
    linux_unit_with_mode(executable, dir, system, false)
}

/// Render a Linux unit for the selected owner-approved mode.
///
/// `full_admin` is meaningful only for a system unit.  The privileged variant
/// runs as root and deliberately does not apply filesystem or capability
/// sandboxes which would prevent an authorized root operation from working.
/// Callers must first prove the owner's `allow_admin = true` configuration.
pub fn linux_unit_with_mode(
    executable: &Path,
    dir: &Path,
    system: bool,
    full_admin: bool,
) -> String {
    let executable = unit_quote(executable);
    let dir = unit_quote(dir);
    let mut unit = String::from(
        "[Unit]\nDescription=OpenGate secure remote access daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\n",
    );
    if system {
        if full_admin {
            unit.push_str("User=root\nGroup=root\n");
        } else {
            unit.push_str("User=opengate\nGroup=opengate\n");
        }
        unit.push_str("StateDirectory=opengate\nStateDirectoryMode=0700\n");
    }
    unit.push_str(&format!("ExecStart={executable} --data-dir {dir} daemon\nRestart=on-failure\nRestartSec=5\nUMask=0077\n"));
    if full_admin {
        unit.push_str("# Full Admin mode is owner-approved and intentionally unsandboxed so root operations can work.\n");
    } else {
        unit.push_str("NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\n");
        if system {
            unit.push_str("ProtectHome=true\n");
        } else {
            // ProtectHome=true hides a user state directory.  A read-only home
            // plus this explicit writable exception keeps the user unit usable.
            unit.push_str("ProtectHome=read-only\n");
        }
        unit.push_str(&format!("ReadWritePaths={dir}\nCapabilityBoundingSet=\nLockPersonality=true\nMemoryDenyWriteExecute=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nRestrictNamespaces=true\nRestrictRealtime=true\nSystemCallArchitectures=native\n"));
    }
    unit.push_str(&format!(
        "\n[Install]\nWantedBy={}\n",
        if system {
            "multi-user.target"
        } else {
            "default.target"
        }
    ));
    unit
}

/// Installs the current executable as a service. System services need elevation;
/// user services are managed with `systemctl --user` on Linux.
pub fn install(executable: &Path, dir: &Path, system: bool, full_admin: bool) -> Result<()> {
    install_impl(executable, dir, system, full_admin).map_err(|error| {
        anyhow::Error::new(OpenGateError::new(
            ErrorCode::Service,
            error.to_string(),
            false,
        ))
    })
}

fn install_impl(executable: &Path, dir: &Path, system: bool, full_admin: bool) -> Result<()> {
    if !executable.is_file() {
        bail!(
            "OpenGate executable does not exist: {}",
            executable.display()
        );
    }
    if system && !is_elevated() {
        bail!(
            "system service installation requires elevation; use the platform installer or run from an elevated administrator shell"
        );
    }
    if system {
        require_trusted_system_executable(executable)?;
    }
    #[cfg(windows)]
    if system {
        require_windows_system_dir(dir)?;
    }
    if full_admin {
        if !system {
            bail!("Full Admin Access requires an explicitly installed system service");
        }
        if !dir.join("config.toml").is_file() {
            bail!(
                "Full Admin Access requires an existing owner configuration with allow_admin = true; refusing to create or enable it implicitly"
            );
        }
        let config = Config::load_or_create(dir)?;
        if !config.allow_admin {
            bail!(
                "Full Admin Access is disabled in config.toml; an owner must set allow_admin = true before installing a privileged service"
            );
        }
    }
    #[cfg(target_os = "linux")]
    {
        install_linux(executable, dir, system, full_admin)
    }
    #[cfg(windows)]
    {
        install_windows(executable, dir, system, full_admin)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        bail!("service installation is currently supported on Linux and Windows")
    }
}

#[cfg(target_os = "linux")]
fn require_trusted_system_executable(executable: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let actual = executable
        .canonicalize()
        .with_context(|| format!("canonicalizing system executable {}", executable.display()))?;
    let allowed = [
        Path::new("/usr/bin/opengate"),
        Path::new("/usr/local/bin/opengate"),
    ];
    if !allowed.iter().any(|path| actual == *path) {
        bail!(
            "system services require the installed OpenGate executable at /usr/bin/opengate or /usr/local/bin/opengate"
        );
    }
    let file = std::fs::metadata(&actual)?;
    if file.uid() != 0 || file.mode() & 0o022 != 0 {
        bail!("system executable must be root-owned and not writable by group or other users");
    }
    let mut parent = actual.parent();
    while let Some(path) = parent {
        let metadata = std::fs::metadata(path)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!(
                "system executable parent directories must be root-owned and not writable by group or other users"
            );
        }
        parent = path.parent();
    }
    Ok(())
}

#[cfg(windows)]
fn require_trusted_system_executable(executable: &Path) -> Result<()> {
    let program_files = std::env::var_os("ProgramFiles").ok_or_else(|| {
        anyhow!("ProgramFiles is unavailable; cannot install the Windows system service")
    })?;
    let expected = PathBuf::from(program_files)
        .join("OpenGate")
        .join("opengate.exe")
        .canonicalize()
        .with_context(|| "canonicalizing the installed Windows OpenGate executable")?;
    let actual = executable
        .canonicalize()
        .with_context(|| format!("canonicalizing system executable {}", executable.display()))?;
    if !actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        bail!(
            "Windows system services require the installed executable at {}",
            expected.display()
        );
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn require_trusted_system_executable(_executable: &Path) -> Result<()> {
    bail!("system service installation is unsupported on this platform")
}

pub fn uninstall(system: bool) -> Result<()> {
    uninstall_impl(system).map_err(|error| {
        anyhow::Error::new(OpenGateError::new(
            ErrorCode::Service,
            error.to_string(),
            false,
        ))
    })
}

fn uninstall_impl(system: bool) -> Result<()> {
    if system && !is_elevated() {
        bail!("system service removal requires elevation");
    }
    #[cfg(target_os = "linux")]
    {
        uninstall_linux(system)
    }
    #[cfg(windows)]
    {
        uninstall_windows(system)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        bail!("service removal is currently supported on Linux and Windows")
    }
}

#[cfg(unix)]
pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut token = std::ptr::null_mut();
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0;
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return false;
    }
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    ok != 0 && elevation.TokenIsElevated != 0
}
#[cfg(not(any(unix, windows)))]
pub fn is_elevated() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn install_linux(executable: &Path, dir: &Path, system: bool, full_admin: bool) -> Result<()> {
    use std::fs;
    if system {
        if dir != Path::new("/var/lib/opengate") {
            bail!("system services require the dedicated state path /var/lib/opengate");
        }
        if !command_ok(Command::new("/usr/bin/getent").args(["passwd", "opengate"]))? {
            run(Command::new("/usr/sbin/useradd").args([
                "--system",
                "--home-dir",
                "/var/lib/opengate",
                "--shell",
                "/usr/sbin/nologin",
                "opengate",
            ]))?;
        }
        fs::create_dir_all(dir)?;
        let owner = if full_admin {
            "root:root"
        } else {
            "opengate:opengate"
        };
        // State is a root-owned 0700 directory while this installer runs.  Do
        // not follow a malicious symlink while preserving an existing identity.
        run(Command::new("/usr/bin/chown")
            .args(["--recursive", "--no-dereference", owner])
            .arg(dir))?;
        fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        fs::write(
            "/etc/systemd/system/opengate.service",
            linux_unit_with_mode(executable, dir, true, full_admin),
        )?;
        run(Command::new("/usr/bin/systemctl").args(["daemon-reload"]))?;
        run(Command::new("/usr/bin/systemctl").args(["enable", "opengate.service"]))?;
        // A mode change has to replace an already running daemon; `enable
        // --now` only starts inactive units and would otherwise leave the old
        // account and sandbox in effect.
        run(Command::new("/usr/bin/systemctl").args(["restart", "opengate.service"]))?;
    } else {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| anyhow!("HOME is not set; cannot install user service"))?;
        let path = Path::new(&home).join(".config/systemd/user/opengate.service");
        fs::create_dir_all(path.parent().expect("user unit parent"))?;
        fs::write(&path, linux_unit(executable, dir, false))?;
        run(Command::new("/usr/bin/systemctl").args(["--user", "daemon-reload"]))?;
        run(Command::new("/usr/bin/systemctl").args([
            "--user",
            "enable",
            "--now",
            "opengate.service",
        ]))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_linux(system: bool) -> Result<()> {
    use std::fs;
    if system {
        let _ = Command::new("/usr/bin/systemctl")
            .args(["disable", "--now", "opengate.service"])
            .status();
        let path = Path::new("/etc/systemd/system/opengate.service");
        if path.exists() {
            fs::remove_file(path)?;
        }
        run(Command::new("/usr/bin/systemctl").args(["daemon-reload"]))?;
    } else {
        let _ = Command::new("/usr/bin/systemctl")
            .args(["--user", "disable", "--now", "opengate.service"])
            .status();
        let home = std::env::var_os("HOME")
            .ok_or_else(|| anyhow!("HOME is not set; cannot remove user service"))?;
        let path = Path::new(&home).join(".config/systemd/user/opengate.service");
        if path.exists() {
            fs::remove_file(path)?;
        }
        run(Command::new("/usr/bin/systemctl").args(["--user", "daemon-reload"]))?;
    }
    Ok(())
}

#[cfg(windows)]
fn install_windows(executable: &Path, dir: &Path, system: bool, full_admin: bool) -> Result<()> {
    if !system {
        bail!(
            "Windows background operation is installed as the OpenGate Windows service; use --system from an elevated administrator shell"
        );
    }
    let account = if full_admin {
        "LocalSystem"
    } else {
        "NT AUTHORITY\\LocalService"
    };
    // `service-run` is a dedicated hidden CLI entry point.  It must call
    // `dispatch` before Tokio is created; it is not the public `service`
    // management command.
    let binary = format!(
        "\"{}\" --data-dir \"{}\" service-run",
        executable.display(),
        dir.display()
    );
    let sc = windows_system_command()?;
    if command_ok(Command::new(&sc).args(["qc", WINDOWS_SERVICE_NAME]))? {
        stop_windows_service()?;
        run(Command::new(&sc).args([
            "config",
            WINDOWS_SERVICE_NAME,
            "binPath=",
            &binary,
            "start=",
            "auto",
            "obj=",
            account,
            "password=",
            "",
        ]))?;
    } else {
        run(Command::new(&sc).args([
            "create",
            WINDOWS_SERVICE_NAME,
            "binPath=",
            &binary,
            "start=",
            "auto",
            "obj=",
            account,
            "password=",
            "",
        ]))?;
    }
    run(Command::new(&sc).args(["sidtype", WINDOWS_SERVICE_NAME, "unrestricted"]))?;
    run(Command::new(&sc).args(["failureflag", WINDOWS_SERVICE_NAME, "1"]))?;
    run(Command::new(&sc).args([
        "failure",
        WINDOWS_SERVICE_NAME,
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/10000/restart/30000",
    ]))?;
    run(Command::new(&sc).args(["start", WINDOWS_SERVICE_NAME]))?;
    Ok(())
}

/// The per-machine service deliberately has one canonical state location.  That
/// keeps its identity material machine-DPAPI protected and lets the security
/// layer apply the service-SID ACL instead of accepting an arbitrary directory.
#[cfg(windows)]
fn require_windows_system_dir(dir: &Path) -> Result<()> {
    use std::path::PathBuf;

    let program_data = std::env::var_os("ProgramData").ok_or_else(|| {
        anyhow!("ProgramData is unavailable; cannot install the Windows system service")
    })?;
    let expected = PathBuf::from(program_data).join("OpenGate");
    let supplied_parent = dir
        .parent()
        .ok_or_else(|| anyhow!("Windows system state directory has no parent"))?
        .canonicalize()
        .with_context(|| {
            format!(
                "canonicalizing Windows system state parent for {}",
                dir.display()
            )
        })?;
    let expected_parent = expected
        .parent()
        .expect("ProgramData/OpenGate always has a parent")
        .canonicalize()
        .context("canonicalizing ProgramData")?;
    let correct_name = dir
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("OpenGate"));
    if !correct_name
        || !supplied_parent
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected_parent.to_string_lossy())
    {
        bail!(
            "Windows system services require the dedicated state path {}",
            expected.display()
        );
    }
    // This directory is created while elevated, below the canonical ProgramData
    // parent.  The first security-layer operation replaces its DACL with the
    // protected service-SID ACL before any state file is read or written.
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating Windows system state directory {}", dir.display()))?;
    let actual = dir.canonicalize().with_context(|| {
        format!(
            "canonicalizing Windows system state directory {}",
            dir.display()
        )
    })?;
    let canonical_expected = expected.canonicalize().with_context(|| {
        format!(
            "canonicalizing required Windows system state directory {}",
            expected.display()
        )
    })?;
    if !actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&canonical_expected.to_string_lossy())
    {
        bail!(
            "Windows system services require the dedicated state path {}",
            expected.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn stop_windows_service() -> Result<()> {
    use std::{thread, time::Duration};
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let sc = windows_system_command()?;
    let _ = Command::new(&sc)
        .args(["stop", WINDOWS_SERVICE_NAME])
        .status();
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the Windows Service Control Manager")?;
    let service = manager
        .open_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .context("opening the OpenGate Windows service")?;
    for _ in 0..30 {
        if service
            .query_status()
            .context("querying OpenGate Windows service state")?
            .current_state
            == ServiceState::Stopped
        {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    bail!("OpenGate Windows service did not stop within 30 seconds")
}
#[cfg(windows)]
fn uninstall_windows(system: bool) -> Result<()> {
    if !system {
        bail!("Windows service removal requires --system from an elevated administrator shell");
    }
    let sc = windows_system_command()?;
    let _ = Command::new(&sc)
        .args(["stop", WINDOWS_SERVICE_NAME])
        .status();
    run(Command::new(&sc).args(["delete", WINDOWS_SERVICE_NAME]))
}

#[cfg(windows)]
fn windows_system_command() -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| OsString::from(r"C:\Windows"));
    let path = PathBuf::from(root).join("System32").join("sc.exe");
    if !path.is_file() {
        bail!(
            "Windows service controller is unavailable at {}",
            path.display()
        );
    }
    Ok(path)
}

fn run(command: &mut Command) -> Result<()> {
    let display = format!("{command:?}");
    let status = command
        .status()
        .with_context(|| format!("launching {display}"))?;
    if !status.success() {
        bail!("{display} failed with {status}");
    }
    Ok(())
}
#[cfg(any(target_os = "linux", windows))]
fn command_ok(command: &mut Command) -> Result<bool> {
    Ok(command.status()?.success())
}

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
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    static CALLBACK: OnceLock<ServiceCallback> = OnceLock::new();
    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch(callback: ServiceCallback) -> Result<()> {
        CALLBACK
            .set(callback)
            .map_err(|_| anyhow!("Windows service dispatcher was already configured"))?;
        service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main)
            .context("connecting to the Windows Service Control Manager")?;
        Ok(())
    }

    fn status(state: ServiceState) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }
    fn service_main(arguments: Vec<OsString>) {
        let _ = run_service(arguments);
    }
    fn run_service(arguments: Vec<OsString>) -> Result<()> {
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let status_handle =
            service_control_handler::register(WINDOWS_SERVICE_NAME, move |event| match event {
                ServiceControl::Stop => {
                    stop.cancel();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;
        status_handle.set_service_status(status(ServiceState::Running))?;
        let result = CALLBACK
            .get()
            .ok_or_else(|| anyhow!("Windows service callback was not configured"))?(
            arguments,
            cancellation,
        );
        let mut stopped = status(ServiceState::Stopped);
        if result.is_err() {
            stopped.exit_code = ServiceExitCode::Win32(1);
        }
        status_handle.set_service_status(stopped)?;
        result
    }
}

#[cfg(windows)]
pub use windows_dispatcher::dispatch;
#[cfg(not(windows))]
pub fn dispatch(_callback: ServiceCallback) -> Result<()> {
    bail!("Windows service dispatch is only available on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn user_unit_is_restricted_and_uses_user_target() {
        let unit = linux_unit(
            Path::new("/opt/OpenGate/opengate"),
            Path::new("/home/alice/.local/share/opengate"),
            false,
        );
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("ProtectHome=read-only"));
        assert!(unit.contains("ReadWritePaths=\"/home/alice/.local/share/opengate\""));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(!unit.contains("User=opengate"));
    }
    #[test]
    fn system_unit_uses_dedicated_identity() {
        let unit = linux_unit(
            Path::new("/usr/bin/opengate"),
            Path::new("/var/lib/opengate"),
            true,
        );
        assert!(unit.contains("User=opengate"));
        assert!(unit.contains("StateDirectoryMode=0700"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }
    #[test]
    fn full_admin_system_unit_runs_as_root_without_conflicting_sandbox() {
        let unit = linux_unit_with_mode(
            Path::new("/usr/bin/opengate"),
            Path::new("/var/lib/opengate"),
            true,
            true,
        );
        assert!(unit.contains("User=root"));
        assert!(!unit.contains("ProtectSystem=strict"));
        assert!(!unit.contains("CapabilityBoundingSet="));
    }
}
