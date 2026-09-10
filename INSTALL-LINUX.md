# Install OpenGate on Linux

For developer setup, inspect `scripts/bootstrap-linux.sh` (dry run), then use
`scripts/bootstrap-linux.sh --apply` to install prerequisites, build, test, and
package. `--install-ssh-server` additionally installs and enables conventional
OpenSSH Server; OpenGate itself does not require it.

With the prerequisites already installed, build a release binary:

```sh
cargo build --locked --release
```

For a user service, which runs with your normal account and stores its state in
`~/.local/share/opengate`, run:

```sh
scripts/install-linux.sh --bin=target/release/opengate
```

For the system service, run the installer with normal `sudo` authorization:

```sh
sudo scripts/install-linux.sh --bin=target/release/opengate --system
systemctl status opengate.service
```

The default system service runs as the dedicated `opengate` user. Its state is
`/var/lib/opengate`, owned `0700`, and the service has no Linux capabilities or
home-directory access. It starts automatically after installation and after
reboot. Uninstalling a service stops it and removes its unit only; it never
removes its identity, database, or other state.

## Full Admin Access

Full Admin Access is an explicit owner choice. First install and use the normal
system service. Then, after reviewing the trusted-device permissions, set this
exact setting in `/var/lib/opengate/config.toml`:

```toml
allow_admin = true
```

Switch the service only after that owner approval:

```sh
sudo scripts/install-linux.sh --bin=target/release/opengate --system --full-admin
systemctl status opengate.service
```

This converts the dedicated state directory to root ownership and runs the
systemd unit as root. The privileged unit intentionally omits the filesystem
and capability sandboxes used by the default service, because those sandboxes
would prevent authorized root operations. To return to least privilege, remove
or set `allow_admin = false`, then reinstall without `--full-admin`:

```sh
sudo scripts/install-linux.sh --bin=target/release/opengate --system
```

Do not enable Full Admin for a peer unless its saved-device permission is also
explicitly set to Full Admin Access.

## Distribution packages

The release workflow is configured to publish native packages when a version tag is pushed. Install a `.deb` with your
distribution package manager, for example:

```sh
sudo apt install ./opengate_0.1.0_amd64.deb
```

or an RPM:

```sh
sudo dnf install ./opengate-0.1.0-1.x86_64.rpm
```

Packages install the same least-privileged system service. They do not enable
Full Admin Access.
