#!/usr/bin/env python3
"""Opt-in systemd user-service test using an isolated runtime unit and state.

No persistent unit is enabled and no existing OpenGate installation is changed.
Run from the repository root after cargo build --release.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def main():
    binary = Path("target/release/opengate").resolve(strict=True)
    unit = "opengate-validation-" + uuid.uuid4().hex + ".service"
    units = Path(os.environ["XDG_RUNTIME_DIR"]) / "systemd/user"
    units.mkdir(parents=True, exist_ok=True)
    unitfile = units / unit
    with tempfile.TemporaryDirectory(prefix="opengate-service-", dir=Path("target").resolve()) as tmp:
        state = Path(tmp)
        state.chmod(0o700)
        unitfile.write_text(run(str(binary), "--data-dir", str(state), "service", "print-unit").stdout)
        try:
            run("systemd-analyze", "--user", "verify", str(unitfile))
            run("systemctl", "--user", "daemon-reload")
            run("systemctl", "--user", "start", unit)
            endpoint = state / "daemon.endpoint"
            for _ in range(100):
                if endpoint.exists():
                    break
                time.sleep(0.1)
            if not endpoint.exists():
                raise RuntimeError("daemon endpoint was not created")
            first = json.loads(endpoint.read_text())["pid"]
            identity = (state / "identity.key").read_bytes()
            run("systemctl", "--user", "kill", "--signal=SIGKILL", unit)
            second = first
            for _ in range(150):
                try:
                    second = json.loads(endpoint.read_text())["pid"]
                    if second != first:
                        break
                except (FileNotFoundError, json.JSONDecodeError):
                    pass
                time.sleep(0.1)
            if second == first:
                raise RuntimeError("systemd did not restart the daemon")
            if (state / "identity.key").read_bytes() != identity:
                raise RuntimeError("identity changed after restart")
            run("systemctl", "--user", "stop", unit)
            if endpoint.exists():
                raise RuntimeError("endpoint remained after clean stop")
            print("PASS: generated user unit started, restarted after SIGKILL with stable identity, and stopped cleanly.")
        finally:
            subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True)
            unitfile.unlink(missing_ok=True)
            run("systemctl", "--user", "daemon-reload")
            subprocess.run(["systemctl", "--user", "reset-failed", unit], capture_output=True)


if __name__ == "__main__":
    main()
