#!/usr/bin/env python3
"""Exercise the real Linux terminal UI without logging invitation tokens."""
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import struct
import subprocess
import tempfile
import termios
import time


def main():
    binary = Path("target/release/opengate").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="opengate-tui-", dir="target") as tmp:
        state = Path(tmp).resolve()
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))

        def terminal_session():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        process = subprocess.Popen(
            [str(binary), "--data-dir", str(state)],
            stdin=slave, stdout=slave, stderr=slave,
            env={**os.environ, "TERM": "xterm-256color"},
            preexec_fn=terminal_session,
        )
        os.close(slave)

        def read_until(needle):
            # Ratatui positions blank cells with cursor commands. Text-only assertions
            # ignore whitespace; the PTY still runs the actual terminal renderer.
            deadline = time.monotonic() + 20
            output = b""
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    chunk = os.read(master, 65536)
                    output += chunk
                    if b"\x1b[6n" in chunk:
                        os.write(master, b"\x1b[1;1R")
                    plain = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", output)
                    if re.sub(rb"\s+", b"", needle) in re.sub(rb"\s+", b"", plain):
                        return plain
            raise RuntimeError("terminal did not reach the expected view; output withheld to protect tokens")

        try:
            menu = read_until(b"Q exit")
            for label in (b"Connect to Device", b"Allow Access", b"Saved Devices",
                          b"Connections", b"Settings", b"Diagnostics"):
                assert re.sub(rb"\s+", b"", label) in re.sub(rb"\s+", b"", menu)
            os.write(master, b"2")
            first_view = read_until(b"Action:")
            first_token = re.search(rb"OG1-[A-Z2-7-]+", first_view)
            assert first_token, "pairing token was not displayed"
            os.write(master, b"r\n")
            next_view = read_until(b"Action:")
            next_token = re.search(rb"OG1-[A-Z2-7-]+", next_view)
            assert next_token and next_token[0] != first_token[0], "regenerate did not replace token"
            os.write(master, b"x\n")
            assert b"Pairing token cancelled." in read_until(b"Press Enter to return:")
            os.write(master, b"\n")
            read_until(b"Q exit")
            os.write(master, b"q")
            assert process.wait(timeout=10) == 0
            report = subprocess.run(
                [str(binary), "--data-dir", str(state), "status", "--network"],
                capture_output=True, check=True, text=True,
            )
            status = json.loads(report.stdout)
            assert status["measurement_seconds"] >= 0.9
            print("PASS: all six menu entries; pairing display, regenerate and cancel; return and exit; sampled network status.")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            os.close(master)
            if (state / "daemon.endpoint").exists():
                subprocess.run([str(binary), "--data-dir", str(state), "service", "stop"],
                               capture_output=True, timeout=10)


if __name__ == "__main__":
    main()
