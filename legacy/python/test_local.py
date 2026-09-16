#!/usr/bin/env python3
"""Local smoke test for OpenGate's pairing/authenticated tunnel.

Runs the host against a local echo service rather than SSH, pairs a controller,
then confirms bytes pass through the saved-device tunnel.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
APP = ROOT / "opengate.py"


def echo_server(port: int, ready: threading.Event, stop: threading.Event):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen()
    s.settimeout(0.2)
    ready.set()
    try:
        while not stop.is_set():
            try:
                c, _ = s.accept()
            except socket.timeout:
                continue
            def handle(conn):
                with conn:
                    data = conn.recv(65536)
                    conn.sendall(data)
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    finally:
        s.close()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="opengate-test-") as td:
        base = Path(td)
        host_dir = base / "host"
        controller_dir = base / "controller"
        host_dir.mkdir()
        controller_dir.mkdir()

        stop = threading.Event()
        ready = threading.Event()
        threading.Thread(target=echo_server, args=(22422, ready, stop), daemon=True).start()
        ready.wait(2)

        host_env = os.environ.copy()
        host_env["OPENGATE_DATA_DIR"] = str(host_dir)
        ctrl_env = os.environ.copy()
        ctrl_env["XDG_CONFIG_HOME"] = str(controller_dir)

        host = subprocess.Popen(
            [sys.executable, str(APP), "host", "--bind", "127.0.0.1:44444", "--target", "127.0.0.1:22422"],
            env=host_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        controller = None
        try:
            time.sleep(0.3)
            token = subprocess.check_output(
                [sys.executable, str(APP), "token", "--advertise", "127.0.0.1:44444", "--minutes", "5"],
                env=host_env,
                text=True,
            ).strip()

            # Pairing command normally stays running as the local proxy, so a brief
            # timeout is sufficient to complete pairing before we start saved mode.
            try:
                subprocess.run(
                    [sys.executable, str(APP), "connect", "--token", token, "--name", "smoke", "--listen", "127.0.0.1:33444"],
                    env=ctrl_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=0.8,
                )
            except subprocess.TimeoutExpired:
                pass

            controller = subprocess.Popen(
                [sys.executable, str(APP), "connect", "--device", "smoke", "--listen", "127.0.0.1:33444", "--retry-seconds", "2"],
                env=ctrl_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.time() + 5
            while True:
                try:
                    s = socket.create_connection(("127.0.0.1", 33444), timeout=0.5)
                    break
                except OSError:
                    if time.time() >= deadline:
                        raise
                    time.sleep(0.1)
            with s:
                s.sendall(b"opengate-smoke-test")
                got = s.recv(128)
            assert got == b"opengate-smoke-test", got
            print("PASS: pairing, saved-device authentication, and tunnel forwarding")
            return 0
        finally:
            if controller is not None:
                controller.terminate()
            host.terminate()
            stop.set()


if __name__ == "__main__":
    raise SystemExit(main())
