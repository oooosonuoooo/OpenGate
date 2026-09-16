#!/usr/bin/env python3
"""OpenGate - saved-device SSH transport for Windows and Linux.

This MVP provides:
- "Get connected" host mode that exposes ONLY the local OpenSSH server.
- One-time pairing token and saved device authentication.
- "Connect" mode with a persistent local TCP endpoint (default 127.0.0.1:2222).
- Automatic retry for new SSH connections after network/host recovery.
- Cross-platform, standard-library-only Python implementation.

Important network limitation:
Direct TCP mode requires the host address to be reachable from the controller.
Universal NAT/CGNAT traversal without any rendezvous/relay infrastructure is not
possible on all networks. See README.md.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import datetime as dt
import getpass
import hashlib
import hmac
import json
import os
import secrets
import select
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

APP_NAME = "OpenGate"
PROTOCOL_MAGIC = b"OG1"
DEFAULT_PORT = 44344
DEFAULT_LOCAL_PORT = 2222
DEFAULT_SSH_TARGET = "127.0.0.1:22"
MAX_JSON = 64 * 1024
MAX_CONNECTION_WORKERS = 128
CONFIG_LOCK = threading.RLock()


class OpenGateError(Exception):
    pass


def now_ts() -> int:
    return int(time.time())


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    text = text.strip()
    text += "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text.encode("ascii"))


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if is_windows():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def user_data_dir() -> Path:
    if is_windows():
        base = os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / APP_NAME
    base = os.environ.get("XDG_CONFIG_HOME")
    return Path(base) / "opengate" if base else Path.home() / ".config" / "opengate"


def system_data_dir() -> Path:
    if is_windows():
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / APP_NAME
    return Path("/etc/opengate")


def data_dir(system: bool) -> Path:
    env = os.environ.get("OPENGATE_DATA_DIR")
    if env:
        return Path(env)
    return system_data_dir() if system else user_data_dir()


def ensure_dir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if not is_windows():
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def atomic_write_json(path: Path, value: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        if not is_windows():
            os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    finally:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass


def read_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
            if not isinstance(obj, dict):
                raise OpenGateError(f"Invalid configuration in {path}")
            return obj
    except FileNotFoundError:
        return dict(default)


def host_config_path(system: bool) -> Path:
    return data_dir(system) / "host.json"


def devices_config_path() -> Path:
    return user_data_dir() / "devices.json"


def new_host_config() -> Dict[str, Any]:
    return {
        "version": 1,
        "host_id": str(uuid.uuid4()),
        "host_name": socket.gethostname() or "OpenGate Host",
        "bootstrap_secret": "",
        "bootstrap_expires": 0,
        "authorized": {},
        "created_at": now_ts(),
    }


def load_host_config(system: bool) -> Dict[str, Any]:
    path = host_config_path(system)
    with CONFIG_LOCK:
        cfg = read_json(path, {})
        if not cfg:
            cfg = new_host_config()
            atomic_write_json(path, cfg)
        cfg.setdefault("authorized", {})
        cfg.setdefault("bootstrap_secret", "")
        cfg.setdefault("bootstrap_expires", 0)
        return cfg


def save_host_config(system: bool, cfg: Dict[str, Any]) -> None:
    with CONFIG_LOCK:
        atomic_write_json(host_config_path(system), cfg)


def load_devices() -> Dict[str, Any]:
    path = devices_config_path()
    cfg = read_json(path, {"version": 1, "devices": {}})
    cfg.setdefault("devices", {})
    return cfg


def save_devices(cfg: Dict[str, Any]) -> None:
    atomic_write_json(devices_config_path(), cfg)


def local_ipv4_candidates(port: int) -> List[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                ips.add(ip)
        finally:
            s.close()
    except OSError:
        pass
    if not ips:
        ips.add("127.0.0.1")
    return [f"{ip}:{port}" for ip in sorted(ips)]


def parse_endpoint(text: str) -> Tuple[str, int]:
    text = text.strip()
    if text.startswith("["):
        end = text.find("]")
        if end < 0 or end + 1 >= len(text) or text[end + 1] != ":":
            raise OpenGateError(f"Invalid endpoint: {text}")
        return text[1:end], int(text[end + 2 :])
    host, sep, port = text.rpartition(":")
    if not sep or not host:
        raise OpenGateError(f"Endpoint must be host:port: {text}")
    return host, int(port)


def validate_loopback_target(text: str) -> Tuple[str, int]:
    host, port = parse_endpoint(text)
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise OpenGateError("For safety, the host target must be a loopback address (127.0.0.1/localhost/::1).")
    if not (1 <= port <= 65535):
        raise OpenGateError("Invalid target port")
    return host, port


def make_pairing_token(system: bool, advertise: Iterable[str], minutes: int) -> str:
    cfg = load_host_config(system)
    secret = secrets.token_bytes(32)
    cfg["bootstrap_secret"] = b64e(secret)
    cfg["bootstrap_expires"] = now_ts() + max(1, minutes) * 60
    save_host_config(system, cfg)
    candidates = list(dict.fromkeys(x.strip() for x in advertise if x and x.strip()))
    if not candidates:
        candidates = local_ipv4_candidates(DEFAULT_PORT)
    token_obj = {
        "v": 1,
        "host_id": cfg["host_id"],
        "host_name": cfg.get("host_name") or "OpenGate Host",
        "candidates": candidates,
        "secret": b64e(secret),
        "expires": cfg["bootstrap_expires"],
    }
    return "OG1." + b64e(json.dumps(token_obj, separators=(",", ":")).encode("utf-8"))


def decode_pairing_token(token: str) -> Dict[str, Any]:
    token = token.strip()
    if not token.startswith("OG1."):
        raise OpenGateError("This is not an OpenGate pairing token")
    try:
        obj = json.loads(b64d(token[4:]).decode("utf-8"))
    except Exception as exc:
        raise OpenGateError("Invalid pairing token") from exc
    if obj.get("v") != 1 or not obj.get("host_id") or not obj.get("secret"):
        raise OpenGateError("Unsupported or incomplete pairing token")
    if int(obj.get("expires", 0)) < now_ts():
        raise OpenGateError("Pairing token has expired. Generate a new token on the host.")
    candidates = obj.get("candidates") or []
    if not isinstance(candidates, list) or not candidates:
        raise OpenGateError("Pairing token contains no reachable address")
    return obj


def recv_exact(sock: socket.socket, n: int) -> bytes:
    parts = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OpenGateError("Connection closed unexpectedly")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def send_json(sock: socket.socket, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_JSON:
        raise OpenGateError("Protocol message too large")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_json(sock: socket.socket) -> Dict[str, Any]:
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > MAX_JSON:
        raise OpenGateError("Protocol message too large")
    obj = json.loads(recv_exact(sock, size).decode("utf-8"))
    if not isinstance(obj, dict):
        raise OpenGateError("Invalid protocol message")
    return obj


def relay_bidirectional(a: socket.socket, b: socket.socket) -> None:
    a.setblocking(False)
    b.setblocking(False)
    sockets = [a, b]
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 60)
            if exceptional:
                return
            if not readable:
                continue
            for src in readable:
                dst = b if src is a else a
                try:
                    data = src.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                if not data:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                view = memoryview(data)
                while view:
                    try:
                        sent = dst.send(view)
                        view = view[sent:]
                    except (BlockingIOError, InterruptedError):
                        _, writable, _ = select.select([], [dst], [], 10)
                        if not writable:
                            raise OpenGateError("Timed out forwarding data")
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def host_handshake(conn: socket.socket, system: bool) -> Dict[str, Any]:
    nonce = secrets.token_bytes(32)
    conn.sendall(PROTOCOL_MAGIC + nonce)
    request = recv_json(conn)
    mode = request.get("mode")
    controller_id = str(request.get("controller_id") or "")
    proof_text = str(request.get("proof") or "")
    if not controller_id or len(controller_id) > 128:
        raise OpenGateError("Invalid controller identity")
    try:
        proof = b64d(proof_text)
    except Exception as exc:
        raise OpenGateError("Invalid authentication proof") from exc

    with CONFIG_LOCK:
        cfg = load_host_config(system)
        authorized = cfg.setdefault("authorized", {})
        if mode == "pair":
            if int(cfg.get("bootstrap_expires", 0)) < now_ts():
                raise OpenGateError("Pairing token is expired")
            bootstrap_text = cfg.get("bootstrap_secret") or ""
            if not bootstrap_text:
                raise OpenGateError("No active pairing token")
            bootstrap = b64d(bootstrap_text)
            expected = hmac.new(bootstrap, nonce + controller_id.encode("utf-8"), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, proof):
                raise OpenGateError("Pairing token was rejected")
            device_secret = hmac.new(bootstrap, b"device:" + controller_id.encode("utf-8"), hashlib.sha256).digest()
            authorized[controller_id] = {
                "secret": b64e(device_secret),
                "name": str(request.get("controller_name") or "Controller")[:128],
                "paired_at": now_ts(),
                "last_seen": now_ts(),
            }
            # Single-use token: invalidate immediately after first successful pairing.
            cfg["bootstrap_secret"] = ""
            cfg["bootstrap_expires"] = 0
            save_host_config(system, cfg)
            return {"controller_id": controller_id, "paired": True, "purpose": request.get("purpose")}

        if mode == "auth":
            record = authorized.get(controller_id)
            if not isinstance(record, dict) or not record.get("secret"):
                raise OpenGateError("This controller is not paired with the host")
            device_secret = b64d(record["secret"])
            expected = hmac.new(device_secret, nonce, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, proof):
                raise OpenGateError("Authentication failed")
            record["last_seen"] = now_ts()
            save_host_config(system, cfg)
            return {"controller_id": controller_id, "paired": False, "purpose": request.get("purpose")}

    raise OpenGateError("Unsupported authentication mode")


def handle_host_connection(
    conn: socket.socket,
    addr: Tuple[Any, ...],
    system: bool,
    target: Tuple[str, int],
    workers: threading.BoundedSemaphore,
) -> None:
    try:
        conn.settimeout(15)
        auth = host_handshake(conn, system)
        send_json(conn, {"ok": True, "host": socket.gethostname(), "paired": auth["paired"]})
        if auth.get("purpose") == "pair_only":
            return
        target_sock = socket.create_connection(target, timeout=10)
        conn.settimeout(None)
        target_sock.settimeout(None)
        relay_bidirectional(conn, target_sock)
    except Exception as exc:
        try:
            send_json(conn, {"ok": False, "error": str(exc)})
        except Exception:
            pass
        print(f"[{dt.datetime.now().isoformat(timespec='seconds')}] Connection from {addr} rejected/ended: {exc}", file=sys.stderr)
    finally:
        workers.release()
        try:
            conn.close()
        except OSError:
            pass


def run_host(bind_text: str, target_text: str, system: bool) -> None:
    host, port = parse_endpoint(bind_text)
    target = validate_loopback_target(target_text)
    cfg = load_host_config(system)
    print(f"OpenGate host: {cfg.get('host_name')} ({cfg.get('host_id')})")
    print(f"Forwarding authenticated connections to SSH at {target[0]}:{target[1]}")
    print(f"Listening on {host}:{port}")
    print("This service is visible and only forwards to a loopback service; it does not execute commands itself.")

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(128)
    workers = threading.BoundedSemaphore(MAX_CONNECTION_WORKERS)
    try:
        while True:
            conn, addr = listener.accept()
            if not workers.acquire(blocking=False):
                conn.close()
                continue
            t = threading.Thread(
                target=handle_host_connection,
                args=(conn, addr, system, target, workers),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\nOpenGate host stopped.")
    finally:
        listener.close()


def connect_candidate(candidate: str, timeout: float = 8.0) -> socket.socket:
    host, port = parse_endpoint(candidate)
    return socket.create_connection((host, port), timeout=timeout)


def read_challenge(sock: socket.socket) -> bytes:
    header = recv_exact(sock, len(PROTOCOL_MAGIC) + 32)
    if header[: len(PROTOCOL_MAGIC)] != PROTOCOL_MAGIC:
        raise OpenGateError("The remote endpoint is not an OpenGate host")
    return header[len(PROTOCOL_MAGIC) :]


def pair_device(token_text: str, device_name: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    token = decode_pairing_token(token_text)
    controller_id = str(uuid.uuid4())
    controller_name = socket.gethostname() or getpass.getuser() or "Controller"
    bootstrap = b64d(token["secret"])
    device_secret = hmac.new(bootstrap, b"device:" + controller_id.encode("utf-8"), hashlib.sha256).digest()

    errors = []
    for candidate in token["candidates"]:
        sock = None
        try:
            sock = connect_candidate(candidate)
            nonce = read_challenge(sock)
            proof = hmac.new(bootstrap, nonce + controller_id.encode("utf-8"), hashlib.sha256).digest()
            send_json(
                sock,
                {
                    "mode": "pair",
                    "controller_id": controller_id,
                    "controller_name": controller_name,
                    "proof": b64e(proof),
                    "purpose": "pair_only",
                },
            )
            response = recv_json(sock)
            if not response.get("ok"):
                raise OpenGateError(response.get("error") or "Pairing failed")
            name = (device_name or token.get("host_name") or token["host_id"]).strip()
            devices = load_devices()
            final_name = name
            idx = 2
            while final_name in devices["devices"] and devices["devices"][final_name].get("host_id") != token["host_id"]:
                final_name = f"{name}-{idx}"
                idx += 1
            record = {
                "version": 1,
                "name": final_name,
                "host_id": token["host_id"],
                "host_name": token.get("host_name") or name,
                "controller_id": controller_id,
                "secret": b64e(device_secret),
                "candidates": token["candidates"],
                "paired_at": now_ts(),
                "last_candidate": candidate,
            }
            devices["devices"][final_name] = record
            save_devices(devices)
            return final_name, record
        except Exception as exc:
            errors.append(f"{candidate}: {exc}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    raise OpenGateError("Unable to pair with the host. " + " | ".join(errors))


def get_device(name: str) -> Dict[str, Any]:
    devices = load_devices().get("devices", {})
    if name not in devices:
        raise OpenGateError(f"Saved device '{name}' was not found. Use 'opengate devices' to list devices.")
    record = devices[name]
    if not isinstance(record, dict):
        raise OpenGateError(f"Saved device '{name}' is invalid")
    return record


def save_last_candidate(device_name: str, candidate: str) -> None:
    devices = load_devices()
    rec = devices.get("devices", {}).get(device_name)
    if isinstance(rec, dict):
        rec["last_candidate"] = candidate
        save_devices(devices)


def open_authenticated_tunnel(device_name: str, record: Dict[str, Any]) -> socket.socket:
    controller_id = str(record["controller_id"])
    device_secret = b64d(str(record["secret"]))
    candidates = list(record.get("candidates") or [])
    last = record.get("last_candidate")
    if last in candidates:
        candidates.remove(last)
        candidates.insert(0, last)
    errors = []
    for candidate in candidates:
        sock = None
        try:
            sock = connect_candidate(candidate)
            nonce = read_challenge(sock)
            proof = hmac.new(device_secret, nonce, hashlib.sha256).digest()
            send_json(
                sock,
                {
                    "mode": "auth",
                    "controller_id": controller_id,
                    "proof": b64e(proof),
                    "purpose": "tunnel",
                },
            )
            response = recv_json(sock)
            if not response.get("ok"):
                raise OpenGateError(response.get("error") or "Authentication failed")
            sock.settimeout(None)
            save_last_candidate(device_name, candidate)
            return sock
        except Exception as exc:
            errors.append(f"{candidate}: {exc}")
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    raise OpenGateError("No saved address is reachable. " + " | ".join(errors))


def handle_local_connection(
    local: socket.socket,
    addr: Tuple[Any, ...],
    device_name: str,
    record: Dict[str, Any],
    retry_seconds: int,
    workers: threading.BoundedSemaphore,
) -> None:
    deadline = time.time() + max(0, retry_seconds)
    delay = 1.0
    while True:
        try:
            remote = open_authenticated_tunnel(device_name, record)
            relay_bidirectional(local, remote)
            workers.release()
            return
        except Exception as exc:
            if time.time() >= deadline:
                print(f"Local SSH connection from {addr} failed: {exc}", file=sys.stderr)
                try:
                    local.close()
                except OSError:
                    pass
                workers.release()
                return
            time.sleep(delay)
            delay = min(delay * 1.7, 8.0)


def run_controller(device_name: str, listen_text: str, retry_seconds: int) -> None:
    record = get_device(device_name)
    host, port = parse_endpoint(listen_text)
    print(f"OpenGate controller -> {device_name}")
    print(f"Local SSH endpoint: {host}:{port}")
    print(f"Example: ssh -p {port} <remote-user>@{host}")
    print("The proxy remains available and retries new connections when the remote host/network returns.")

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    workers = threading.BoundedSemaphore(MAX_CONNECTION_WORKERS)
    try:
        while True:
            local, addr = listener.accept()
            if not workers.acquire(blocking=False):
                local.close()
                continue
            t = threading.Thread(
                target=handle_local_connection,
                args=(local, addr, device_name, record, retry_seconds, workers),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\nOpenGate controller stopped.")
    finally:
        listener.close()


def list_devices() -> None:
    devices = load_devices().get("devices", {})
    if not devices:
        print("No saved devices.")
        return
    print("Saved devices:")
    for name, rec in sorted(devices.items()):
        candidates = ", ".join(rec.get("candidates") or [])
        paired = rec.get("paired_at")
        paired_text = dt.datetime.fromtimestamp(paired).isoformat(timespec="minutes") if paired else "unknown"
        print(f"  {name}: {rec.get('host_name', '')} | {candidates} | paired {paired_text}")


def remove_device(name: str) -> None:
    cfg = load_devices()
    if name not in cfg.get("devices", {}):
        raise OpenGateError(f"Saved device '{name}' does not exist")
    del cfg["devices"][name]
    save_devices(cfg)
    print(f"Removed saved device '{name}' from this controller.")
    print("For complete revocation, also run 'opengate revoke <controller-id>' on the host.")


def list_authorized(system: bool) -> None:
    cfg = load_host_config(system)
    authorized = cfg.get("authorized", {})
    if not authorized:
        print("No paired controllers.")
        return
    print("Paired controllers:")
    for controller_id, rec in authorized.items():
        last = rec.get("last_seen")
        last_text = dt.datetime.fromtimestamp(last).isoformat(timespec="minutes") if last else "never"
        print(f"  {controller_id} | {rec.get('name','Controller')} | last seen {last_text}")


def revoke_controller(system: bool, controller_id: str) -> None:
    cfg = load_host_config(system)
    authorized = cfg.get("authorized", {})
    if controller_id not in authorized:
        raise OpenGateError("Controller ID was not found")
    del authorized[controller_id]
    save_host_config(system, cfg)
    print(f"Revoked controller {controller_id}.")


def interactive_menu() -> None:
    print("OpenGate")
    print("1) Connect")
    print("2) Get connected")
    print("3) Saved devices")
    choice = input("Select: ").strip()
    if choice == "1":
        cfg = load_devices().get("devices", {})
        if cfg:
            names = sorted(cfg)
            print("Saved devices:")
            for i, name in enumerate(names, 1):
                print(f"  {i}) {name}")
            print("  N) Pair a new device")
            selection = input("Select device: ").strip()
            if selection.lower() != "n":
                try:
                    name = names[int(selection) - 1]
                except Exception:
                    raise OpenGateError("Invalid selection")
                run_controller(name, f"127.0.0.1:{DEFAULT_LOCAL_PORT}", 120)
                return
        token = input("Paste pairing token: ").strip()
        name, _ = pair_device(token, None)
        print(f"Paired as '{name}'.")
        run_controller(name, f"127.0.0.1:{DEFAULT_LOCAL_PORT}", 120)
    elif choice == "2":
        system = is_admin()
        token = make_pairing_token(system, local_ipv4_candidates(DEFAULT_PORT), 15)
        print("Pairing token (valid 15 minutes, single use):")
        print(token)
        run_host(f"0.0.0.0:{DEFAULT_PORT}", DEFAULT_SSH_TARGET, system)
    elif choice == "3":
        list_devices()
    else:
        raise OpenGateError("Invalid selection")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opengate", description="Saved-device OpenSSH transport for Windows and Linux")
    sub = parser.add_subparsers(dest="command")

    p_host = sub.add_parser("host", help="Get connected: run the host service")
    p_host.add_argument("--bind", default=f"0.0.0.0:{DEFAULT_PORT}", help="OpenGate listen address")
    p_host.add_argument("--target", default=DEFAULT_SSH_TARGET, help="Loopback SSH target; default 127.0.0.1:22")
    p_host.add_argument("--system", action="store_true", help="Use system-wide host configuration")

    p_token = sub.add_parser("token", help="Generate a new single-use pairing token")
    p_token.add_argument("--advertise", action="append", default=[], help="Reachable host:port to put in token; may be repeated")
    p_token.add_argument("--minutes", type=int, default=15, help="Token validity in minutes")
    p_token.add_argument("--system", action="store_true", help="Use system-wide host configuration")

    p_connect = sub.add_parser("connect", help="Connect to a new or saved host")
    group = p_connect.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", help="Pairing token for a new host")
    group.add_argument("--device", help="Saved device name")
    p_connect.add_argument("--name", help="Name to save a newly paired host under")
    p_connect.add_argument("--listen", default=f"127.0.0.1:{DEFAULT_LOCAL_PORT}", help="Local SSH proxy listen address")
    p_connect.add_argument("--retry-seconds", type=int, default=120, help="How long each new local SSH connection waits for the host to return")

    sub.add_parser("devices", help="List saved devices on this controller")

    p_remove = sub.add_parser("remove", help="Remove a saved device from this controller")
    p_remove.add_argument("name")

    p_auth = sub.add_parser("authorized", help="List controllers paired with this host")
    p_auth.add_argument("--system", action="store_true")

    p_revoke = sub.add_parser("revoke", help="Revoke a controller on this host")
    p_revoke.add_argument("controller_id")
    p_revoke.add_argument("--system", action="store_true")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not args.command:
            interactive_menu()
            return 0
        if args.command == "host":
            run_host(args.bind, args.target, args.system)
        elif args.command == "token":
            token = make_pairing_token(args.system, args.advertise, args.minutes)
            print(token)
        elif args.command == "connect":
            if args.token:
                name, _ = pair_device(args.token, args.name)
                print(f"Paired successfully. Saved device name: {name}")
            else:
                name = args.device
            run_controller(name, args.listen, args.retry_seconds)
        elif args.command == "devices":
            list_devices()
        elif args.command == "remove":
            remove_device(args.name)
        elif args.command == "authorized":
            list_authorized(args.system)
        elif args.command == "revoke":
            revoke_controller(args.system, args.controller_id)
        else:
            parser.error("Unknown command")
        return 0
    except OpenGateError as exc:
        print(f"OpenGate error: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"Permission error: {exc}. Try running with administrator/root privileges for system host configuration.", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
