#!/usr/bin/env python3
"""Opt-in network acceptance test; unprivileged user/net namespaces protect the host.

Run from the repository root after cargo build --release. --large uses 2 GiB+17
bytes; the default uses 128 MiB. No sudo, host network change, or real Internet
outage is needed. This is controlled Linux network evidence, not a CGNAT test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def command(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=100, **kwargs)
    if result.returncode:
        # Commands may return invitations; never include arbitrary stdout in errors.
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {result.stderr[:1000]}")
    return result.stdout


def eventually(check, seconds, description):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.2)
    raise RuntimeError(description)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def run_inside(args):
    original = os.environ.get("OPENGATE_TEST_OUTER_NETNS")
    if not original or original == os.readlink("/proc/self/ns/net") or os.geteuid() != 0:
        raise RuntimeError("refusing network mutations without verified user/network namespace isolation")
    binary = Path(args.binary).resolve(strict=True)
    processes = []
    with tempfile.TemporaryDirectory(prefix="opengate-net-", dir=Path("target").resolve()) as tmp:
        root = Path(tmp)
        a, b = root / "a", root / "b"
        a.mkdir(mode=0o700)
        b.mkdir(mode=0o700)
        keeper = subprocess.Popen(["unshare", "--net", "--", sys.executable, "-u", "-c",
            "import os,time; print(os.readlink('/proc/self/ns/net')); time.sleep(1800)"], stdout=subprocess.PIPE, text=True)
        processes.append(keeper)
        child_namespace = keeper.stdout.readline().strip()
        if not child_namespace or child_namespace == os.readlink("/proc/self/ns/net"):
            raise RuntimeError("second isolated network namespace did not start")
        ns = ["nsenter", "--target", str(keeper.pid), "--net", "--"]

        def peer_command(peer, *words, **kwargs):
            prefix = ns if peer == b else []
            return command(*prefix, str(binary), "--data-dir", str(peer), *words, **kwargs)

        def connected(peer, other):
            status = json.loads(peer_command(peer, "status"))
            return any(c["peer_id"] == other for c in status["network"]["connections"])

        try:
            command("ip", "link", "set", "lo", "up")
            command(*ns, "ip", "link", "set", "lo", "up")
            command("ip", "link", "add", "og-a", "type", "veth", "peer", "name", "og-b")
            command("ip", "link", "set", "og-b", "netns", str(keeper.pid))
            command("ip", "addr", "add", "10.203.1.1/24", "dev", "og-a")
            command(*ns, "ip", "addr", "add", "10.203.2.1/24", "dev", "og-b")
            command("ip", "link", "set", "og-a", "up")
            command(*ns, "ip", "link", "set", "og-b", "up")
            command("ip", "route", "add", "10.203.2.0/24", "dev", "og-a")
            command(*ns, "ip", "route", "add", "10.203.1.0/24", "dev", "og-b")
            for prefix, interface in (([], "og-a"), (ns, "og-b")):
                command(*prefix, "tc", "qdisc", "add", "dev", interface, "root", "netem", "delay", "15ms", "loss", "0.2%")
            for peer, prefix, address in ((a, [], "10.203.1.1"), (b, ns, "10.203.2.1")):
                process = subprocess.Popen([*prefix, str(binary), "--data-dir", str(peer), "daemon", "--listen",
                    f"/ip4/{address}/udp/43001/quic-v1"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(process)
                eventually(lambda: (peer / "daemon.endpoint").exists(), 15, "daemon startup failed")
                # uid 0 exists only inside this unprivileged user namespace.
                peer_command(peer, "config", "set", "allow_admin", "true")
            peer_command(b, "config", "set", "name", "NET-HOST")
            invitation = peer_command(b, "allow", "--permissions", "full-admin", "--acknowledge-full-admin")
            token = re.search(r"OG1-[A-Z2-7-]+", invitation)
            if not token:
                raise RuntimeError("no invitation returned")
            paired = json.loads(peer_command(a, "connect", "--token-stdin", "--grant", "full-admin",
                "--acknowledge-full-admin", input=token[0] + "\n"))
            peer_id = paired["device"]["peer_id"]
            del invitation, token, paired
            size = 2 * 1024**3 + 17 if args.large else 128 * 1024**2
            source = root / "source.bin"
            with source.open("wb") as stream:
                stream.truncate(size)
            expected_hash = digest(source)
            transfer_log = root / "transfer.log"
            with transfer_log.open("wb") as output:
                transfer = subprocess.Popen([str(binary), "--data-dir", str(a), "push", peer_id,
                    str(source), "received.bin"], stdout=output, stderr=output)
                processes.append(transfer)

                def stage_offset():
                    if transfer.poll() is not None:
                        raise RuntimeError("transfer ended before network interruption")
                    return max((p.stat().st_size for p in (b / "shared").glob("*.part")), default=0)

                offset = eventually(lambda: (n if (n := stage_offset()) >= size // 2 else 0),
                                    600, "transfer did not reach halfway")
                print(f"Transferred {offset}/{size} bytes under 30ms round-trip delay and 0.2% loss per direction.", flush=True)
                command("tc", "qdisc", "replace", "dev", "og-a", "root", "netem", "loss", "100%")
                command(*ns, "tc", "qdisc", "replace", "dev", "og-b", "root", "netem", "loss", "100%")
                eventually(lambda: not connected(a, peer_id), 100, "peer did not detect network loss")
                retained = stage_offset()
                if retained < offset:
                    raise RuntimeError("durable partial data regressed during interruption")
                print(f"Network loss detected; durable checkpoint retained {retained} bytes. Restoring isolated link.", flush=True)
                for prefix, interface in (([], "og-a"), (ns, "og-b")):
                    command(*prefix, "tc", "qdisc", "replace", "dev", interface, "root", "netem", "delay", "15ms", "loss", "0.2%")
                # No explicit Connect or new invitation: the running daemon/CLI must recover.
                eventually(lambda: connected(a, peer_id), 150, "saved peer did not reconnect automatically")
                minimum_after_restore = retained
                deadline = time.monotonic() + 900
                while transfer.poll() is None and time.monotonic() < deadline:
                    values = [p.stat().st_size for p in (b / "shared").glob("*.part")]
                    if values:
                        minimum_after_restore = min(minimum_after_restore, max(values))
                    time.sleep(0.05)
                if transfer.poll() != 0:
                    raise RuntimeError("CLI transfer failed to finish after restoring network")
            if minimum_after_restore < retained:
                raise RuntimeError("resumed transfer restarted from an earlier offset")
            destination = b / "shared/received.bin"
            if destination.stat().st_size != size or digest(destination) != expected_hash:
                raise RuntimeError("destination length or SHA-256 mismatch")
            if "Transfer interrupted; reconnecting" not in transfer_log.read_text():
                raise RuntimeError("test did not exercise the CLI interruption/resume path")
            print(f"PASS: two isolated subnets; real netem loss/restore; saved trust automatically reconnected; CLI resumed {size} bytes without resetting checkpoint; SHA-256 matches.", flush=True)
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--large", action="store_true")
    parser.add_argument("--binary", default="target/release/opengate")
    parser.add_argument("--inside-namespace", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside_namespace:
        run_inside(args)
    else:
        env = {**os.environ, "OPENGATE_TEST_OUTER_NETNS": os.readlink("/proc/self/ns/net")}
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "--", sys.executable,
            str(Path(__file__).resolve()), *sys.argv[1:], "--inside-namespace"], env=env)
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
