#!/usr/bin/env python3
"""Exact-destination TCP proxy used by MHBench's forced-command SSH accounts.

The account's ForceCommand points here with an allow-list file. The client's
SSH_ORIGINAL_COMMAND must name an exact (host, port) pair in that file. The
script never invokes a shell and does not implement SSH forwarding.
"""
from __future__ import annotations

import os
import select
import socket
import sys
import syslog
import threading


def _allow(path: str) -> set[tuple[str, int]]:
    allowed: set[tuple[str, int]] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) == 2:
                try:
                    allowed.add((parts[0], int(parts[1])))
                except ValueError:
                    continue
    return allowed


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    allowed = _allow(sys.argv[1])
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip().split()
    if len(command) != 2:
        return 1
    host, port_text = command
    try:
        port = int(port_text)
    except ValueError:
        return 1
    if (host, port) not in allowed or not (1 <= port <= 65535):
        return 1
    try:
        sock = socket.create_connection((host, port), timeout=15)
    except OSError:
        return 1
    sock.settimeout(None)
    syslog.syslog(syslog.LOG_INFO, f"mhbench-ssh-proxy {host}:{port}")
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    stop = threading.Event()

    def close() -> None:
        stop.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def stdin_to_socket() -> None:
        while not stop.is_set():
            try:
                readable, _, _ = select.select([stdin], [], [], 1.0)
            except (OSError, ValueError):
                close()
                return
            if not readable:
                continue
            try:
                data = os.read(stdin.fileno(), 65536)
            except OSError:
                close()
                return
            if not data:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            try:
                sock.sendall(data)
            except OSError:
                close()
                return

    def socket_to_stdout() -> None:
        while not stop.is_set():
            try:
                readable, _, _ = select.select([sock], [], [], 1.0)
            except (OSError, ValueError):
                close()
                return
            if not readable:
                continue
            try:
                data = sock.recv(65536)
            except OSError:
                close()
                return
            if not data:
                close()
                return
            try:
                stdout.write(data)
                stdout.flush()
            except (BrokenPipeError, OSError):
                close()
                return

    threads = [
        threading.Thread(target=stdin_to_socket),
        threading.Thread(target=socket_to_stdout),
    ]
    for thread in threads:
        thread.start()
    try:
        while any(thread.is_alive() for thread in threads):
            for thread in threads:
                thread.join(0.2)
    finally:
        close()
        sock.close()
    return 0


if __name__ == "__main__":
    syslog.openlog("mhbench-ssh-proxy")
    raise SystemExit(main())
