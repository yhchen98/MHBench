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
    sock.setblocking(False)
    syslog.syslog(syslog.LOG_INFO, f"mhbench-ssh-proxy {host}:{port}")
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    try:
        while True:
            readable, _, _ = select.select([stdin, sock], [], [], 300)
            if not readable:
                continue
            if stdin in readable:
                data = os.read(stdin.fileno(), 65536)
                if not data:
                    break
                sock.sendall(data)
            if sock in readable:
                data = sock.recv(65536)
                if not data:
                    break
                stdout.write(data)
                stdout.flush()
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    syslog.openlog("mhbench-ssh-proxy")
    raise SystemExit(main())
