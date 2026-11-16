#!/usr/bin/env python3
"""Write a bounded, host-local liveness and network-state marker to the VM console."""
import socket
import subprocess
import syslog
import time
from datetime import datetime, timezone


def _ip(*args: str) -> str:
    try:
        return subprocess.run(["ip", "-4", *args], capture_output=True, text=True,
                              timeout=5, check=False).stdout.strip().replace("\n", "; ")
    except OSError:
        return "unavailable"


while True:
    line = (
        f"mhbench-console-audit host={socket.gethostname()} "
        f"ts={datetime.now(timezone.utc).isoformat()} state=alive "
        f"addr={_ip('-o', 'addr', 'show')} "
        f"route={_ip('route', 'show')} "
        f"neigh={_ip('neigh', 'show')}"
    )
    try:
        with open("/dev/console", "w", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        syslog.syslog(syslog.LOG_WARNING, "mhbench-console-audit write failed")
    time.sleep(60)
