#!/usr/bin/env python3
"""Write a bounded, host-local liveness marker to the VM console."""
import socket
import syslog
import time
from datetime import datetime, timezone

while True:
    line = (
        f"mhbench-console-audit host={socket.gethostname()} "
        f"ts={datetime.now(timezone.utc).isoformat()} state=alive"
    )
    try:
        with open("/dev/console", "w", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        syslog.syslog(syslog.LOG_WARNING, "mhbench-console-audit write failed")
    time.sleep(60)
