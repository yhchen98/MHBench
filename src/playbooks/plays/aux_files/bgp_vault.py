#!/usr/bin/env python3
"""Protected data service: authenticated serving of the per-deployment random file."""
import base64
import hashlib
import hmac
import json
import syslog
from http.server import BaseHTTPRequestHandler, HTTPServer

CONFIG_PATH = "/etc/mhbench/vault.json"

with open(CONFIG_PATH, encoding="utf-8") as handle:
    CONFIG = json.load(handle)
DATA_PATH = CONFIG["data_path"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        syslog.syslog(syslog.LOG_INFO, "mhbench-vault " + (fmt % args))

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in {"Content-Type": "text/html; charset=utf-8", **(headers or {})}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _authenticated_user(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
            user, separator, password = decoded.partition(":")
        except (ValueError, UnicodeDecodeError):
            return None
        if not separator:
            return None
        user_ok = hmac.compare_digest(user, CONFIG["username"])
        password_ok = hmac.compare_digest(password, CONFIG["password"])
        return user if user_ok and password_ok else None

    def do_GET(self):
        if self.path == "/health":
            self._send(200, b"VAULT\n", {"Content-Type": "text/plain; charset=utf-8"})
            return
        if self.path != "/data.json":
            self._send(404, b"not found\n")
            return
        user = self._authenticated_user()
        if user is None:
            syslog.syslog(syslog.LOG_WARNING,
                          f"mhbench-vault auth failed src={self.client_address[0]}")
            self._send(401, b"authentication required\n", {
                "WWW-Authenticate": 'Basic realm="Protected Data Service"',
                "Content-Type": "text/plain; charset=utf-8",
            })
            return
        with open(DATA_PATH, "rb") as handle:
            body = handle.read()
        digest = hashlib.md5(body).hexdigest()
        syslog.syslog(syslog.LOG_INFO,
                      f"mhbench-vault served user={user} src={self.client_address[0]} "
                      f"bytes={len(body)} md5={digest}")
        self._send(200, body, {"Content-Type": "application/json"})


if __name__ == "__main__":
    syslog.openlog("mhbench-vault")
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
