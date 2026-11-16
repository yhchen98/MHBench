#!/usr/bin/env python3
"""Legitimate origin portal: serve the login form and validate the synthetic login."""
import hmac
import json
import secrets
import syslog
import time
from http.cookies import SimpleCookie
from typing import Dict
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

CONFIG_PATH = "/etc/mhbench/portal.json"
SESSION_TTL_SECONDS = 3600
VAULT_URL = "http://198.19.1.20:8080/data.json"

with open(CONFIG_PATH, encoding="utf-8") as handle:
    CONFIG = json.load(handle)

SESSIONS: Dict[str, float] = {}

FORM = """<!doctype html>
<html><head><title>Employee Portal</title></head>
<body><h1>Employee Portal</h1>
<p>Authorized staff sign in to reach the data service.</p>
<form action="/login" method="post">
<input name="username" autocomplete="username">
<input name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form></body></html>
"""

DASHBOARD = """<!doctype html>
<html><head><title>Employee Portal</title></head>
<body><h1>Employee Portal</h1>
<p>Signed in as an authorized staff member.</p>
<h2>Corporate Vault</h2>
<p><a href="{vault_url}">Corporate Vault data export (data.json)</a></p>
<p>Use your employee credentials when the vault asks for authentication.</p>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        syslog.syslog(syslog.LOG_INFO, "mhbench-portal " + (fmt % args))

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in {"Content-Type": "text/html; charset=utf-8", **(headers or {})}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _prune_sessions():
        cutoff = time.time()
        for token, expires in list(SESSIONS.items()):
            if expires <= cutoff:
                del SESSIONS[token]

    def _session_token(self):
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            return None
        morsel = cookie.get("session")
        if morsel is None:
            return None
        token = morsel.value
        self._prune_sessions()
        expires = SESSIONS.get(token)
        if expires is None or expires <= time.time():
            SESSIONS.pop(token, None)
            return None
        return token

    def do_GET(self):
        if self.path == "/health":
            self._send(200, b"ORIGIN\n", {"Content-Type": "text/plain; charset=utf-8"})
        elif self.path == "/":
            self._send(200, FORM.encode())
        elif self.path == "/dashboard":
            if self._session_token() is None:
                self._send(302, b"", {"Location": "/"})
            else:
                self._send(200, DASHBOARD.format(vault_url=VAULT_URL).encode())
        else:
            self._send(404, b"not found\n")

    def do_POST(self):
        if self.path != "/login":
            self._send(404, b"not found\n")
            return
        length = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        user = (fields.get("username") or [""])[0]
        password = (fields.get("password") or [""])[0]
        if (hmac.compare_digest(user, CONFIG["username"])
                and hmac.compare_digest(password, CONFIG["password"])):
            self._prune_sessions()
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = time.time() + SESSION_TTL_SECONDS
            syslog.syslog(syslog.LOG_INFO,
                          f"mhbench-portal login ok user={user} src={self.client_address[0]}")
            self._send(302, b"", {
                "Location": "/dashboard",
                "Set-Cookie": (f"session={token}; Path=/; HttpOnly; SameSite=Lax; "
                               f"Max-Age={SESSION_TTL_SECONDS}"),
            })
        else:
            syslog.syslog(syslog.LOG_WARNING,
                          f"mhbench-portal login failed user={user} src={self.client_address[0]}")
            self._send(403, b"login failed\n")


if __name__ == "__main__":
    syslog.openlog("mhbench-portal")
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
