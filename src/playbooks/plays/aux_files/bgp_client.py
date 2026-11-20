#!/usr/bin/env python3
"""Legitimate client: fetch the login form and submit credentials on a fixed schedule."""
import http.cookiejar
import json
import re
import ssl
import syslog
import time
import urllib.parse
import urllib.request

CONFIG_PATH = "/etc/mhbench/client.json"
INTERVAL_SECONDS = 30
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

with open(CONFIG_PATH, encoding="utf-8") as handle:
    CONFIG = json.load(handle)

PORTAL = CONFIG["portal"].rstrip("/")
USERNAME = CONFIG["username"]
PASSWORD = CONFIG["password"]
CA_FILE = CONFIG.get("ca_file")
if PORTAL.startswith("https://") and not CA_FILE:
    raise SystemExit("HTTPS portal requires an explicit ca_file; refusing system trust fallback")
_handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
if PORTAL.startswith("https://"):
    _context = ssl.create_default_context(cafile=CA_FILE)
    _context.minimum_version = ssl.TLSVersion.TLSv1_2
    _handlers.append(urllib.request.HTTPSHandler(context=_context))
OPENER = urllib.request.build_opener(*_handlers)

FORM_RE = re.compile(r"<form\b[^>]*\baction=[\"']([^\"']*)[\"'][^>]*>", re.I)
INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
NAME_RE = re.compile(r"\bname=[\"']([^\"']+)[\"']", re.I)


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with OPENER.open(request, timeout=10) as response:
        return response.status, response.read().decode("utf-8", "replace")


def submit(form_action, html):
    fields = {"username": USERNAME, "password": PASSWORD}
    for tag in INPUT_RE.findall(html):
        name = NAME_RE.search(tag)
        if name and name.group(1) not in fields:
            fields[name.group(1)] = ""
    action = form_action or "/login"
    url = urllib.parse.urljoin(PORTAL + "/", action)
    data = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"User-Agent": USER_AGENT})
    with OPENER.open(request, timeout=10) as response:
        response.read()
        return response.status


def main():
    syslog.openlog("mhbench-client")
    while True:
        try:
            status, html = fetch(PORTAL + "/")
            form = FORM_RE.search(html)
            if not form:
                syslog.syslog(syslog.LOG_INFO,
                              "mhbench-client no login form; not submitting")
            else:
                code = submit(form.group(1), html)
                syslog.syslog(syslog.LOG_INFO,
                              f"mhbench-client login ok status={code}")
        except Exception as exc:  # noqa: BLE001 — the client must keep its schedule
            syslog.syslog(syslog.LOG_WARNING,
                          f"mhbench-client login error {type(exc).__name__}: {exc}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
