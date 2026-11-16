#!/usr/bin/env python3
"""Prepare and verify the guest network managed by the routing playbook."""
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import sys


def ip_json(*args):
    return json.loads(subprocess.check_output(["ip", "-j", *args], text=True))


def devices(network):
    links = ip_json("link", "show")
    result = {}
    for name, entry in network["network"]["ethernets"].items():
        mac = entry["match"]["macaddress"].lower()
        matches = [link["ifname"] for link in links if link.get("address", "").lower() == mac]
        if len(matches) != 1:
            raise ValueError("Expected one guest NIC for " + name + " (" + mac + ")")
        result[name] = matches[0]
    return result


def prepare(payload):
    network = payload["network"]
    names = devices(network)
    control = network["network"]["ethernets"]["mhb_control"]
    control.setdefault("routes", [])
    link_local = ipaddress.IPv4Network("169.254.0.0/16")
    for route in ip_json("-4", "route", "show"):
        if route.get("dst") in (None, "default") or not route.get("gateway"):
            continue
        if route.get("dev") == names["mhb_control"] and ipaddress.IPv4Network(route["dst"]).subnet_of(link_local):
            destination = ipaddress.IPv4Network(route["dst"])
            data = [ipaddress.IPv4Interface(a).network for key, nic in network["network"]["ethernets"].items()
                    if key != "mhb_control" for a in nic.get("addresses", [])]
            if any(destination.overlaps(prefix) for prefix in data):
                raise ValueError("Provider control route overlaps the data plane")
            entry = {"to": str(destination), "via": route["gateway"]}
            if entry not in control["routes"]:
                control["routes"].append(entry)
    hostname = payload.get("c2_hostname")
    if hostname:
        prefixes = [ipaddress.IPv4Network(p) for p in payload["control_prefixes"]]
        addresses = {ipaddress.IPv4Address(row[4][0])
                     for row in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)}
        if not addresses or any(not any(a in p for p in prefixes) for a in addresses):
            raise ValueError("C2 IPv4 addresses are not covered by control routes")
    if "ID=kali" in open("/etc/os-release", encoding="utf-8").read():
        network["network"]["renderer"] = "ifupdown"
    return network



def apply_ifupdown(network):
    names = devices(network)
    ethernets = network["network"]["ethernets"]
    control = ethernets["mhb_control"]
    data_name = next(name for name in ethernets if name != "mhb_control")
    data = ethernets[data_name]

    # The experimental control interface is DHCP-only. Kali's dhclient must not install the DHCP
    # default route; the data interface remains the sole default.
    if control.get("dhcp4"):
        Path("/etc/dhcp/dhclient.conf").write_text(
            "supersede routers 0.0.0.0;\nrequest subnet-mask, broadcast-address, time-offset, "
            "host-name, domain-name, domain-search, interface-mtu;\n", encoding="utf-8")

    lines = ["auto lo", "iface lo inet loopback", ""]
    for entry, ifname in ((control, names["mhb_control"]), (data, names[data_name])):
        lines.append(f"auto {ifname}")
        if entry.get("dhcp4"):
            lines.append(f"iface {ifname} inet dhcp")
            # Kali's cloud-init/networkd path can install the DHCP default even when dhclient is
            # configured to supersede routers; remove any control default after the interface is up.
            lines.append(f"    post-up ip route del default dev {ifname} 2>/dev/null || true")
            for route in entry.get("routes", []):
                if route["to"] in ("0.0.0.0/0", "default"):
                    continue
                lines.append(f"    post-up ip route add {route['to']} via {route['via']} dev {ifname}")
                lines.append(f"    pre-down ip route del {route['to']} via {route['via']} dev {ifname} || true")
        else:
            lines.append(f"iface {ifname} inet static")
            for address in entry.get("addresses", []):
                lines.append(f"    address {address}")
            default = next((route["via"] for route in entry.get("routes", [])
                            if route["to"] in ("0.0.0.0/0", "default")), None)
            if default:
                lines.append(f"    gateway {default}")
            for route in entry.get("routes", []):
                if route["to"] in ("0.0.0.0/0", "default"):
                    continue
                lines.append(f"    post-up ip route add {route['to']} via {route['via']} dev {ifname}")
                lines.append(f"    pre-down ip route del {route['to']} via {route['via']} dev {ifname} || true")
        lines.append("")
    Path("/etc/network/interfaces").write_text("\n".join(lines), encoding="utf-8")
    if control.get("dhcp4"):
        _install_control_default_guard(names["mhb_control"])
    subprocess.run(["systemctl", "restart", "networking"], check=True)
    return {"applied": True}


def _install_control_default_guard(ifname: str):
    """Keep a DHCP control interface from re-installing a default route after a port reattach.

    ifupdown's post-up removal runs at configuration time, but the DHCP client can re-add the
    default when the detached control port comes back. A small timer removes it on every change.
    """
    Path("/usr/local/sbin/mhbench-control-default-guard").write_text(
        "#!/bin/bash\n"
        "set -u\n"
        f"IFACE={ifname!r}\n"
        "while ip -4 route show default dev \"$IFACE\" 2>/dev/null | grep -q .; do\n"
        "  ip -4 route del default dev \"$IFACE\" 2>/dev/null || break\n"
        "done\n",
        encoding="utf-8",
    )
    Path("/usr/local/sbin/mhbench-control-default-guard").chmod(0o755)
    Path("/etc/systemd/system/mhbench-control-default-guard.service").write_text(
        "[Unit]\nDescription=Remove DHCP default from the MHBench control interface\n"
        "After=network.target\n[Service]\nType=oneshot\n"
        "ExecStart=/usr/local/sbin/mhbench-control-default-guard\n",
        encoding="utf-8",
    )
    Path("/etc/systemd/system/mhbench-control-default-guard.timer").write_text(
        "[Unit]\nDescription=Periodically remove the MHBench control default\n"
        "[Timer]\nOnBootSec=3\nOnUnitActiveSec=2\n"
        "[Install]\nWantedBy=timers.target\n",
        encoding="utf-8",
    )
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "mhbench-control-default-guard.timer"], check=True)


def verify(payload):
    network = payload.get("network", payload)
    is_router = bool(payload.get("router", False))
    names = devices(network)
    addresses = ip_json("-4", "address", "show")
    routes = ip_json("-4", "route", "show")
    for route in routes:
        destination = "0.0.0.0/0" if route.get("dst") in (None, "default") else route["dst"]
        route["dst"] = str(ipaddress.IPv4Network(destination))
    expected_defaults = []
    for name, entry in network["network"]["ethernets"].items():
        actual = next(a for a in addresses if a["ifname"] == names[name])
        present = {a["local"] + "/" + str(a["prefixlen"])
                   for a in actual["addr_info"] if a["family"] == "inet"}
        if entry.get("dhcp4"):
            if not present:
                raise ValueError("Guest control DHCP address is missing on " + name)
        elif not set(entry.get("addresses", [])) <= present:
            raise ValueError("Guest data/control addresses do not match " + name)
        for route in entry.get("routes", []):
            if route["to"] == "0.0.0.0/0":
                expected_defaults.append(route)
            if not any(r["dst"] == str(ipaddress.IPv4Network(route["to"]))
                       and r.get("gateway") == route["via"] and r.get("dev") == names[name] for r in routes):
                raise ValueError("Missing guest route " + str(route))
    defaults = [r for r in routes if r["dst"] == "0.0.0.0/0"]
    expected_count = 0 if is_router else 1
    if len(expected_defaults) != expected_count or len(defaults) != expected_count:
        raise ValueError(f"Guest must have exactly {expected_count} default route(s)")
    return {"verified": True}


if __name__ == "__main__":
    payload = json.load(sys.stdin)
    if sys.argv[1] == "prepare":
        result = prepare(payload)
    elif sys.argv[1] == "apply-ifupdown":
        result = apply_ifupdown(payload)
    elif sys.argv[1] == "verify":
        result = verify(payload)
    else:
        raise SystemExit("Expected prepare, apply-ifupdown, or verify")
    json.dump(result, sys.stdout)
    print()
