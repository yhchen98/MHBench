from __future__ import annotations

import hashlib
import json
import logging
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import ansible_runner

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.deployment.backends.base import CloudBackend
from src.deployment.online_registry_service import OnlineRegistryService
from src.deployment.routing import guest_configurations
from src.playbooks.playbook_registry_service import PlaybookRegistryService

logger = logging.getLogger(__name__)

_MHBENCH_DIR = Path(__file__).resolve().parent.parent.parent
_CONSOLE_TAIL_LINES = 100
_PLAYBOOK_RETRIES = 5
_PLAYBOOK_RETRY_DELAY = 20
_PARALLEL_HOSTS = 8  # max hosts configured concurrently in run_parallel (bounds the single bastion's sshd load)
_COLLECT_RETRIES = 5       # in-place collect retries (VMs still up); only re-fetches hosts that came back empty
_COLLECT_RETRY_DELAY = 30  # backoff between collect retries — lets a saturated bastion recover


class AnsibleRunner:

    def __init__(
        self,
        config: Config,
        online_registry: OnlineRegistryService,
        playbook_registry: PlaybookRegistryService,
        backend: CloudBackend | None = None,
        project_name: str | None = None,
    ) -> None:
        self._config = config
        self._ssh_key_path = config.ssh_key_path
        self._online = online_registry
        self._playbook_registry = playbook_registry
        self._backend = backend
        self._project_name = project_name
        c2c = getattr(config, "c2c", None)
        self._c2c_vars: dict = {"caldera_ip": c2c.ip, "caldera_port": c2c.port} if c2c else {}
        self._attacker_play = getattr(config, "attacker_play", None)  # overrides the kali host's runtime play (per-attacker)
        self._attacker_only = getattr(config, "attacker_only", False)  # run ONLY the kali attacker host's play (post-config setup step)
        self._verbosity = getattr(config, "ansible_verbosity", 0)
        # The Arena manager may be started without the MHBench virtualenv on PATH. ansible-runner
        # resolves ansible-playbook from PATH, so make the project interpreter explicit.
        venv_bin = str(_MHBENCH_DIR / ".venv" / "bin")
        os.environ["PATH"] = venv_bin + os.pathsep + os.environ.get("PATH", "")

    def _reset_stale_masters(self, ssh_ctl_dir: str) -> None:
        """Unlink every ControlPath socket under ssh_ctl_dir so the next attempt opens fresh
        connections instead of reusing one that just failed. ControlPersist keeps a master alive
        across an entire playbook run (intentionally — see _run_playbook's own comment on why),
        but that means a master that went bad mid-run (e.g. the far end silently dying, or an
        upstream hop like a bastion glitching) stays in place across the SAME run's retries too:
        ControlMaster=auto happily hands out a channel on an already-open master without
        re-verifying it end-to-end, so a task can appear to "succeed" over a half-dead mux with
        truncated/garbled output instead of a clean connection error - which is exactly the
        failure shape collect_host_logs hit (finds registering as bare dicts missing 'files',
        with no ssh-level error at all). Only called between retries, never before the first
        attempt of a call, so the intra-run connection reuse this dir exists for is undisturbed
        when nothing has actually gone wrong yet."""
        try:
            for sock in Path(ssh_ctl_dir).iterdir():
                try:
                    sock.unlink()
                except OSError:
                    pass
        except FileNotFoundError:
            pass

    def _ssh_ctl_dir(self) -> str:
        """Per-experiment SSH ControlPath directory, namespaced by project (see the callers'
        own comments on why: isolating concurrent runs that reuse the same internal IPs).
        Hashed rather than the raw project name: AF_UNIX socket paths cap out at 108 bytes,
        and OpenSSH appends its own ~17-byte suffix (". " + 16 random chars) when atomically
        creating the control socket on top of the 40-char %C hash / "bastion-<ip>" filename -
        so a project name longer than about two dozen characters can silently break every SSH
        connection for that experiment ("ControlPath too long" / "too long for Unix domain
        socket"). A short fixed-length hash keeps this well under the limit regardless of how
        the experiment is named."""
        if not self._project_name:
            return "/tmp/mhbench-ssh/default"
        digest = hashlib.sha1(self._project_name.encode()).hexdigest()[:10]
        return f"/tmp/mhbench-ssh/{digest}"

    def _log_console(self, host_name: str) -> None:
        if not self._backend:
            return
        full_name = f"{self._project_name}-{host_name}" if self._project_name else host_name
        console_text = self._backend.get_console_output(full_name, length=_CONSOLE_TAIL_LINES)
        if console_text is None:
            return
        logger.info("Console log for %s (last %d lines):\n%s", full_name, _CONSOLE_TAIL_LINES, console_text)

    def _run_playbook(self, pb_name: str, inventory: dict, extravars: dict, tmp: str, project_dir: str,
                      log_path: str | None = None) -> None:
        pb_path = self._playbook_registry.get_path(pb_name)
        # Per-experiment ControlPath dir. %C hashes only (host,port,user) — NOT the bastion — so concurrent
        # experiments (identical internal IPs 192.168.200.x reached via different bastions) would otherwise
        # share one mux socket and configure each other's hosts. Namespacing by project isolates runs while
        # keeping the intra-run per-host connection reuse.
        ssh_ctl_dir = self._ssh_ctl_dir()
        Path(ssh_ctl_dir).mkdir(parents=True, exist_ok=True)
        logf = open(log_path, "a") if log_path else None  # route this play's ansible trace to a per-host file, off shared stdout
        def _stream(event: dict) -> bool:
            line = event.get("stdout", "")
            if line:
                logf.write(line) if logf else print(line, end="", flush=True)
            return True

        try:
            for attempt in range(1, _PLAYBOOK_RETRIES + 1):
                # Ansible Runner installs process handlers on the main thread; do not leak them.
                handlers = ({s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
                            if threading.current_thread() is threading.main_thread() else {})
                try:
                    result = ansible_runner.run(
                        private_data_dir=tmp,
                        project_dir=project_dir,
                        playbook=pb_path.name,
                        inventory=inventory,
                        extravars=extravars,
                        event_handler=_stream,
                        quiet=True,
                        verbosity=self._verbosity,
                        envvars={
                            # One reused SSH connection per host across all tasks (ControlPersist) instead of a fresh
                            # handshake per task — a 26-host configure otherwise opens thousands of connections through
                            # the single bastion and overwhelms its sshd (the kex/timeout/connection-closed storms).
                            "ANSIBLE_SSH_ARGS": (
                                "-o ControlMaster=auto "
                                f"-o ControlPath={ssh_ctl_dir}/%C "
                                "-o ControlPersist=60s "
                                "-o StrictHostKeyChecking=no "
                                "-o UserKnownHostsFile=/dev/null "
                                "-o ServerAliveInterval=30 "
                                "-o ServerAliveCountMax=10"
                            ),
                            "ANSIBLE_PIPELINING": "True",
                            "ANSIBLE_SSH_RETRIES": "3",
                        }
                    )
                finally:
                    for signum, handler in handlers.items():
                        signal.signal(signum, handler)
                if result.status == "canceled":
                    raise KeyboardInterrupt(f"Playbook '{pb_name}' canceled")
                if result.status == "successful":
                    return
                stderr = result.stderr.read() if result.stderr else ""
                if attempt < _PLAYBOOK_RETRIES:
                    logger.warning(
                        "Playbook '%s' failed (attempt %d/%d, status: %s) — retrying in %ds.\n%s",
                        pb_name, attempt, _PLAYBOOK_RETRIES, result.status, _PLAYBOOK_RETRY_DELAY, stderr,
                    )
                    self._reset_stale_masters(ssh_ctl_dir)
                    time.sleep(_PLAYBOOK_RETRY_DELAY)
                else:
                    # Exhausted our own retries — still reset before surfacing the failure, so a
                    # caller-level retry (e.g. collect()'s own outer loop) doesn't inherit this
                    # attempt's dead/half-dead master either.
                    self._reset_stale_masters(ssh_ctl_dir)
                    raise RuntimeError(
                        f"Playbook '{pb_name}' failed after {_PLAYBOOK_RETRIES} attempts (status: {result.status}).\n{stderr}"
                    )
        finally:
            if logf:
                logf.close()

    def _configure_routing(self, topology: NetworkTopology, inventory_hosts: dict) -> None:
        if topology.routing is None or self._attacker_only:
            return
        if self._backend is None or self._backend.name != "openstack":
            raise NotImplementedError("BGP routing configuration requires the OpenStack backend.")
        actual = self._backend.routing_interfaces(topology)
        guests = guest_configurations(topology, self._config, actual)
        project_dir = str((_MHBENCH_DIR / self._playbook_registry.get_path("configure_routing")).resolve().parent)
        inventory = {"all": {"hosts": inventory_hosts}}
        with tempfile.TemporaryDirectory() as tmp:
            for name, args in guests.items():
                self._run_playbook("configure_routing", inventory, {"host": name, **args}, tmp, project_dir)
            for router in topology.routing.routers:
                self._run_playbook("verify_bgp", inventory, {"host": router.host, **guests[router.host]},
                                   tmp, project_dir)

    def run(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        hosts = topology.get_all_hosts()
        for host in hosts:
            if host.ip_address is None:
                raise RuntimeError(f"Host '{host.name}' has no ip_address; cannot build ansible inventory.")

        # bastion-hop mux: all hosts share ONE ssh connection to the bastion (separate -W channels) so the
        # parallel-configure burst can't trip its default MaxStartups (10) and drop the attacker. Per-experiment
        # socket keyed on the bastion IP + namespaced per-project (same dir as the outer per-target mux) so
        # concurrent runs — same internal IPs, different bastions — never share a socket.
        ctl = self._ssh_ctl_dir()
        proxy = self._bastion_proxy(topology, mgmt_floating_ip, ctl)
        inventory_hosts = {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": self._ssh_key_path,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no '
                    f'-o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 '
                    f'-o ServerAliveCountMax=10 '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in hosts
        }

        self._configure_routing(topology, inventory_hosts)

        queue: list[tuple[str | None, str, dict]] = []
        for host in hosts:
            if self._attacker_only and not self._is_kali(host.vm_type):
                continue
            runtime_pbs = self._online.get_runtime_playbooks(host.vm_type)
            if self._attacker_play and self._is_kali(host.vm_type):
                runtime_pbs = [self._attacker_play]
            if runtime_pbs:
                queue.append((host.name, "check_if_host_up", {
                    "manage_ip": mgmt_floating_ip,
                    "ssh_key_path": self._ssh_key_path,
                }))
                for pb_name in runtime_pbs:
                    queue.append((host.name, pb_name, {"user": "root", **self._c2c_vars}))
        if not self._attacker_only:
            for pb in topology.playbooks:
                queue.append((None, pb.name, pb.args))

        if not queue:
            logger.info("No playbooks to run.")
            return

        first_pb = self._playbook_registry.get_path(queue[0][1])
        project_dir = str((_MHBENCH_DIR / first_pb).resolve().parent)

        with tempfile.TemporaryDirectory() as tmp:
            for host_name, pb_name, args in queue:
                # mhb_project last so a topology arg can never shadow it: add_data.yml
                # hashes it into each planted file's flag, which is what makes one
                # host's copy of data.json distinguishable from another's.
                extravars = (
                    {"host": host_name, **args, "mhb_project": self._project_name}
                    if host_name
                    else {**args, "mhb_project": self._project_name}
                )
                if host_name:
                    logger.info("Running playbook '%s' on '%s'", pb_name, host_name)
                else:
                    logger.info("Running topology playbook '%s'", pb_name)
                try:
                    self._run_playbook(
                        pb_name,
                        {"all": {"hosts": inventory_hosts}},
                        extravars,
                        tmp,
                        project_dir,
                    )
                except RuntimeError:
                    if host_name:
                        self._log_console(host_name)
                    raise

    def _setup_telemetry_relay(self, mgmt_floating_ip: str, topology: NetworkTopology) -> None:
        """Ship + start the transparent fan-out relay on the management host (the fixed bake target).

        Runs setup_telemetry_relay.yml against the bastion directly on its floating IP. Best-effort:
        a failure is logged and swallowed so it never fails an otherwise-good configure.

        The relay is set up with its DEFAULT downstream (the baked ES) only. It does NOT assume the
        defender box: the relay is forwarded to a box ES only when the DEFENDER requests it (via
        `request-ingress <port>:telemetry`), because that dest is only useful if the defender actually
        runs ES there. Overridable via MHBENCH_RELAY_ES_ADDRESS.
        """
        plays_dir = str(_MHBENCH_DIR / "src" / "playbooks" / "plays")
        extravars: dict = {}
        es_override = os.environ.get("MHBENCH_RELAY_ES_ADDRESS")
        if es_override:
            extravars["relay_es_address"] = es_override
        inventory = {"all": {"hosts": {"bastion": {
            "ansible_host": mgmt_floating_ip,
            "ansible_user": "root",
            "ansible_ssh_private_key_file": self._ssh_key_path,
            "ansible_ssh_common_args": "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        }}}}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                result = ansible_runner.run(
                    private_data_dir=tmp, project_dir=plays_dir,
                    playbook="setup_telemetry_relay.yml", inventory=inventory,
                    extravars=extravars, quiet=True, verbosity=self._verbosity,
                )
            if result.status == "successful":
                logger.info("Telemetry relay up on management host %s:9200", mgmt_floating_ip)
            else:
                logger.warning("Telemetry relay setup did not succeed (status=%s); continuing.",
                               result.status)
        except Exception as e:  # noqa: BLE001 — telemetry relay is best-effort; never fail configure on it
            logger.warning("Telemetry relay setup errored (%s); continuing.", e)

    # --- per-system scoped key injection (no god-key handed to an agent) --------------------------------
    # The environment ISSUES two scoped keys on top of the broad management key (which stays for
    # provisioning and never enters a spec): attacker_key opens the foothold only, defender_key opens the
    # defender box + victims. Injected here at configure so every deploy path gets them. Classified by
    # subnet: attacker_subnet -> foothold (prefer a Kali host over a router in the same subnet),
    # defender_subnet -> box, everything else internal -> victim.
    _ATTACKER_SUBNET = "attacker_subnet"
    _DEFENDER_SUBNET = "defender_subnet"

    @staticmethod
    def _is_kali(vm_type: str) -> bool:
        """True for any Kali attacker image profile (the shared one or a dedicated one)."""
        return vm_type.startswith("kali")

    _RELAY_KEY_NAMES = ("relay_admin", "guest_proxy", "c2_proxy", "mh_hop", "guest_admin")

    def _issue_relay_keys(self) -> dict[str, Path]:
        keydir = _MHBENCH_DIR / "keys"
        keydir.mkdir(parents=True, exist_ok=True)
        out: dict[str, Path] = {}
        for name in self._RELAY_KEY_NAMES:
            p = keydir / name
            if not p.exists():
                subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(p), "-N", "", "-q",
                                "-C", f"mhbench-{name}"], check=True)
                p.chmod(0o600)
            out[name] = p
        return out

    def _relay_key(self, name: str) -> Path:
        return _MHBENCH_DIR / "keys" / name

    def _run_bootstrap_ssh(self, topology: NetworkTopology, mgmt_ip: str, host_ip: str,
                           command: str, *, input_text: str | None = None, direct: bool = False) -> subprocess.CompletedProcess:
        argv = ["ssh", *self._ssh_base()]
        if not direct:
            proxy = self._bastion_proxy(topology, mgmt_ip, self._ssh_ctl_dir())
            argv += ["-o", f"ProxyCommand={proxy}"]
        argv += [f"root@{host_ip}", command]
        return subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=120)

    def _install_relay_access(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        """Install relay admin/proxy accounts and keys, leaving the cloud key for the setup window."""
        keys = self._issue_relay_keys()
        infrastructure = [h for h in topology.get_all_hosts() if h.infrastructure and h.ip_address]
        if not infrastructure:
            return
        c2_host = infrastructure[0]
        c2_ip = str(c2_host.ip_address)
        # Root keys: relay admin on c2; guest admin on every experimental guest.
        for host in topology.get_all_hosts():
            if host.infrastructure or not host.ip_address:
                continue
            if not self._inject_pubkey(Path(str(keys["guest_admin"]) + ".pub").read_text().strip(),
                                       str(host.ip_address), mgmt_floating_ip, topology):
                raise RuntimeError(f"Guest-admin key injection failed for {host.name}.")
        if not self._inject_pubkey(Path(str(keys["relay_admin"]) + ".pub").read_text().strip(),
                                   c2_ip, mgmt_floating_ip, topology):
            raise RuntimeError("Relay-admin key injection failed.")
        proxy_script = (_MHBENCH_DIR / "src/playbooks/plays/aux_files/ssh_proxy.py").read_text()
        guest_allow = "\n".join(
            f"{h.ip_address} 22" for h in topology.get_all_hosts()
            if not h.infrastructure and h.ip_address) + "\n"
        c2_allow = "127.0.0.1 8888\n"
        mgmt_allow = f"{c2_ip} 22\n"

        def pub(name: str) -> str:
            return Path(str(keys[name]) + ".pub").read_text().strip()

        def installs(host: str, accounts: list[tuple[str, str, str]]) -> None:
            for user, key_name, allow_path in accounts:
                pubkey = pub(key_name)
                cmd = (
                    f"id -u {user} >/dev/null 2>&1 || useradd -m -s /bin/bash {user}; "
                    f"install -d -m700 -o {user} -g {user} /home/{user}/.ssh; "
                    f"printf '%s\n' {shlex.quote(pubkey)} > /home/{user}/.ssh/authorized_keys; "
                    f"chown -R {user}:{user} /home/{user}/.ssh; chmod 600 /home/{user}/.ssh/authorized_keys"
                )
                r = self._run_bootstrap_ssh(topology, mgmt_floating_ip, host, cmd,
                                            direct=host == mgmt_floating_ip)
                if r.returncode != 0:
                    raise RuntimeError(f"Relay account {user} on {host} failed: {r.stderr.strip()}")
            # Shared exact proxy script.
            r = self._run_bootstrap_ssh(
                topology, mgmt_floating_ip, host,
                "install -d -m755 /usr/local/sbin /etc/mhbench && cat > /usr/local/sbin/mhbench-ssh-proxy && chmod 0755 /usr/local/sbin/mhbench-ssh-proxy",
                input_text=proxy_script, direct=host == mgmt_floating_ip)
            if r.returncode != 0:
                raise RuntimeError(f"Relay proxy script on {host} failed: {r.stderr.strip()}")

        # c2 proxy accounts and exact allow files.
        installs(c2_ip, [
            ("relay-guest-proxy", "guest_proxy", "/etc/mhbench/guest-proxy.allow"),
            ("relay-c2-proxy", "c2_proxy", "/etc/mhbench/c2-proxy.allow"),
        ])
        for path, content in (("/etc/mhbench/guest-proxy.allow", guest_allow),
                              ("/etc/mhbench/c2-proxy.allow", c2_allow)):
            r = self._run_bootstrap_ssh(topology, mgmt_floating_ip, c2_ip,
                                        f"printf '%s' {shlex.quote(content)} > {path} && chmod 0644 {path}")
            if r.returncode != 0:
                raise RuntimeError(f"Relay allow-list {path} failed: {r.stderr.strip()}")
        c2_sshd = """# BEGIN mhbench-relay-proxy
Match User relay-guest-proxy
  ForceCommand /usr/local/sbin/mhbench-ssh-proxy /etc/mhbench/guest-proxy.allow
  AllowTcpForwarding no
  PermitTTY no
Match User relay-c2-proxy
  ForceCommand /usr/local/sbin/mhbench-ssh-proxy /etc/mhbench/c2-proxy.allow
  AllowTcpForwarding no
  PermitTTY no
Match all
# END mhbench-relay-proxy
"""
        r = self._run_bootstrap_ssh(
            topology, mgmt_floating_ip, c2_ip,
            "cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.mhbench.bak 2>/dev/null || true; "
            "sed -i '/# BEGIN mhbench-relay-proxy/,/# END mhbench-relay-proxy/d' /etc/ssh/sshd_config; "
            "cat >> /etc/ssh/sshd_config && sshd -t && systemctl reload ssh",
            input_text=c2_sshd)
        if r.returncode != 0:
            raise RuntimeError(f"Relay sshd proxy config failed: {r.stderr.strip()}")
        # management outer jump.
        installs(mgmt_floating_ip, [("mh-hop", "mh_hop", "/etc/mhbench/mh-hop.allow")])
        r = self._run_bootstrap_ssh(
            topology, mgmt_floating_ip, mgmt_floating_ip,
            "printf '%s' " + shlex.quote(mgmt_allow) + " > /etc/mhbench/mh-hop.allow && chmod 0644 /etc/mhbench/mh-hop.allow",
            direct=True)
        if r.returncode != 0:
            raise RuntimeError(f"Management hop allow-list failed: {r.stderr.strip()}")
        mgmt_sshd = """# BEGIN mhbench-relay-proxy
Match User mh-hop
  ForceCommand /usr/local/sbin/mhbench-ssh-proxy /etc/mhbench/mh-hop.allow
  AllowTcpForwarding no
  PermitTTY no
Match all
# END mhbench-relay-proxy
"""
        r = self._run_bootstrap_ssh(
            topology, mgmt_floating_ip, mgmt_floating_ip,
            "cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.mhbench.bak 2>/dev/null || true; "
            "sed -i '/# BEGIN mhbench-relay-proxy/,/# END mhbench-relay-proxy/d' /etc/ssh/sshd_config; "
            "cat >> /etc/ssh/sshd_config && sshd -t && systemctl reload ssh",
            input_text=mgmt_sshd, direct=True)
        if r.returncode != 0:
            raise RuntimeError(f"Management sshd proxy config failed: {r.stderr.strip()}")
        logger.info("Relay forced-proxy access installed on c2 and management host")

    def _issue_scoped_keys(self):
        keydir = _MHBENCH_DIR / "keys"
        keydir.mkdir(parents=True, exist_ok=True)
        out = []
        for name in ("attacker_key", "defender_key"):
            p = keydir / name
            if not p.exists():
                subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(p), "-N", "", "-q",
                                "-C", f"arena-{name}"], check=True)
                p.chmod(0o600)
            out.append(p)
        return out[0], out[1]

    def _ssh_base(self):
        return ["-i", str(self._ssh_key_path), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15"]

    def _bastion_proxy(self, topology: NetworkTopology, mgmt_floating_ip: str, ctl: str,
                       use_proxies: bool = False) -> str:
        """ProxyCommand from the harness to a guest: management outer jump, then c2 when the topology
        contains an infrastructure relay. The relay is the only experimental-guest management source
        after the control plane is isolated; the management host remains the outer jump only."""
        infrastructure = [h for h in topology.get_all_hosts()
                          if h.infrastructure and h.ip_address]
        if not infrastructure:
            return (
                f"ssh -W %h:%p -i {self._ssh_key_path} "
                f"-o BatchMode=yes -o PasswordAuthentication=no "
                f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"-o ControlMaster=auto -o ControlPath={ctl}/bastion-{mgmt_floating_ip} -o ControlPersist=300s "
                f"root@{mgmt_floating_ip}"
            )
        relay_ip = str(infrastructure[0].ip_address)
        guest_proxy_key = self._relay_key("guest_proxy")
        mh_hop_key = self._relay_key("mh_hop")
        if use_proxies:
            # The forced-proxy path is the isolation boundary. Do not fall back to root -W with the
            # cloud key: a missing proxy credential must fail the seal/collection, not silently
            # re-open a management path.
            if not guest_proxy_key.exists() or not mh_hop_key.exists():
                raise RuntimeError("Forced relay proxy credentials are missing for an isolated topology.")
            inner = (
                f"ssh -i {mh_hop_key} -o BatchMode=yes -o PasswordAuthentication=no "
                f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"mh-hop@{mgmt_floating_ip} {relay_ip} 22"
            )
            return (
                f"ssh -i {guest_proxy_key} -o BatchMode=yes -o PasswordAuthentication=no "
                f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"-o ProxyCommand='{inner}' "
                f"relay-guest-proxy@{relay_ip} %h %p"
            )
        # Nested ProxyCommand: outer SSH terminates on the relay and forwards to the guest; its
        # ProxyCommand reaches the relay through the management outer jump. This keeps the relay
        # as the guest-management source while the management host is only the outer hop.
        inner = (
            f"ssh -W {relay_ip}:22 -i {self._ssh_key_path} "
            f"-o BatchMode=yes -o PasswordAuthentication=no "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"root@{mgmt_floating_ip}"
        )
        return (
            f"ssh -W %h:%p -i {self._ssh_key_path} "
            f"-o BatchMode=yes -o PasswordAuthentication=no "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o ControlMaster=auto -o ControlPath={ctl}/bastion-{mgmt_floating_ip} -o ControlPersist=300s "
            f"-o ProxyCommand='{inner}' "
            f"root@{relay_ip}"
        )

    def _inject_pubkey(self, pubkey: str, host_ip: str, mgmt_ip: str,
                       topology: NetworkTopology | None = None) -> bool:
        """Append pubkey to root's authorized_keys on host_ip, reached via the bastion. Idempotent."""
        if topology is not None and any(h.infrastructure for h in topology.get_all_hosts()):
            proxy = self._bastion_proxy(topology, mgmt_ip, self._ssh_ctl_dir())
        else:
            proxy = "ssh -W %h:%p " + " ".join(self._ssh_base()) + f" root@{mgmt_ip}"
        remote = ("install -d -m700 ~/.ssh && touch ~/.ssh/authorized_keys && "
                  f"grep -qxF {pubkey!r} ~/.ssh/authorized_keys || echo {pubkey!r} >> ~/.ssh/authorized_keys")
        r = subprocess.run(["ssh", *self._ssh_base(), "-o", f"ProxyCommand={proxy}", f"root@{host_ip}", remote],
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0

    def _inject_bastion_jump(self, pubkey: str, targets: list, mgmt_ip: str) -> bool:
        """Forward-only entry on the bastion: this key may ONLY tunnel (-W) to `targets`, no shell/command."""
        if not targets:
            return True
        opts = ('command="/bin/false",restrict,port-forwarding,'
                + ",".join(f'permitopen="{t}"' for t in targets))
        entry = f"{opts} {pubkey}"
        keymat = pubkey.split()[1]
        remote = ("install -d -m700 ~/.ssh && touch ~/.ssh/authorized_keys && "
                  f"{{ grep -vF {keymat!r} ~/.ssh/authorized_keys || true; }} > ~/.ssh/ak.tmp && "
                  "mv ~/.ssh/ak.tmp ~/.ssh/authorized_keys && "
                  f"printf '%s\\n' {entry!r} >> ~/.ssh/authorized_keys")
        r = subprocess.run(["ssh", *self._ssh_base(), f"root@{mgmt_ip}", remote],
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0

    def _inject_scoped_keys(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        isolated = bool(topology.routing is not None and topology.routing.isolate_management)
        try:
            ak, dk = self._issue_scoped_keys()
            ak_pub = Path(str(ak) + ".pub").read_text().strip()
            dk_pub = Path(str(dk) + ".pub").read_text().strip()
        except Exception as e:  # noqa: BLE001
            if isolated:
                raise RuntimeError(f"Scoped-key generation failed for an isolated topology: {e}") from e
            logger.warning("Scoped-key generation failed (%s); skipping injection.", e)
            return
        attacker_hosts: list[tuple[bool, str]] = []
        box_ip = None
        victim_ips: list[str] = []
        for sub in topology.get_all_subnets():
            for h in sub.hosts:
                if not h.ip_address:
                    continue
                ip = str(h.ip_address)
                if sub.name == self._ATTACKER_SUBNET or self._is_kali(h.vm_type):
                    attacker_hosts.append((self._is_kali(h.vm_type), ip))
                elif sub.name == self._DEFENDER_SUBNET:
                    box_ip = ip
                else:
                    victim_ips.append(ip)
        foothold_ip = next((ip for is_kali, ip in attacker_hosts if is_kali), None)
        if foothold_ip is None and attacker_hosts:
            foothold_ip = attacker_hosts[0][1]
        try:
            if foothold_ip:
                ok = self._inject_pubkey(ak_pub, foothold_ip, mgmt_floating_ip, topology)
                if not ok and isolated:
                    raise RuntimeError(f"Attacker key injection failed on foothold {foothold_ip}.")
                logger.info("Scoped key: attacker_key -> foothold %s: %s", foothold_ip, "ok" if ok else "FAILED")
                if not self._inject_bastion_jump(ak_pub, [f"{foothold_ip}:22"], mgmt_floating_ip) and isolated:
                    raise RuntimeError("Attacker-key management jump injection failed.")
            dtargets = ([box_ip] if box_ip else []) + victim_ips
            for ip in dtargets:
                ok = self._inject_pubkey(dk_pub, ip, mgmt_floating_ip, topology)
                if not ok and isolated:
                    raise RuntimeError(f"Defender key injection failed on {ip}.")
                logger.info("Scoped key: defender_key -> %s: %s", ip, "ok" if ok else "FAILED")
            if dtargets and not self._inject_bastion_jump(dk_pub, [f"{ip}:22" for ip in dtargets], mgmt_floating_ip) and isolated:
                raise RuntimeError("Defender-key management jump injection failed.")
            self._install_relay_access(topology, mgmt_floating_ip)
        except Exception as e:  # noqa: BLE001
            if isolated:
                raise
            logger.warning("Scoped-key injection errored (%s); continuing.", e)

    def run_parallel(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        # Same result as run(), but the per-host online plays (no cross-host deps) run concurrently in a
        # bounded thread pool, then the topology plays (setup_ssh_keys/add_data — cross-host) run serially
        # after. Capped at _PARALLEL_HOSTS so the single bastion's sshd isn't swamped (each host reuses one
        # mux connection). Inventory + chain setup mirrors run(); kept separate so run() stays the safe serial path.
        hosts = topology.get_all_hosts()
        for host in hosts:
            if host.ip_address is None:
                raise RuntimeError(f"Host '{host.name}' has no ip_address; cannot build ansible inventory.")

        # bastion-hop mux: all hosts share ONE ssh connection to the bastion (separate -W channels) so the
        # parallel-configure burst can't trip its default MaxStartups (10) and drop the attacker. Per-experiment
        # socket keyed on the bastion IP + namespaced per-project (same dir as the outer per-target mux) so
        # concurrent runs — same internal IPs, different bastions — never share a socket.
        ctl = self._ssh_ctl_dir()
        proxy = self._bastion_proxy(topology, mgmt_floating_ip, ctl)
        inventory_hosts = {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": self._ssh_key_path,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no '
                    f'-o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 '
                    f'-o ServerAliveCountMax=10 '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in hosts
        }

        self._configure_routing(topology, inventory_hosts)

        # Per-host chain = check_if_host_up then that host's online plays, ordered (a host's own plays are
        # sequential; only across hosts is it parallel). Topology plays are cross-host and run after, serially.
        per_host: dict[str, list[tuple[str, dict]]] = {}
        for host in hosts:
            if self._attacker_only and not self._is_kali(host.vm_type):
                continue
            runtime_pbs = self._online.get_runtime_playbooks(host.vm_type)
            if self._attacker_play and self._is_kali(host.vm_type):
                runtime_pbs = [self._attacker_play]
            if runtime_pbs:
                per_host[host.name] = (
                    [("check_if_host_up", {"manage_ip": mgmt_floating_ip, "ssh_key_path": self._ssh_key_path})]
                    + [(pb_name, {"user": "root", **self._c2c_vars}) for pb_name in runtime_pbs]
                )
        topo = [] if self._attacker_only else [(pb.name, pb.args) for pb in topology.playbooks]

        if not per_host and not topo:
            logger.info("No playbooks to run.")
            return

        first_name = next(iter(per_host.values()))[0][0] if per_host else topo[0][0]
        project_dir = str((_MHBENCH_DIR / self._playbook_registry.get_path(first_name)).resolve().parent)
        logger.info("Parallel configure: %d hosts (max %d concurrent) + %d topology plays",
                    len(per_host), _PARALLEL_HOSTS, len(topo))

        ansible_log_dir = os.environ.get("MHBENCH_ANSIBLE_LOG_DIR")  # harness points per-host ansible logs here; None -> stdout
        if ansible_log_dir:
            Path(ansible_log_dir).mkdir(parents=True, exist_ok=True)

        # Pre-establish the ONE bastion ControlMaster BEFORE fanning out, so the parallel plays REUSE it instead of
        # racing to create it. Without this, ControlMaster=auto + N concurrent procs race: the losers hit "ControlSocket
        # already exists, disabling multiplexing" -> a non-mux fallback that dies as "Connection closed by UNKNOWN port
        # 65535" -> host UNREACHABLE -> setup_ssh_keys fails (verified by reproduction). An ad-hoc connect to the bastion
        # opens the master at the same ControlPath the ProxyCommand targets. Best-effort: on failure the plays fall back
        # to the old on-demand behavior, so this can only help.
        Path(ctl).mkdir(parents=True, exist_ok=True)
        # Raise the bastion's MaxStartups (stock 10:30:100 throttles the parallel plays' connection burst -> the
        # setup_ssh_keys "port 65535" drops) + reload sshd, before the master opens below.
        with tempfile.TemporaryDirectory() as ms_tmp:
            ansible_runner.run(
                private_data_dir=ms_tmp, host_pattern="bastion", module="raw",
                module_args=(
                    "sed -i '/^[[:space:]]*MaxStartups/d' /etc/ssh/sshd_config && "
                    "printf 'MaxStartups 200:30:400\\n' >> /etc/ssh/sshd_config && "
                    "(systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload)"
                ),
                quiet=True, verbosity=self._verbosity,
                inventory={"all": {"hosts": {"bastion": {
                    "ansible_host": mgmt_floating_ip, "ansible_user": "root",
                    "ansible_ssh_private_key_file": self._ssh_key_path,
                    "ansible_ssh_common_args": "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
                }}}},
            )
        with tempfile.TemporaryDirectory() as warm_tmp:
            warm = ansible_runner.run(
                private_data_dir=warm_tmp, host_pattern="bastion", module="raw", module_args="true", quiet=True,
                verbosity=self._verbosity,
                inventory={"all": {"hosts": {"bastion": {
                    "ansible_host": mgmt_floating_ip, "ansible_user": "root",
                    "ansible_ssh_private_key_file": self._ssh_key_path,
                    "ansible_ssh_common_args": (
                        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                        f"-o ControlMaster=auto -o ControlPath={ctl}/bastion-{mgmt_floating_ip} -o ControlPersist=300s"
                    ),
                }}}},
            )
        if warm.status == "successful":
            logger.info("Bastion ControlMaster pre-warmed at %s", mgmt_floating_ip)
        else:
            logger.warning("Bastion ControlMaster pre-warm did not succeed (status=%s); falling back to on-demand.",
                           warm.status)

        # Stand up the transparent telemetry fan-out relay on the mgmt host — the constant bake target
        # sensors ship to. Best-effort: on existing images sensors still target the ES directly, so a
        # relay failure must not break configure (it only matters once sensors bake to the relay).
        self._setup_telemetry_relay(mgmt_floating_ip, topology)

        def _run_host_chain(host_name: str, chain: list[tuple[str, dict]]) -> None:
            log_path = f"{ansible_log_dir}/{host_name}.log" if ansible_log_dir else None
            with tempfile.TemporaryDirectory() as tmp:  # own private_data_dir per thread — a shared one clobbers
                for pb_name, args in chain:
                    logger.info("Running playbook '%s' on '%s'", pb_name, host_name)
                    self._run_playbook(pb_name, {"all": {"hosts": inventory_hosts}},
                                       {"host": host_name, **args,
                                        "mhb_project": self._project_name},
                                       tmp, project_dir, log_path)

        # Phase 1: per-host online plays, up to _PARALLEL_HOSTS at once. Wait for all, then surface failures.
        with ThreadPoolExecutor(max_workers=_PARALLEL_HOSTS) as pool:
            futures = {pool.submit(_run_host_chain, h, chain): h for h, chain in per_host.items()}
            errors = []
            for fut in as_completed(futures):
                exc = fut.exception()
                if exc:
                    errors.append((futures[fut], exc))
        if errors:
            for host_name, _ in errors:
                self._log_console(host_name)  # serial after the pool — avoids concurrent use of the backend client
            raise RuntimeError(
                f"Parallel configure failed on {len(errors)} host(s): "
                + "; ".join(f"{h}: {e}" for h, e in errors[:5])
            )

        # Phase 2: topology plays, run in the same bounded pool as phase 1 but guarded by a per-host lock so plays
        # touching the same host serialize — setup_ssh_keys all write the 'attacker' leader's ~/.ssh/config (must
        # serialize), while the many add_data plays hit disjoint hosts and run fully concurrent (the bulk of the win).
        if topo:
            # A play touches whatever hosts its args name: host + follower (legacy single pair) + followers[]
            # (a play may fan a leader out to many followers). Generic — no per-playbook knowledge here.
            def _touched(args: dict) -> set:
                return ({args.get("host"), args.get("follower")}
                        | {f["follower"] for f in args.get("followers", [])}) - {None}

            all_hosts: set[str] = set()
            for _, args in topo:
                all_hosts |= _touched(args)
            host_locks = {h: threading.Lock() for h in all_hosts}

            def _run_topo(idx: int, pb_name: str, args: dict) -> None:
                held = [host_locks[h] for h in sorted(_touched(args))]
                for lk in held:  # sorted acquire order across all plays ⇒ no deadlock
                    lk.acquire()
                try:
                    log_path = f"{ansible_log_dir}/_topology_{idx}_{pb_name}.log" if ansible_log_dir else None
                    with tempfile.TemporaryDirectory() as tmp:  # own private_data_dir per thread — a shared one clobbers
                        logger.info("Running topology playbook '%s'", pb_name)
                        # mhb_project last so a topology arg can never shadow it.
                        # add_data.yml hashes it into each planted file's flag, and
                        # add_data is a TOPOLOGY play, so this call site - not the
                        # serial one in run(), which configure never reaches - is
                        # the one that decides whether the flag carries the
                        # experiment name or an empty string.
                        self._run_playbook(pb_name, {"all": {"hosts": inventory_hosts}},
                                           {**args, "mhb_project": self._project_name},
                                           tmp, project_dir, log_path)
                finally:
                    for lk in reversed(held):
                        lk.release()

            with ThreadPoolExecutor(max_workers=_PARALLEL_HOSTS) as pool:
                futures = {pool.submit(_run_topo, i, pb, args): pb for i, (pb, args) in enumerate(topo)}
                errors = []
                for fut in as_completed(futures):
                    exc = fut.exception()
                    if exc:
                        errors.append((futures[fut], exc))
            if errors:
                raise RuntimeError(
                    f"Topology configure failed on {len(errors)} play(s): "
                    + "; ".join(f"{p}: {e}" for p, e in errors[:5])
                )

        # Inject the per-system scoped keys now that all hosts are up + configured: attacker_key on the
        # foothold, defender_key on the box + victims, plus forward-only bastion jump entries. This runs
        # on EVERY deploy path (a bare `cli.py deploy` AND the full harness both reach run_parallel), so
        # the scoped keys are authorized with no separate step. Best-effort: never fails configure.
        self._inject_scoped_keys(topology, mgmt_floating_ip)

    def collect(self, topology: NetworkTopology, mgmt_floating_ip: str, dest: str) -> None:
        # Post-experiment log exfil: rebuild the same bastion ProxyJump inventory as run() and
        # fetch every host's ground-truth logs to <dest>/<host>/. One play over all hosts (ansible
        # forks parallelize the fetch); ignore_unreachable in the play keeps a dead host from
        # sinking the rest. Runs before teardown deletes the VMs.
        logger.debug("Collecting host logs to %s via mgmt %s", dest, mgmt_floating_ip)
        # every host including the attacker (kali) — its image now bakes in the same telemetry
        hosts = [h for h in topology.get_all_hosts() if not h.infrastructure]
        for host in hosts:
            if host.ip_address is None:
                raise RuntimeError(f"Host '{host.name}' has no ip_address; cannot build ansible inventory.")
            # ansible.builtin.copy (the auditctl-dump task) does NOT create its destination
            # directory the way ansible.builtin.fetch does further down in the same play — on any
            # host where auditctl actually succeeds (rc == 0, so that task's `when` is true rather
            # than cleanly skipping) it fails outright with "Destination directory ... does not
            # exist", since nothing else in this call chain ever creates <dest>/<host>/.
            Path(dest, host.name).mkdir(parents=True, exist_ok=True)

        # bastion-hop mux: all hosts share ONE ssh connection to the bastion (separate -W channels) so the
        # parallel-configure burst can't trip its default MaxStartups (10) and drop the attacker. Per-experiment
        # socket keyed on the bastion IP + namespaced per-project (same dir as the outer per-target mux) so
        # concurrent runs — same internal IPs, different bastions — never share a socket.
        ctl = self._ssh_ctl_dir()
        proxy = self._bastion_proxy(topology, mgmt_floating_ip, ctl, use_proxies=True)
        guest_admin = self._relay_key("guest_admin")
        isolated = bool(topology.routing is not None and topology.routing.isolate_management)
        if isolated and not guest_admin.exists():
            raise RuntimeError("Guest-admin key is missing for an isolated topology.")
        target_key = str(guest_admin) if isolated else str(self._ssh_key_path)
        inventory_hosts = {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": target_key,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no '
                    f'-o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 '
                    f'-o ServerAliveCountMax=10 '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in hosts
        }

        pb_path = self._playbook_registry.get_path("collect_host_logs")
        project_dir = str((_MHBENCH_DIR / pb_path).resolve().parent)
        # Retry collection IN PLACE (VMs are still up), each pass re-fetching ONLY the hosts whose
        # <dest>/<host>/ is still empty — a host that already returned its logs is never re-copied, and a
        # transient bastion drop no longer costs the whole experiment a re-attack. Best-effort: after the
        # retries, proceed to teardown with a loud warning for any host that never returned logs, instead of
        # raising (which would escalate to a full-experiment retry).
        pending = dict(inventory_hosts)
        for attempt in range(1, _COLLECT_RETRIES + 1):
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    self._run_playbook("collect_host_logs", {"all": {"hosts": pending}}, {"dest": dest}, tmp, project_dir)
                except Exception as e:
                    logger.warning("collect_host_logs attempt %d/%d had failures — retrying incomplete hosts.\n%s",
                                   attempt, _COLLECT_RETRIES, e)
            pending = {n: h for n, h in inventory_hosts.items()
                       if not (Path(dest) / n).is_dir() or not any((Path(dest) / n).iterdir())}
            if not pending:
                return
            if attempt < _COLLECT_RETRIES:
                time.sleep(_COLLECT_RETRY_DELAY)
        logger.warning("collect_host_logs: %d host(s) returned no logs after %d attempts (proceeding best-effort): %s",
                       len(pending), _COLLECT_RETRIES, sorted(pending))

    def _forced_inventory(self, topology: NetworkTopology, mgmt_floating_ip: str,
                          include_infrastructure: bool = False) -> dict:
        ctl = self._ssh_ctl_dir()
        proxy = self._bastion_proxy(topology, mgmt_floating_ip, ctl, use_proxies=True)
        guest_admin = self._relay_key("guest_admin")
        if not guest_admin.exists():
            raise RuntimeError("Guest-admin key is missing for forced guest access.")
        target_key = str(guest_admin)
        return {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": target_key,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 -o ServerAliveCountMax=10 '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in topology.get_all_hosts()
            if host.ip_address and (include_infrastructure or not host.infrastructure)
        }

    def verify_restoration(self, topology: NetworkTopology, mgmt_floating_ip: str) -> dict:
        """Verify real post-restore DHCP/SSH/routing/Ansible reachability, not just port state."""
        if topology.routing is None or not topology.routing.isolate_management:
            return {}
        infrastructure = [h for h in topology.get_all_hosts() if h.infrastructure and h.ip_address]
        if not infrastructure:
            return {}
        guest_admin = self._relay_key("guest_admin")
        if not guest_admin.exists():
            raise RuntimeError("Guest-admin key is missing; cannot verify restoration.")
        proxy = self._bastion_proxy(topology, mgmt_floating_ip, self._ssh_ctl_dir(), use_proxies=True)
        routers = {r.host for r in topology.routing.routers}
        verified = []
        for host in topology.get_all_hosts():
            if host.infrastructure or not host.ip_address:
                continue
            prefix = topology.get_subnet_for_host(host).cidr.prefixlen
            expected_address = f"{host.ip_address}/{prefix}"
            command = "hostname; ip -4 -o addr show; ip -4 route show; ip -4 rule show"
            r = subprocess.run(
                ["ssh", "-i", str(guest_admin), "-o", "BatchMode=yes",
                 "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                 "-o", f"ProxyCommand={proxy}", f"root@{host.ip_address}", command],
                capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                raise RuntimeError(f"restoration: SSH failed for {host.name}: {r.stderr.strip()}")
            output = r.stdout
            if expected_address not in output:
                raise RuntimeError(f"restoration: {host.name} did not reacquire {expected_address}.")
            if "10.0.1." in output:
                raise RuntimeError(f"restoration: {host.name} still has a management reference.")
            defaults = [line for line in output.splitlines() if line.startswith("default ")]
            expected_defaults = 0 if host.name in routers else 1
            if len(defaults) != expected_defaults:
                raise RuntimeError(
                    f"restoration: {host.name} has {len(defaults)} default route(s), expected {expected_defaults}.")
            verified.append(host.name)
        ansible = _MHBENCH_DIR / ".venv" / "bin" / "ansible"
        if not ansible.exists():
            raise RuntimeError("ansible CLI is missing; cannot verify Ansible restoration.")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(self._forced_inventory(topology, mgmt_floating_ip), handle)
            inventory_path = handle.name
        try:
            r = subprocess.run(
                [str(ansible), "-i", inventory_path, "all", "-m", "ping", "-o", "-f", "8"],
                capture_output=True, text=True, timeout=180)
        finally:
            Path(inventory_path).unlink(missing_ok=True)
        if r.returncode != 0:
            raise RuntimeError(f"restoration: Ansible ping failed: {r.stderr.strip() or r.stdout[-500:]}")
        return {"verified": verified, "ansible": "ok"}

    def scrub(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        """Remove known management exposure from experimental guests before sealing."""
        inventory = self._forced_inventory(topology, mgmt_floating_ip)
        management_key = Path(str(self._ssh_key_path) + ".pub").read_text().strip()
        pb_path = self._playbook_registry.get_path("scrub_guest")
        project_dir = str((_MHBENCH_DIR / pb_path).resolve().parent)
        with tempfile.TemporaryDirectory() as tmp:
            self._run_playbook(
                "scrub_guest", {"all": {"hosts": inventory}},
                {"management_key_pub": management_key,
                 "management_ips": ["10.0.1.10", mgmt_floating_ip]},
                tmp, project_dir)

    def scrub_relay(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        """Remove the relay's cloud key and restrict SSH to the control interface after setup."""
        infrastructure = [h for h in topology.get_all_hosts() if h.infrastructure and h.ip_address]
        if not infrastructure:
            return
        c2_ip = str(infrastructure[0].ip_address)
        admin_key = self._relay_key("relay_admin")
        mh_hop_key = self._relay_key("mh_hop")
        if not admin_key.exists() or not mh_hop_key.exists():
            raise RuntimeError("Relay admin/mh-hop keys are missing; refusing to seal without forced relay access.")
        cloud_pub = Path(str(self._ssh_key_path) + ".pub").read_text().strip().split()
        keymat = cloud_pub[1] if len(cloud_pub) > 1 else ""

        def hardening_command(listen_ip: str, remove_cloud_key: bool) -> str:
            directives = [
                f"ListenAddress {listen_ip}",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "AllowAgentForwarding no",
                "X11Forwarding no",
                "GatewayPorts no",
                "PermitTunnel no",
                "AllowTcpForwarding no",
                "PermitRootLogin prohibit-password",
            ]
            remove = (
                "if [ -n " + shlex.quote(keymat) + " ]; then "
                "sed -i " + shlex.quote("\\|" + keymat + "|d") + " /root/.ssh/authorized_keys; fi; "
                if remove_cloud_key else ""
            )
            return (
                "cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.mhbench.sealed 2>/dev/null || true; "
                "for key in ListenAddress PasswordAuthentication KbdInteractiveAuthentication "
                "AllowAgentForwarding X11Forwarding GatewayPorts PermitTunnel AllowTcpForwarding "
                "PermitRootLogin; do sed -i \"/^${key}[[:space:]]/d\" /etc/ssh/sshd_config; done; "
                + remove +
                "{ printf '%s\\n' " + " ".join(shlex.quote(x) for x in directives) +
                "; cat /etc/ssh/sshd_config; } > /etc/ssh/sshd_config.mhbench.new && "
                "mv /etc/ssh/sshd_config.mhbench.new /etc/ssh/sshd_config && "
                "sshd -t && systemctl reload ssh"
            )

        proxy = (f"ssh -i {mh_hop_key} -o BatchMode=yes -o StrictHostKeyChecking=no "
                 f"-o UserKnownHostsFile=/dev/null mh-hop@{mgmt_floating_ip} {c2_ip} 22")
        r = subprocess.run(
            ["ssh", "-i", str(admin_key), "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", f"ProxyCommand={proxy}", f"root@{c2_ip}",
             hardening_command(c2_ip, True)],
            capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"relay hardening failed: {r.stderr.strip()}")

        # Management host: only the management interface, no forwarding, no tunnel. Its cloud key
        # remains for infrastructure access; only the relay key is removed.
        r = self._run_bootstrap_ssh(topology, mgmt_floating_ip, mgmt_floating_ip,
                                    hardening_command("10.0.1.10", False), direct=True)
        if r.returncode != 0:
            raise RuntimeError(f"management SSH hardening failed: {r.stderr.strip()}")

    def rotate_logs(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        # Pre-attack reset: rebuild the same bastion ProxyJump inventory as collect() and reset every
        # host's ground-truth logs to empty at the deploy->attack boundary, so post-experiment
        # collection yields attack-phase-only logs. The harness blocks the attacker on this. Includes
        # the attacker (kali), same as collect() — its image now bakes in the same telemetry.
        logger.debug("Rotating host logs via mgmt %s", mgmt_floating_ip)
        hosts = list(topology.get_all_hosts())
        for host in hosts:
            if host.ip_address is None:
                raise RuntimeError(f"Host '{host.name}' has no ip_address; cannot build ansible inventory.")

        # bastion-hop mux: all hosts share ONE ssh connection to the bastion (separate -W channels) so the
        # parallel-configure burst can't trip its default MaxStartups (10) and drop the attacker. Per-experiment
        # socket keyed on the bastion IP + namespaced per-project (same dir as the outer per-target mux) so
        # concurrent runs — same internal IPs, different bastions — never share a socket.
        ctl = self._ssh_ctl_dir()
        proxy = self._bastion_proxy(topology, mgmt_floating_ip, ctl)
        inventory_hosts = {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": self._ssh_key_path,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no '
                    f'-o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 '
                    f'-o ServerAliveCountMax=10 '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in hosts
        }

        pb_path = self._playbook_registry.get_path("rotate_host_logs")
        project_dir = str((_MHBENCH_DIR / pb_path).resolve().parent)
        with tempfile.TemporaryDirectory() as tmp:
            self._run_playbook(
                "rotate_host_logs",
                {"all": {"hosts": inventory_hosts}},
                {},
                tmp,
                project_dir,
            )
