from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from src.abstractions.routing import RoutingConfig


class SubnetConnection(BaseModel):
    from_subnet: str
    to_subnet: str
    protocol: str | None = None
    ports: list[Annotated[int, Field(ge=1, le=65535, strict=True)]] | None = None
    bidirectional: bool = True

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.lower()
        if value.isdecimal():
            value = str(int(value))
        aliases = {"all": None, "1": "icmp", "6": "tcp", "17": "udp", "132": "sctp", "gre": "47"}
        if value in aliases:
            return aliases[value]
        if value in {"tcp", "udp", "icmp", "esp", "ah", "ipip", "sctp"}:
            return value
        if value.isdecimal() and 1 <= int(value) <= 255:
            return str(int(value))
        raise ValueError("protocol must be an IP protocol name or number (1-255), or null")

    @model_validator(mode="after")
    def validate_ports(self) -> SubnetConnection:
        if self.ports is not None:
            if not self.ports:
                raise ValueError("ports must be a nonempty list or null")
            if self.protocol not in {"tcp", "udp", "sctp"}:
                raise ValueError("ports require protocol tcp, udp, or sctp")
        return self


class PlaybookRef(BaseModel):
    name: str
    args: dict = Field(default_factory=dict)


class HostInterface(BaseModel):
    subnet: str
    ip_address: IPv4Address | None = None
    response_prefixes: list[IPv4Network] = Field(default_factory=list)


class Host(BaseModel):
    name: str
    # In-VM/OS hostname. FRR and BGP derive their advertised name from it, so
    # this is attacker-visible; `name` remains the resource/inventory identifier.
    hostname: str | None = None
    vm_type: str
    flavor: str = "m1.small"
    ip_address: IPv4Address | None = None
    extra_interfaces: list[HostInterface] = Field(default_factory=list)
    # Infrastructure control-plane host (for example the C2 relay): excluded from experimental sealing,
    # attacker-scoped keys, and the attacker-facing inventory.
    infrastructure: bool = False


class Subnet(BaseModel):
    name: str
    cidr: IPv4Network
    dns_servers: list[str] = Field(default_factory=lambda: ["8.8.8.8"])
    hosts: list[Host] = Field(default_factory=list)
    external: bool = False
    internet_egress: bool = True
    # Declarative marker: the internet-facing / perimeter tier (e.g. the DMZ webserver segment an
    # external attacker reaches first). PURELY informational — unlike `external` it drives NO provisioning
    # (no public gateway, no 0.0.0.0/0 SG rule); it just lets a consumer (the arena's defender spec) know
    # which segment is the perimeter so deception can bait the ingress path from a property the defender
    # legitimately owns, rather than inferring the attacker's position from subnet_connections.
    perimeter: bool = False

    @computed_field
    @property
    def sg_name(self) -> str:
        return f"{self.name}_sg"


class Network(BaseModel):
    name: str
    description: str = ""
    subnets: list[Subnet] = Field(default_factory=list)


class PkiConfig(BaseModel):
    """Optional private Web PKI contract for a routed topology."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    company_name: str
    domain: str
    domain_mode: Literal["hermetic_synthetic"] = "hermetic_synthetic"
    ca_host: str
    dns_host: str
    portal_host: str
    portal_name: str
    ca_name: str
    dns_records: dict[str, IPv4Address]
    trust_hosts: list[str] = Field(default_factory=lambda: ["server", "client"])

    @field_validator("company_name")
    @classmethod
    def validate_company(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("company_name must not be empty")
        if any(c in value for c in "\r\n\t"):
            raise ValueError("company_name must be a single line")
        return value

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        value = value.strip().lower().rstrip(".")
        domain_re = re.compile(
            r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+com$"
        )
        if not domain_re.fullmatch(value):
            raise ValueError("domain must be a lowercase .com DNS name")
        return value

    @field_validator("trust_hosts")
    @classmethod
    def validate_trust_hosts(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("trust_hosts must not be empty")
        if len(value) != len(set(value)):
            raise ValueError("trust_hosts must be unique")
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> PkiConfig:
        for name in (self.ca_host, self.dns_host, self.portal_host,
                     self.portal_name, self.ca_name):
            if not name:
                raise ValueError("pki host/name fields must not be empty")
        if self.portal_name != f"portal.{self.domain}":
            raise ValueError("portal_name must be portal.<domain>")
        if self.ca_name != f"ca.{self.domain}":
            raise ValueError("ca_name must be ca.<domain>")
        if self.portal_host == self.ca_host:
            raise ValueError("portal_host and ca_host must be distinct")
        expected = {self.portal_name, self.ca_name}
        if set(self.dns_records) != expected:
            raise ValueError("dns_records must contain exactly the portal and CA names")
        return self

    @staticmethod
    def _host_addresses(host) -> set[IPv4Address]:
        addresses = {host.ip_address} if host.ip_address is not None else set()
        addresses.update(i.ip_address for i in host.extra_interfaces if i.ip_address is not None)
        return addresses

    def validate_topology(self, topology: NetworkTopology) -> None:
        if topology.routing is None:
            raise ValueError("pki requires a routed topology")
        # This implementation hosts the CA and DNS roles on one fixed `pki` host and
        # configures the portal on the fixed `server` host. Reject other bindings instead
        # of silently deploying the fixed names.
        if self.ca_host != "pki" or self.dns_host != "pki":
            raise ValueError(
                "ca_host and dns_host must both be pki; the single-VM PKI deployment does not support a split CA/DNS host"
            )
        if self.portal_host != "server":
            raise ValueError("portal_host must be server in the BGP-PKI topology")
        if self.portal_host not in self.trust_hosts:
            raise ValueError("trust_hosts must include the portal host")
        if "client" not in self.trust_hosts:
            raise ValueError("trust_hosts must include the legitimate client host client")

        data_subnets = topology.routing.data_subnet_names(topology)
        role_hosts = {"ca_host": self.ca_host, "portal_host": self.portal_host}
        resolved = {}
        for role, name in role_hosts.items():
            host = topology.get_host_by_name(name)
            if host is None:
                raise ValueError(f"{role} references unknown host {name!r}")
            if host.infrastructure:
                raise ValueError(f"{role} must not reference an infrastructure host")
            if not any(i.subnet in data_subnets and i.ip_address is not None
                       for i in host.extra_interfaces):
                raise ValueError(f"{role} host {name!r} needs a data-plane interface")
            resolved[role] = host
        for name in self.trust_hosts:
            host = topology.get_host_by_name(name)
            if host is None:
                raise ValueError(f"trust_hosts references unknown host {name!r}")
            if host.infrastructure:
                raise ValueError(f"trust_hosts must not reference infrastructure host {name!r}")
        for record_name, owner_role in ((self.portal_name, "portal_host"),
                                        (self.ca_name, "ca_host")):
            owner = resolved[owner_role]
            data_addresses = {
                i.ip_address for i in owner.extra_interfaces
                if i.subnet in data_subnets and i.ip_address is not None
            }
            if self.dns_records[record_name] not in data_addresses:
                raise ValueError(
                    f"DNS record {record_name!r} must point at a data-plane interface of {owner_role} {owner.name!r}"
                )


class NetworkTopology(BaseModel):
    name: str
    networks: list[Network] = Field(default_factory=list)
    subnet_connections: list[SubnetConnection] = Field(default_factory=list)
    playbooks: list[PlaybookRef] = Field(default_factory=list)
    routing: RoutingConfig | None = None
    pki: PkiConfig | None = None
    attacker_briefing: str | None = None

    @model_validator(mode="after")
    def validate_connections(self) -> NetworkTopology:
        names = [s.name for s in self.get_all_subnets()]
        if len(names) != len(set(names)):
            raise ValueError("subnet names must be unique")
        for connection in self.subnet_connections:
            for name in (connection.from_subnet, connection.to_subnet):
                if name not in names:
                    raise ValueError(f"Connection references unknown subnet {name!r}")
        if self.routing is not None:
            self.routing.validate_topology(self)
        elif any(i.response_prefixes for h in self.get_all_hosts() for i in h.extra_interfaces):
            raise ValueError("response_prefixes require routing")
        if self.pki is not None:
            self.pki.validate_topology(self)
        return self

    def get_ingress_connections(self, subnet_name: str) -> list[SubnetConnection]:
        """Incoming initiation permissions, with explicit pairs overriding role defaults."""
        incoming = []
        explicit_peers = set()
        for connection in self.subnet_connections:
            if connection.to_subnet == subnet_name:
                explicit_peers.add(connection.from_subnet)
                incoming.append(connection)
            elif connection.from_subnet == subnet_name:
                explicit_peers.add(connection.to_subnet)
                if connection.bidirectional:
                    incoming.append(connection.model_copy(update={
                        "from_subnet": connection.to_subnet, "to_subnet": subnet_name,
                        "bidirectional": False,
                    }))
        data_names = self.routing.data_subnet_names(self) if self.routing is not None else set()
        for source in self.get_all_subnets():
            if subnet_name in data_names or source.name in data_names:
                continue
            if source.name == subnet_name or source.name in explicit_peers:
                continue
            callback = (subnet_name == "attacker_subnet" and not source.external
                        and source.name != "defender_subnet")
            response = (source.name == "defender_subnet"
                        and subnet_name not in {"attacker_subnet", "defender_subnet"})
            if callback or response:
                incoming.append(SubnetConnection(
                    from_subnet=source.name, to_subnet=subnet_name, bidirectional=False,
                ))
        return incoming

    def get_all_hosts(self) -> list[Host]:
        return [h for net in self.networks for sub in net.subnets for h in sub.hosts]

    def get_all_subnets(self) -> list[Subnet]:
        return [sub for net in self.networks for sub in net.subnets]

    def get_subnet_by_name(self, name: str) -> Subnet | None:
        return next((s for s in self.get_all_subnets() if s.name == name), None)

    def get_subnet_for_host(self, host: Host) -> Subnet | None:
        return next((s for s in self.get_all_subnets() if host in s.hosts), None)

    def get_host_by_name(self, name: str) -> Host | None:
        return next((h for h in self.get_all_hosts() if h.name == name), None)
