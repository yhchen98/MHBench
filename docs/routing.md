# Routed environments

An optional `routing` section describes IPv4 unicast routing through one router per AS. On OpenStack, omitting it retains Neutron routing; existing non-BGP behavior is unchanged on both backends. BGP environments use the OpenStack backend and require the management host.

## Interfaces and gateways

Keep every host's primary `ip_address` on a control subnet. Declare data NICs in `extra_interfaces`, using existing subnet names and static `ip_address` values. A router's extra interfaces connect its data LANs and peering links. An end host has one data interface and a gateway on that LAN.

Data subnets have no primary hosts and explicitly set `external: false` and `internet_egress: false`. Use distinct, non-overlapping control and data subnets. The routers and hosts retain their primary control identities for management and Arena access.

## Routing fields

| Field | Meaning |
| --- | --- |
| `routers` | Nonempty list of `host`, `asn`, `router_id`, and optional `advertised_prefixes`. The host names an existing VM with an image derived from `frr_router`. Initial advertisements are its connected data LAN prefixes. |
| `peerings` | Each entry names a `subnet` and exactly two `endpoints`. Each endpoint names a `router` host and explicit `import_policy` and `export_policy`. The data link contains only those router interfaces. |
| `policies` | Named ordered prefix-filter rules with an explicit `default_action: "deny"`. Policies contain no router CLI commands. |
| `host_gateways` | Entries with `host`, `subnet`, and `gateway`, identifying an end host's data interface and the router interface used as its default gateway. |
| `control_routes` | Optional additional IPv4 destination prefixes for control services outside the known control networks. They cannot include a default route or overlap any data subnet. |

Each prefix rule has `prefix`, `action` (`permit` or `deny`), optional `min_prefix_length`/`max_prefix_length`, and optional `local_preference` on a permitted import. Without length bounds, a rule matches the exact prefix. With only a maximum length, a rule includes the base prefix and its subprefixes through that length. A minimum without a maximum extends through /32.

For example, this policy permits a /23 and its /24 subprefixes at import preference 200:

```json
{
  "name": "customer_in",
  "rules": [{
    "prefix": "198.19.0.0/23",
    "action": "permit",
    "max_prefix_length": 24,
    "local_preference": 200
  }],
  "default_action": "deny"
}
```

Permit rules are confined to declared data LAN prefixes. Peering/control networks and default routes are excluded. An export policy cannot set local preference. Peering relationships are implemented by the supplied policies; MHBench does not infer commercial relationships or prefix ownership.

Routing policies govern route exchange. `subnet_connections` separately governs application protocol, destination ports, and initiation direction. A route does not grant application access.

End hosts use their AS router as their sole default gateway. Explicit control routes preserve management/C2 access through the control network. Numeric C2 endpoints must be outside the data plane; DNS-named endpoints require explicit control destination prefixes, whose coverage must be checked before changing guest routes. End hosts do not run BGP. Dynamic add/rebuild/remove-host operations are unsupported for routed environments.
