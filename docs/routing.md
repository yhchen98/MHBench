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

## Deployment

Build and upload `frr_router` through the [normal image workflow](../README.md#compile-images) before deploying a routed environment. The profile contains FRR; the environment supplies its configuration. Set `openstack.external_network` to the site's external network name; leaving it unset retains `external`.

Provisioning creates separate Neutron networks for the data LANs and peering links, with no DHCP, Neutron gateway, router attachment, or floating IP. Configuration reads each port's MAC and the actual control gateway, applies persistent MAC-matched Netplan settings, enables Linux forwarding on routers, and starts FRR. It then waits for declared BGP sessions and initial origin routes. Use the existing `deploy` command, or `provision` followed by `configure`, including the management IP.

Control routes preserve primary-address SSH, C2, and telemetry access. DNS-named C2 endpoints must resolve to IPv4 addresses covered by the declared control routes before cutover. Route exceptions do not grant security-group egress: control services must also be reachable under the control subnet's connectivity policy. End hosts have one data default; routers retain a control default but reject forwarding to or from their control NIC. No experimental destination can use a control-route exception.

Router data ports have port security disabled to carry transit packets with other hosts' source addresses. Control ports and end-host data ports retain security groups and port security. Data LAN groups enforce explicit application connections without management or role-based exceptions. Router guest rules restrict data-plane SSH and BGP access; root access to a router remains administrative access, not an isolated attacker privilege.

## Three-AS example

[bgp_three_as.json](../environments/non-generated/bgp_three_as.json) places the client in transit AS65002. Origin AS65001 and attacker AS65003 are both customers of transit; there is no peer link. Each AS has one router and needs no intradomain protocol.

| Guest | AS | Control IP | Data IPs |
| --- | --- | --- | --- |
| origin-router | 65001 | 10.200.1.10 | WAN 10.250.0.1/30; LAN 198.19.0.1/23 |
| server | 65001 | 10.200.1.20 | 198.19.0.10/23 |
| transit-router | 65002 | 10.200.2.10 | WANs 10.250.0.2/30 and 10.250.0.5/30; LAN 198.18.0.1/24 |
| client | 65002 | 10.200.2.20 | 198.18.0.10/24 |
| attacker-router | 65003 | 10.200.3.10 | WAN 10.250.0.6/30; prepared loopback 198.19.0.10/24 |

Let `P = 198.19.0.0/23`, `H = 198.19.0.0/24`, and `C = 198.18.0.0/24`. Origin initially advertises P, transit advertises C, and attacker advertises nothing. All policies end in deny:

| Receiver → neighbor | Relationship | Import | Export |
| --- | --- | --- | --- |
| Transit → origin or attacker | Provider → customer | `customer_in`: P and its /24s, preference 200 on both links | `to_customer`: exact C, P and its /24s |
| Origin → transit | Customer → provider | `origin_in`: exact C, preference 100 | `origin_out`: exact P |
| Attacker → transit | Customer → provider | `attacker_in`: exact C and P, preference 100 | `attacker_out`: exact H |

Transit's filter bounds deaggregation at /24 but deliberately does not bind prefixes to the owning customer. It therefore accepts H from AS65003 with an ordinary first-AS-valid path. Both customer imports keep preference 200. P and H are distinct routes; longest-prefix forwarding selects H for the server address. No receiving policy or preference changes during the attack.

A /23 versus /24 models unauthorized deaggregation within a common maximum-/24 policy, without depending on /32 host-route acceptance. A same-prefix example with these symmetric customers would depend on further BGP tie-breaks. The private ASNs and [benchmarking addresses](https://www.iana.org/assignments/iana-ipv4-special-registry/) model an isolated lab, not Internet propagation or universal filtering practice. [RFC 7454](https://www.rfc-editor.org/rfc/rfc7454.html#section-6.1.3) discusses prefix-length filtering.

### Preparation and baseline

Use the normal image/deployment workflow with `environments/non-generated/bgp_three_as.json` and a unique `--project-name`. The example needs six VMs including management, eight networks, and 14 VM NICs. Confirm site quota/flavors before cloud use. Validation alone uses `mhbench deploy environments/non-generated/bgp_three_as.json --validate-only`.

Configuration runs `prepare_bgp_demo` after routing readiness. It starts HTTP services bound only to `198.19.0.10:8080`, returning `ORIGIN` on the server and `ATTACKER` on the attacker router. The latter has a guest-only loopback /24 backing route, prepared before measurement and initially unannounced; no overlapping Neutron port is created. The only declared application grant is client LAN → origin LAN TCP/8080, with stateful replies.

Connect as root through the management bastion to the guests' control addresses. Run commands below on the named guest. Do not tunnel or proxy the probe through SSH. On the client, use a fresh numeric, source-bound request for every observation:

```sh
curl --noproxy '*' --interface 198.18.0.10 --connect-timeout 2 --max-time 5 http://198.19.0.10:8080/
```

On transit, record sessions, both prefixes, and the kernel forwarding decision:

```sh
vtysh -c 'show bgp ipv4 unicast summary json'
vtysh -c 'show bgp ipv4 unicast 198.19.0.0/23 json'
vtysh -c 'show bgp ipv4 unicast 198.19.0.0/24 json'
ip -4 route show
ip -4 route get 198.19.0.10 from 198.18.0.10 iif <client-LAN-interface>
```

Find actual interfaces by their assigned addresses with `ip -br -4 address`; do not assume NIC order. Baseline requires H absent, P via `10.250.0.1` with path `65001` and preference 200, and an ORIGIN response. Both origin and attacker must retain C through transit for replies. The client keeps default gateway `198.18.0.1`; its own route lookup cannot establish which BGP path transit selected.

### Announcement and withdrawal

On attacker only, add the network statement without saving it to the startup configuration:

```sh
vtysh -c 'configure terminal' -c 'router bgp 65003' -c 'address-family ipv4 unicast' -c 'network 198.19.0.0/24' -c 'end'
```

Within a bounded convergence interval (for example 60 seconds), transit must keep P via origin and install H via `10.250.0.6`, path `65003`, preference 200. The same client request must now return ATTACKER. Change no services, addresses, gateways, firewalls, or receiving policies between these stages.

Withdraw on attacker:

```sh
vtysh -c 'configure terminal' -c 'router bgp 65003' -c 'address-family ipv4 unicast' -c 'no network 198.19.0.0/24' -c 'end'
```

Require H absent from transit's BGP and kernel tables, the target lookup via `10.250.0.1`, and ORIGIN again. Keep the attacker backing address/service until after this observation; otherwise service failure could be mistaken for routing restoration. A convergence timeout is a failed run to diagnose.

### Path evidence and negative controls

Capture the probe tuple on transit's client LAN, selected WAN, unused WAN, and control NIC using `tcpdump -ni <interface> 'host 198.18.0.10 and host 198.19.0.10 and tcp port 8080'`, or use equivalent flow-specific counters. Requests and replies must use the origin WAN before/after the attack and attacker WAN during it, with no probe packets on the unused WAN or control NIC. On OpenStack, inspect actual data subnet gateway/DHCP settings, router interfaces, ports, and floating IPs as well; guest observations and generated requests alone cannot establish Neutron state.

Before the measured attack, with H absent and both services healthy, disable the origin peering data interface using `ip link set <origin-WAN-interface> down` on origin. Wait for P and H to be absent on transit. A fresh client request must fail while control SSH and local service checks remain healthy. Inspect `iptables -nvxL MHBENCH_FORWARD` on transit for rejected control-default fallback. Restore the interface, use `vtysh -c 'clear bgp 10.250.0.2'` on origin if needed to prompt reconnection, and require the original route and ORIGIN response before the attack.

For a separate filtering control, make a copy of the JSON whose `customer_in` rule omits `max_prefix_length`, retaining preference 200 on both links. Deploy this fixed exact-P policy from the start of a fresh fixture. P must work normally; the same H announcement must be exported by attacker but absent from transit's RIB/FIB, with ORIGIN still returned. Record attacker `show bgp ipv4 unicast neighbors 10.250.0.5 advertised-routes json` and an incoming BGP update capture on transit; received-route inspection is also available if inbound soft reconfiguration is enabled before the baseline. This control tests subprefix filtering, not origin authorization or an exact-prefix defense. Do not modify receiver policies during either fixture's attack.

With a valid baseline route, separately check that a healthy listener on server TCP/8081 is unreachable from client and that a healthy client listener cannot receive a fresh server-initiated connection. Verify each listener locally first; a stopped service is not firewall-denial evidence. Keep these controls outside the announcement-only sequence.

After withdrawal/restoration evidence, stop `mhbench-bgp-demo` on server and attacker. Stopping the attacker service removes its prepared loopback address. These demonstration services are not enabled at boot. Reconfiguration restores declared FRR state and prepares the services again; full teardown/provision/configure resets the experiment. Use the same project name for teardown.

This is an MHBench operator demonstration. Existing Arena orchestration can pass the specification through the normal CLI, but its Kali-specific attacker discovery does not turn this FRR VM into an Incalmo foothold or grant BGP actions.
