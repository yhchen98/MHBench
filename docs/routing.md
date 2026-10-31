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

### Run and verify automatically

Use the normal image workflow to build/upload the required images, and configure OpenStack and the SSH key as usual. From the MHBench directory:

```sh
uv run python scripts/run_bgp_three_as.py --project-name bgp-demo
```

This creates and configures the fixed example, verifies it, and tears it down. It requires six VMs including management, eight networks, and 14 VM NICs. The project name must be unused. To verify an already configured deployment and then **delete it**:

```sh
uv run python scripts/run_bgp_three_as.py --project-name bgp-demo --existing
```

Use `--config` for another MHBench configuration or `--output-dir` for a new evidence directory. The default output is under `../.validation/bgp-three-as/`; reports and captures remain after teardown. The script supports this fixed OpenStack example and discovers interface names and the management floating IP from actual readback.

The runner checks services, BGP peers, addresses, return routes, host default gateways/rules, forwarding guards, NAT, and Neutron configuration. It captures transit's three data interfaces and control interface while issuing fresh numeric IPv4 HTTP requests bound to the client data address. Both response services and the attacker's loopback backing address are prepared before measurement.

| Stage | Transit next hop for the target | Response | WAN carrying requests and replies |
| --- | --- | --- | --- |
| Baseline | 10.250.0.1 | ORIGIN | Origin |
| Announcement | 10.250.0.6 | ATTACKER | Attacker |
| Withdrawal | 10.250.0.1 | ORIGIN | Origin |

Before the announcement, a separate negative control administratively shuts down the origin BGP neighbor while retaining its configuration. Fresh client requests must fail with no P/H route, while control SSH and both local services remain healthy. A selected control default must hit the forwarding DROP rule. The neighbor and baseline are restored before measurement continues. Announcing and withdrawing H changes only the attacker's temporary BGP network statement; receiving policies, host routes, services, addresses, and firewalls remain fixed.

Success requires the correct RIB/FIB changes, matching request/reply captures on the selected interfaces, no matching traffic on the unused WAN, and no TCP/8080 traffic on control. Capture failure or packet loss is a verification failure. Provider checks require no data gateway, DHCP, host routes, Neutron router attachments, or data floating IPs; addressless OVN metadata ports are recognized separately from router ports.

Errors, convergence deadlines, and interruption trigger restoration attempts, capture cleanup, and teardown of the owned/adopted deployment. Any verification or cleanup failure produces a nonzero exit and diagnostics in `summary.json`, `run.log`, command results, and capture files. A preflight namespace rejection leaves that deployment untouched. Check the reported remaining resources if cleanup fails.

This is an MHBench operator demonstration. Existing Arena orchestration can pass the specification through the normal CLI, but its Kali-specific attacker discovery does not turn this FRR VM into an Incalmo foothold or grant BGP actions.
