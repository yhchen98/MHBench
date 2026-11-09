#!/bin/sh
# Restricted FRR CLI for the attacker's own edge router.
#
# The Kali foothold key is authorized with this forced command. The wrapper
# accepts read-only `show` commands and a fixed allow-list of BGP/static-route
# configuration lines. Everything else is rejected; the command text is passed
# to vtysh as data, never evaluated by a shell.
set -eu

usage() {
    cat <<'EOF'
restricted FRR CLI
  show <command>   run one read-only show command (for example: show ip bgp)
  help             show this help

Configuration is a semicolon-separated list of exactly these lines:
  configure terminal
  ip route <prefix> <nexthop>
  no ip route <prefix> <nexthop>
  router bgp 65003
  address-family ipv4 unicast
  network <prefix>
  no network <prefix>
  exit-address-family
  exit
  end
Send the command as the SSH command argument; stdin is not read. Abbreviations (for example "conf t") are not accepted.
EOF
}

command_text="${SSH_ORIGINAL_COMMAND:-}"
if [ -z "$command_text" ]; then
    echo "restricted FRR CLI: send a vtysh command (e.g. show ip bgp) or a semicolon-separated config list (run 'help' for accepted commands)" >&2
    exit 2
fi

case "$command_text" in
    vtysh\ -c\ *) command_text=${command_text#vtysh -c } ;;
esac
case "$command_text" in
    \"*\") command_text=${command_text#\"}; command_text=${command_text%\"} ;;
    \'*\') command_text=${command_text#\'}; command_text=${command_text%\'} ;;
esac

case "$command_text" in
    help|--help)
        usage
        exit 0
        ;;
esac

case "$command_text" in
    show|show\ *)
        case "$command_text" in
            *";"*|*[![:print:]]*) echo "rejected by restricted FRR CLI: show must be one command (run 'help' for accepted commands)" >&2; exit 3 ;;
        esac
        exec /usr/bin/vtysh -c "$command_text"
        ;;
esac

tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT

printf '%s\n' "$command_text" \
    | tr ';' '\n' \
    | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
    | sed '/^$/d' > "$tmp"

address='([0-9]{1,3}\.){3}[0-9]{1,3}'
prefix="$address/[0-9]{1,2}"
while IFS= read -r line; do
    case "$line" in
        "configure terminal"|"end"|"exit"|"exit-address-family"|"router bgp 65003"|"address-family ipv4 unicast")
            ;;
        *)
            if ! printf '%s\n' "$line" | grep -Eq "^(no )?(network $prefix|ip route $prefix $address)$"; then
                echo "rejected by restricted FRR CLI: $line (run 'help' for accepted commands)" >&2
                exit 3
            fi
            ;;
    esac
done < "$tmp"

sed -i '/^configure terminal$/d; /^end$/d' "$tmp"
/usr/bin/vtysh -f "$tmp"
