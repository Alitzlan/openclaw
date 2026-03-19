#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAIN="${OPENCLAW_FIREWALL_CHAIN:-DOCKER-USER}"
NETWORK_NAME="${OPENCLAW_NETWORK_NAME:-openclaw_default}"
CONTAINER_NAME="${OPENCLAW_CONTAINER_NAME:-openclaw-openclaw-gateway-1}"
GATEWAY_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"
BRIDGE_PORT="${OPENCLAW_BRIDGE_PORT:-18790}"
COMMENT_PREFIX="${OPENCLAW_FIREWALL_COMMENT_PREFIX:-openclaw-guard}"
BRIDGE_NF_IPTABLES_PATH="/proc/sys/net/bridge/bridge-nf-call-iptables"

fail() {
  echo "OpenClaw firewall apply failed: $*" >&2
  exit 1
}

require_bridge_netfilter() {
  if [[ ! -r "$BRIDGE_NF_IPTABLES_PATH" ]]; then
    fail \
      "bridge netfilter is unavailable ($BRIDGE_NF_IPTABLES_PATH missing). " \
      "Load br_netfilter and enable net.bridge.bridge-nf-call-iptables=1 before applying rules."
  fi

  local bridge_nf_iptables
  bridge_nf_iptables="$(<"$BRIDGE_NF_IPTABLES_PATH")"
  if [[ "$bridge_nf_iptables" != "1" ]]; then
    fail \
      "net.bridge.bridge-nf-call-iptables=$bridge_nf_iptables. " \
      "Docker bridge traffic will bypass the DOCKER-USER chain. " \
      "Set net.bridge.bridge-nf-call-iptables=1 and re-run this script."
  fi
}

require_bridge_netfilter

docker inspect "$CONTAINER_NAME" >/dev/null 2>&1
docker network inspect "$NETWORK_NAME" >/dev/null 2>&1

SRC_SUBNET="$(
  docker network inspect "$NETWORK_NAME" \
    --format '{{(index .IPAM.Config 0).Subnet}}'
)"
BRIDGE_GATEWAY_IP="$(
  docker network inspect "$NETWORK_NAME" \
    --format '{{(index .IPAM.Config 0).Gateway}}'
)"
CONTAINER_IP="$(
  docker inspect "$CONTAINER_NAME" \
    --format "{{with index .NetworkSettings.Networks \"$NETWORK_NAME\"}}{{.IPAddress}}{{end}}"
)"

if [[ -z "$SRC_SUBNET" || -z "$BRIDGE_GATEWAY_IP" || -z "$CONTAINER_IP" ]]; then
  fail "Failed to resolve OpenClaw Docker network details."
fi

if ! iptables -nL "$CHAIN" >/dev/null 2>&1; then
  iptables -N "$CHAIN"
fi

"$SCRIPT_DIR/remove.sh"

# Insert in reverse order because each rule is added at the top of the chain.
iptables -I "$CHAIN" 1 \
  -s "$SRC_SUBNET" \
  -j ACCEPT \
  -m comment --comment "$COMMENT_PREFIX allow-public"

iptables -I "$CHAIN" 1 \
  -s "$SRC_SUBNET" \
  -d 169.254.0.0/16 \
  -j REJECT --reject-with icmp-port-unreachable \
  -m comment --comment "$COMMENT_PREFIX deny-link-local"

iptables -I "$CHAIN" 1 \
  -s "$SRC_SUBNET" \
  -d 192.168.0.0/16 \
  -j REJECT --reject-with icmp-port-unreachable \
  -m comment --comment "$COMMENT_PREFIX deny-192"

iptables -I "$CHAIN" 1 \
  -s "$SRC_SUBNET" \
  -d 172.16.0.0/12 \
  -j REJECT --reject-with icmp-port-unreachable \
  -m comment --comment "$COMMENT_PREFIX deny-172"

iptables -I "$CHAIN" 1 \
  -s "$SRC_SUBNET" \
  -d 10.0.0.0/8 \
  -j REJECT --reject-with icmp-port-unreachable \
  -m comment --comment "$COMMENT_PREFIX deny-10"

iptables -I "$CHAIN" 1 \
  -s "$SRC_SUBNET" \
  -p tcp --dport 53 \
  -j ACCEPT \
  -m comment --comment "$COMMENT_PREFIX dns-tcp"

iptables -I "$CHAIN" 1 \
  -s "$SRC_SUBNET" \
  -p udp --dport 53 \
  -j ACCEPT \
  -m comment --comment "$COMMENT_PREFIX dns-udp"

iptables -I "$CHAIN" 1 \
  -p tcp \
  -d "$CONTAINER_IP" \
  -m multiport --dports "$GATEWAY_PORT","$BRIDGE_PORT" \
  ! -s "$BRIDGE_GATEWAY_IP" \
  -j REJECT --reject-with tcp-reset \
  -m comment --comment "$COMMENT_PREFIX deny-ui-nonhost"

iptables -I "$CHAIN" 1 \
  -p tcp \
  -s "$BRIDGE_GATEWAY_IP" \
  -d "$CONTAINER_IP" \
  --dport "$BRIDGE_PORT" \
  -j ACCEPT \
  -m comment --comment "$COMMENT_PREFIX allow-bridge-from-host"

iptables -I "$CHAIN" 1 \
  -p tcp \
  -s "$BRIDGE_GATEWAY_IP" \
  -d "$CONTAINER_IP" \
  --dport "$GATEWAY_PORT" \
  -j ACCEPT \
  -m comment --comment "$COMMENT_PREFIX allow-gateway-from-host"

iptables -I "$CHAIN" 1 \
  -s "$SRC_SUBNET" \
  -m conntrack --ctstate RELATED,ESTABLISHED \
  -j ACCEPT \
  -m comment --comment "$COMMENT_PREFIX established"

iptables -nvL "$CHAIN"
