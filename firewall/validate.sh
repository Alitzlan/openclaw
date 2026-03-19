#!/usr/bin/env bash
set -euo pipefail

CHAIN="${OPENCLAW_FIREWALL_CHAIN:-DOCKER-USER}"
HOST_INPUT_CHAIN="${OPENCLAW_FIREWALL_HOST_INPUT_CHAIN:-INPUT}"
NETWORK_NAME="${OPENCLAW_NETWORK_NAME:-openclaw_default}"
CONTAINER_NAME="${OPENCLAW_CONTAINER_NAME:-openclaw-openclaw-gateway-1}"
GATEWAY_PORT="${OPENCLAW_GATEWAY_PORT:-18789}"
BRIDGE_PORT="${OPENCLAW_BRIDGE_PORT:-18790}"
COMMENT_PREFIX="${OPENCLAW_FIREWALL_COMMENT_PREFIX:-openclaw-guard}"
BRIDGE_NF_IPTABLES_PATH="/proc/sys/net/bridge/bridge-nf-call-iptables"
BRIDGE_NF_IP6TABLES_PATH="/proc/sys/net/bridge/bridge-nf-call-ip6tables"
HOST_TEST_PORT="${OPENCLAW_VALIDATE_HOST_TEST_PORT:-22}"
PUBLIC_TEST_URL="${OPENCLAW_VALIDATE_PUBLIC_TEST_URL:-https://example.com}"
TCP_TIMEOUT_MS="${OPENCLAW_VALIDATE_TCP_TIMEOUT_MS:-3000}"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

pass() {
  printf 'PASS: %s\n' "$*"
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

warn() {
  printf 'WARN: %s\n' "$*"
  WARN_COUNT=$((WARN_COUNT + 1))
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  fi
}

probe_tcp_from_container() {
  local host="$1"
  local port="$2"
  local result
  local exit_code

  if result="$(
    docker exec "$CONTAINER_NAME" node -e '
const net = require("net");

const [host, portRaw, timeoutRaw] = process.argv.slice(1);
const port = Number(portRaw);
const timeoutMs = Number(timeoutRaw);

const socket = net.createConnection({ host, port });
let settled = false;

function finish(code, message) {
  if (settled) {
    return;
  }
  settled = true;
  if (message) {
    process.stdout.write(String(message));
  }
  socket.destroy();
  process.exit(code);
}

socket.once("connect", () => finish(0, "open"));
socket.once("error", (err) => finish(1, err && err.code ? err.code : "error"));
socket.setTimeout(timeoutMs, () => finish(2, "timeout"));
    ' "$host" "$port" "$TCP_TIMEOUT_MS"
  )"; then
    exit_code=0
  else
    exit_code=$?
  fi

  printf '%s' "$result"
  return "$exit_code"
}

probe_url_from_container() {
  local url="$1"
  docker exec "$CONTAINER_NAME" sh -lc "curl -fsS --max-time 5 '$url' >/dev/null"
}

check_rule_comment() {
  local chain_dump="$1"
  local comment="$2"
  if grep -Fq -- "$comment" <<<"$chain_dump"; then
    return 0
  fi
  return 1
}

require_command docker
require_command iptables
require_command ip

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
mapfile -t HOST_IPV4S < <(
  ip -4 -o addr show scope global \
    | awk '{split($4, parts, "/"); print parts[1]}'
)
mapfile -t PUBLISHED_HOST_IPS < <(
  docker inspect "$CONTAINER_NAME" \
    --format '{{range $port, $bindings := .NetworkSettings.Ports}}{{range $bindings}}{{println .HostIp}}{{end}}{{end}}' \
    | sed '/^$/d'
)

printf 'OpenClaw firewall validation\n'
printf '  container: %s\n' "$CONTAINER_NAME"
printf '  network:   %s\n' "$NETWORK_NAME"
printf '  subnet:    %s\n' "$SRC_SUBNET"
printf '  gateway:   %s\n' "$BRIDGE_GATEWAY_IP"
printf '  container: %s\n' "$CONTAINER_IP"
printf '  host test port: %s\n' "$HOST_TEST_PORT"

if [[ -r "$BRIDGE_NF_IPTABLES_PATH" && "$(<"$BRIDGE_NF_IPTABLES_PATH")" == "1" ]]; then
  pass "bridge netfilter is active for iptables"
else
  fail "bridge netfilter is not active for iptables"
fi

if [[ -r "$BRIDGE_NF_IP6TABLES_PATH" && "$(<"$BRIDGE_NF_IP6TABLES_PATH")" == "1" ]]; then
  pass "bridge netfilter is active for ip6tables"
else
  warn "bridge netfilter is not active for ip6tables"
fi

if printf '%s\n' "${PUBLISHED_HOST_IPS[@]:-}" | grep -Fxq '::'; then
  fail "container ports are still published on IPv6"
else
  pass "container ports are not published on IPv6"
fi

CHAIN_DUMP=""
HOST_INPUT_DUMP=""
if CHAIN_DUMP="$(iptables -S "$CHAIN" 2>/dev/null)"; then
  for required_comment in \
    "$COMMENT_PREFIX established" \
    "$COMMENT_PREFIX allow-gateway-from-host" \
    "$COMMENT_PREFIX allow-bridge-from-host" \
    "$COMMENT_PREFIX deny-ui-nonhost" \
    "$COMMENT_PREFIX dns-udp" \
    "$COMMENT_PREFIX dns-tcp" \
    "$COMMENT_PREFIX deny-10" \
    "$COMMENT_PREFIX deny-172" \
    "$COMMENT_PREFIX deny-192" \
    "$COMMENT_PREFIX deny-link-local" \
    "$COMMENT_PREFIX allow-public"
  do
    if check_rule_comment "$CHAIN_DUMP" "$required_comment"; then
      pass "$CHAIN contains $required_comment"
    else
      fail "$CHAIN is missing $required_comment"
    fi
  done
else
  warn "could not read $CHAIN rules; run with sudo for full validation"
fi

if HOST_INPUT_DUMP="$(iptables -S "$HOST_INPUT_CHAIN" 2>/dev/null)"; then
  for required_comment in \
    "$COMMENT_PREFIX host-established" \
    "$COMMENT_PREFIX deny-host-input"
  do
    if check_rule_comment "$HOST_INPUT_DUMP" "$required_comment"; then
      pass "$HOST_INPUT_CHAIN contains $required_comment"
    else
      fail "$HOST_INPUT_CHAIN is missing $required_comment"
    fi
  done
else
  warn "could not read $HOST_INPUT_CHAIN rules; run with sudo for full validation"
fi

for host_ip in "${HOST_IPV4S[@]}"; do
  if [[ "$host_ip" == "$BRIDGE_GATEWAY_IP" ]]; then
    continue
  fi

  probe_result="$(probe_tcp_from_container "$host_ip" "$HOST_TEST_PORT")" || probe_status=$?
  probe_status="${probe_status:-0}"
  if [[ "$probe_status" -eq 0 ]]; then
    fail "container can still reach host IP $host_ip on port $HOST_TEST_PORT"
  else
    pass "container cannot reach host IP $host_ip on port $HOST_TEST_PORT ($probe_result)"
  fi
  unset probe_status
done

probe_result="$(probe_tcp_from_container "$BRIDGE_GATEWAY_IP" "$HOST_TEST_PORT")" || probe_status=$?
probe_status="${probe_status:-0}"
if [[ "$probe_status" -eq 0 ]]; then
  fail "container can still reach Docker bridge gateway $BRIDGE_GATEWAY_IP on port $HOST_TEST_PORT"
else
  pass "container cannot reach Docker bridge gateway $BRIDGE_GATEWAY_IP on port $HOST_TEST_PORT ($probe_result)"
fi
unset probe_status

if probe_url_from_container "$PUBLIC_TEST_URL"; then
  pass "container can still reach public internet ($PUBLIC_TEST_URL)"
else
  warn "container could not reach public internet ($PUBLIC_TEST_URL)"
fi

printf '\nSummary: %s pass, %s fail, %s warn\n' "$PASS_COUNT" "$FAIL_COUNT" "$WARN_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
