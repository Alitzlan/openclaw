#!/usr/bin/env bash
set -euo pipefail

CHAIN="${OPENCLAW_FIREWALL_CHAIN:-DOCKER-USER}"
HOST_INPUT_CHAIN="${OPENCLAW_FIREWALL_HOST_INPUT_CHAIN:-INPUT}"
COMMENT_PREFIX="${OPENCLAW_FIREWALL_COMMENT_PREFIX:-openclaw-guard}"

remove_chain_rules() {
  local chain="$1"
  if ! iptables -nL "$chain" >/dev/null 2>&1; then
    return 0
  fi

  mapfile -t RULE_NUMBERS < <(
    iptables -nvL "$chain" --line-numbers \
      | awk -v prefix="$COMMENT_PREFIX" '$0 ~ prefix { print $1 }' \
      | sort -rn
  )

  for rule_number in "${RULE_NUMBERS[@]}"; do
    iptables -D "$chain" "$rule_number"
  done
}

remove_chain_rules "$CHAIN"
remove_chain_rules "$HOST_INPUT_CHAIN"
