#!/usr/bin/env bash
set -euo pipefail

CHAIN="${OPENCLAW_FIREWALL_CHAIN:-DOCKER-USER}"
COMMENT_PREFIX="${OPENCLAW_FIREWALL_COMMENT_PREFIX:-openclaw-guard}"

if ! iptables -nL "$CHAIN" >/dev/null 2>&1; then
  exit 0
fi

mapfile -t RULE_NUMBERS < <(
  iptables -nvL "$CHAIN" --line-numbers \
    | awk -v prefix="$COMMENT_PREFIX" '$0 ~ prefix { print $1 }' \
    | sort -rn
)

for rule_number in "${RULE_NUMBERS[@]}"; do
  iptables -D "$CHAIN" "$rule_number"
done
