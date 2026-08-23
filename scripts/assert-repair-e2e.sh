#!/usr/bin/env bash
set -euo pipefail

# Compare two redacted snapshots produced by the disposable local repair
# fixture. Secrets are represented only by hashes; this script never prints
# environment-file contents.
if [[ $# -lt 3 || $# -gt 4 ]]; then
  printf 'usage: %s BEFORE.json AFTER.json EXPECTED_GENERATION_DELTA [EXPECTED_PUBLIC_PROBE]\n' "$0" >&2
  exit 2
fi

before=$1
after=$2
delta=$3
expected_public_probe=${4:-any}

case "$expected_public_probe" in
  any|true|false) ;;
  *)
    printf 'EXPECTED_PUBLIC_PROBE must be any, true, or false\n' >&2
    exit 2
    ;;
esac

for file in "$before" "$after"; do
  [[ -s "$file" ]] || { printf 'missing snapshot: %s\n' "$file" >&2; exit 1; }
done

before_id=$(jq -r '.deployment_id' "$before")
after_id=$(jq -r '.deployment_id' "$after")
[[ "$before_id" == "$after_id" && -n "$before_id" ]] || {
  printf 'deployment identity changed\n' >&2
  exit 1
}

before_generation=$(jq -r '.installation_generation' "$before")
after_generation=$(jq -r '.installation_generation' "$after")
[[ $((after_generation - before_generation)) -eq delta ]] || {
  printf 'unexpected installation generation change\n' >&2
  exit 1
}

for field in postgres_identity redis_identity newapi_data_identity kuma_data_identity; do
  before_value=$(jq -r --arg field "$field" '.[$field]' "$before")
  after_value=$(jq -r --arg field "$field" '.[$field]' "$after")
  [[ "$before_value" == "$after_value" && "$before_value" != "null" ]] || {
    printf 'persistent fact changed: %s\n' "$field" >&2
    exit 1
  }
done

before_state_sha=$(jq -r '.state_sha256' "$before")
after_state_sha=$(jq -r '.state_sha256' "$after")
[[ "$before_state_sha" != "null" && -n "$before_state_sha" && "$after_state_sha" != "null" && -n "$after_state_sha" ]] || {
  printf 'missing state_sha256 snapshot field\n' >&2
  exit 1
}
# Credential activation updates data/state.json with the new installation
# generation. For non-rotation scenarios, the operational state must remain
# byte-for-byte stable.
if [[ "$delta" -eq 0 && "$before_state_sha" != "$after_state_sha" ]]; then
  printf 'persistent fact changed: state_sha256\n' >&2
  exit 1
fi

jq -e '.newapi_status_success == true and .postgres_select_1 == true and .redis_ping == true and .reporting_verified == true and (.public_probe_verified == null or (.public_probe_verified | type) == "boolean")' "$after" >/dev/null || {
  printf 'post-repair health/reporting assertions failed\n' >&2
  exit 1
}

if [[ "$expected_public_probe" != any ]]; then
  jq -e --argjson expected "$expected_public_probe" '.public_probe_verified == $expected' "$after" >/dev/null || {
    printf 'public probe assertion failed: expected %s\n' "$expected_public_probe" >&2
    exit 1
  }
fi

printf 'repair E2E assertions passed: deployment=%s generation=%s\n' "$after_id" "$after_generation"
