#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: webui-smoke.sh PATH_TO_BINARY}"
state_dir="$(mktemp -d "${TMPDIR:-/tmp}/meowai-webui-smoke.XXXXXX")"
log_file="$state_dir/server.log"
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$state_dir"
}
trap cleanup EXIT

MEOWAI_DEPLOY_HOME="$state_dir/home" "$binary" web --no-open >"$log_file" 2>&1 &
server_pid=$!

origin=""
for _ in {1..80}; do
  if [[ -s "$log_file" ]]; then
    url="$(sed -n 's/^WebUI 已启动：\(http:\/\/127\.0\.0\.1:[0-9]*\).*$/\1/p' "$log_file" | head -n1)"
    if [[ -n "$url" ]]; then
      origin="$url"
      break
    fi
  fi
  sleep 0.1
done

if [[ -z "$origin" ]]; then
  echo "WebUI did not announce a loopback URL" >&2
  cat "$log_file" >&2
  exit 1
fi

curl --fail --silent --show-error -H "Host: ${origin#http://}" "$origin/api/health" | grep -q '"status":"ok"'
curl --fail --silent --show-error -H "Host: ${origin#http://}" "$origin/" | grep -q '部署校准台'
