#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: build-upgrade-bundle.sh --input-dir DIR --output FILE \
  --release-id ID --deployment-schema N --migration-steps JSON \
  [--compose-changes JSON] [--env-changes JSON]

JSON arguments are arrays. The script never signs a release or reads a secret.
EOF
  exit 2
}

input_dir=
output=
release_id=
deployment_schema=
migration_steps=
compose_changes='[]'
env_changes='[]'

while (($#)); do
  case "$1" in
    --input-dir) input_dir=${2-}; shift 2 ;;
    --output) output=${2-}; shift 2 ;;
    --release-id) release_id=${2-}; shift 2 ;;
    --deployment-schema) deployment_schema=${2-}; shift 2 ;;
    --migration-steps) migration_steps=${2-}; shift 2 ;;
    --compose-changes) compose_changes=${2-}; shift 2 ;;
    --env-changes) env_changes=${2-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "$input_dir" && -d "$input_dir" && -n "$output" && -n "$release_id" && -n "$deployment_schema" && -n "$migration_steps" ]] || usage
command -v jq >/dev/null 2>&1 || { echo 'jq is required to build an upgrade bundle' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo 'tar is required to build an upgrade bundle' >&2; exit 1; }
command -v zstd >/dev/null 2>&1 || { echo 'zstd is required to build an upgrade bundle' >&2; exit 1; }

[[ "$release_id" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || { echo 'invalid release id' >&2; exit 1; }
[[ "$deployment_schema" =~ ^[1-9][0-9]*$ ]] || { echo 'invalid deployment schema' >&2; exit 1; }
jq -e 'type == "array" and all(.[]; type == "string")' <<<"$migration_steps" >/dev/null || { echo 'migration steps must be a JSON string array' >&2; exit 1; }
jq -e 'type == "array"' <<<"$compose_changes" >/dev/null || { echo 'compose changes must be a JSON array' >&2; exit 1; }
jq -e 'type == "array"' <<<"$env_changes" >/dev/null || { echo 'environment changes must be a JSON array' >&2; exit 1; }

declare -A modes=(
  [docker-compose.yml]=644
  [docker-compose.updater.yml]=644
  [secrets.env.patch]=600
  [downstream-credentials.env.patch]=600
  [meowai-deploy-upgrade-agent]=700
)
required=(docker-compose.yml meowai-deploy-upgrade-agent)

for name in "${required[@]}"; do
  [[ -f "$input_dir/$name" ]] || { echo "missing required bundle file: $name" >&2; exit 1; }
done

files=()
while IFS= read -r name; do files+=("$name"); done < <(find "$input_dir" -mindepth 1 -maxdepth 2 -type f -print | sed "s#^$input_dir/##" | LC_ALL=C sort)
[[ "${#files[@]}" -gt 0 && "${#files[@]}" -le 40 ]] || { echo 'bundle must contain 1..40 regular files' >&2; exit 1; }
for name in "${files[@]}"; do
  if [[ -z "${modes[$name]+x}" && ! "$name" =~ ^migrations/[A-Za-z0-9._-]{1,96}\.sh$ ]]; then
    echo "unallowlisted bundle file: $name" >&2
    exit 1
  fi
  actual_mode=$(stat -c '%a' "$input_dir/$name" 2>/dev/null || stat -f '%Lp' "$input_dir/$name")
  expected_mode=${modes[$name]:-700}
  [[ "$actual_mode" == "$expected_mode" ]] || { echo "invalid mode for $name: $actual_mode" >&2; exit 1; }
done

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$work_dir/input"
cp -Rp "$input_dir"/. "$work_dir/input/"

files_json='[]'
for name in "${files[@]}"; do
  hash=$(sha256sum "$work_dir/input/$name" | awk '{print $1}')
  mode=${modes[$name]:-700}
  mode_bits=$((8#$mode))
  files_json=$(jq -c --arg path "$name" --arg sha256 "$hash" --argjson mode "$mode_bits" '. + [{path:$path,sha256:$sha256,mode:$mode}]' <<<"$files_json")
done

jq -n \
  --arg release_id "$release_id" \
  --argjson deployment_schema "$deployment_schema" \
  --argjson migration_steps "$migration_steps" \
  --argjson files "$files_json" \
  --argjson compose_changes "$compose_changes" \
  --argjson env_changes "$env_changes" \
  '{bundle_schema:1,release_id:$release_id,deployment_schema:$deployment_schema,files:$files,migration_steps:$migration_steps,compose_changes:$compose_changes,env_changes:$env_changes}' \
  > "$work_dir/input/bundle-manifest.json"

tar -C "$work_dir/input" --format=ustar --owner=0 --group=0 --numeric-owner -cf - "${files[@]}" bundle-manifest.json \
  | zstd -T0 -q -f -o "$output"
chmod 600 "$output"
echo "built $output"
