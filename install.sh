#!/usr/bin/env bash
set -euo pipefail

# Override these variables when testing a private release mirror.
release_base_url="${MEOWAI_DEPLOY_RELEASE_BASE_URL:-https://github.com/MeowAI-Business/meowai-deploy/releases/latest/download}"
install_dir="${MEOWAI_DEPLOY_INSTALL_DIR:-${HOME}/.local/bin}"
artifact_name="meowai-deploy-linux-amd64"
temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/meowai-deploy.XXXXXX")"
trap 'rm -rf "${temporary_dir}"' EXIT

case "$(uname -s)" in
  Linux) ;;
  *) printf 'meowai-deploy currently supports Linux amd64 only.\n' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) printf 'meowai-deploy currently supports Linux amd64 only.\n' >&2; exit 1 ;;
esac
command -v curl >/dev/null 2>&1 || { printf 'curl is required.\n' >&2; exit 1; }

binary_path="${temporary_dir}/${artifact_name}"
checksum_path="${binary_path}.sha256"
curl --fail --silent --show-error --location "${release_base_url}/${artifact_name}" --output "${binary_path}"
curl --fail --silent --show-error --location "${release_base_url}/${artifact_name}.sha256" --output "${checksum_path}"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "${temporary_dir}" && sha256sum --check "${artifact_name}.sha256")
elif command -v shasum >/dev/null 2>&1; then
  expected_hash="$(awk '{print $1}' "${checksum_path}")"
  actual_hash="$(shasum -a 256 "${binary_path}" | awk '{print $1}')"
  [ "${expected_hash}" = "${actual_hash}" ] || { printf 'SHA256 verification failed.\n' >&2; exit 1; }
else
  printf 'sha256sum or shasum is required for release verification.\n' >&2
  exit 1
fi

mkdir -p "${install_dir}"
install -m 0755 "${binary_path}" "${install_dir}/meowai-deploy"
printf 'Installed meowai-deploy to %s/meowai-deploy\n' "${install_dir}"
printf 'Run: %s/meowai-deploy doctor\n' "${install_dir}"

