#!/usr/bin/env bash
set -euo pipefail

# Override these variables when testing a private release mirror.
release_base_url="${MEOWAI_DEPLOY_RELEASE_BASE_URL:-https://github.com/MeowAI-Business/meowai-deploy/releases/latest/download}"
install_dir="${MEOWAI_DEPLOY_INSTALL_DIR:-${HOME}/.local/bin}"
checksum_name="checksums-sha256.txt"
temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/meowai-deploy.XXXXXX")"
trap 'rm -rf "${temporary_dir}"' EXIT

case "$(uname -s)" in
  Linux) target_os="linux" ;;
  Darwin) target_os="macos" ;;
  *) printf 'meowai-deploy supports Linux and macOS only.\n' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) target_arch="amd64" ;;
  aarch64|arm64) target_arch="arm64" ;;
  *) printf 'meowai-deploy supports amd64 and arm64 only.\n' >&2; exit 1 ;;
esac
artifact_name="meowai-deploy-${target_os}-${target_arch}.tar.gz"
command -v curl >/dev/null 2>&1 || { printf 'curl is required.\n' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { printf 'tar is required.\n' >&2; exit 1; }

archive_path="${temporary_dir}/${artifact_name}"
checksum_path="${temporary_dir}/${checksum_name}"
curl --fail --silent --show-error --location "${release_base_url}/${artifact_name}" --output "${archive_path}"
curl --fail --silent --show-error --location "${release_base_url}/${checksum_name}" --output "${checksum_path}"

expected_hash="$(awk -v artifact="${artifact_name}" '$2 == artifact {print $1}' "${checksum_path}")"
[ -n "${expected_hash}" ] || { printf 'Release checksum does not contain %s.\n' "${artifact_name}" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual_hash="$(sha256sum "${archive_path}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual_hash="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
else
  printf 'sha256sum or shasum is required for release verification.\n' >&2
  exit 1
fi
[ "${expected_hash}" = "${actual_hash}" ] || { printf 'SHA256 verification failed.\n' >&2; exit 1; }

tar -xzf "${archive_path}" -C "${temporary_dir}" meowai-deploy
mkdir -p "${install_dir}"
install -m 0755 "${temporary_dir}/meowai-deploy" "${install_dir}/meowai-deploy"
printf 'Installed meowai-deploy to %s/meowai-deploy\n' "${install_dir}"

case ":${PATH}:" in
  *":${install_dir}:"*) ;;
  *)
    if [ "${install_dir}" = "${HOME}/.local/bin" ]; then
      case "${SHELL:-}" in
        */zsh) shell_profile="${HOME}/.zshrc" ;;
        */bash) shell_profile="${HOME}/.bashrc" ;;
        *) shell_profile="${HOME}/.profile" ;;
      esac
      path_line='export PATH="$HOME/.local/bin:$PATH"'
      if [ ! -f "${shell_profile}" ] || ! grep -Fqx "${path_line}" "${shell_profile}"; then
        printf '\n# Added by the meowai-deploy installer.\n%s\n' "${path_line}" >> "${shell_profile}"
      fi
      printf 'Added ~/.local/bin to PATH in %s\n' "${shell_profile}"
      printf 'Open a new terminal or run: export PATH="$HOME/.local/bin:$PATH"\n'
    else
      printf 'Add %s to PATH before running meowai-deploy.\n' "${install_dir}"
    fi
    ;;
esac

printf 'Run: meowai-deploy doctor\n'
printf 'Then: meowai-deploy onboard\n'
