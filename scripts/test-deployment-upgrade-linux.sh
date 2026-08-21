#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_root=$(mktemp -d)

for platform in linux/amd64 linux/arm64; do
  arch=${platform#linux/}
  case "$arch" in
    amd64) rust_target=x86_64-unknown-linux-musl ;;
    arm64) rust_target=aarch64-unknown-linux-musl ;;
    *) exit 1 ;;
  esac
  mkdir -p "$output_root/$arch"
  docker run --rm --platform "$platform" \
    -v "$repo_root:/src:ro" \
    -v "$output_root/$arch:/out" \
    -e RUST_TARGET="$rust_target" \
    -e TARGET_ARCH="$arch" \
    rust:bookworm \
    bash -euo pipefail -c '
      apt-get update >/dev/null
      apt-get install --yes binutils jq musl-tools zstd >/dev/null
      mkdir -p /work
      tar -C /src --anchored --exclude=./.git --exclude=./target --exclude=./webui/node_modules -cf - . | tar -C /work -xf -
      cd /work
      mkdir -p /run/systemd/system
      cargo test --locked \
        target::upgrade_agent::e2e_tests::complete_apply_covers_success_failures_data_rollback_and_recovery \
        -- --exact --test-threads=1
      rustup target add "$RUST_TARGET"
      cargo build --release --locked --target "$RUST_TARGET"
      binary="target/$RUST_TARGET/release/meowai-deploy"
      if readelf -l "$binary" | grep -q "Requesting program interpreter"; then
        echo "upgrade agent is dynamically linked" >&2
        exit 1
      fi
      mkdir -p /tmp/bundle-input
      install -m 0644 upgrade-bundle/docker-compose.yml /tmp/bundle-input/docker-compose.yml
      install -m 0700 "$binary" /tmp/bundle-input/meowai-deploy-upgrade-agent
      mkdir -p /tmp/bundle-input/migrations
      printf "#!/bin/sh\nexit 0\n" > /tmp/bundle-input/migrations/data-1-to-2.sh
      chmod 0700 /tmp/bundle-input/migrations/data-1-to-2.sh
      scripts/build-upgrade-bundle.sh \
        --input-dir /tmp/bundle-input \
        --output "/out/meowai-deploy-upgrade-linux-$TARGET_ARCH.tar.zst" \
        --release-id rel_linux_smoke \
        --deployment-schema 2 \
        --migration-steps "[\"deployment-1-to-2\",\"data-1-to-2\"]"
      (cd /out && sha256sum "meowai-deploy-upgrade-linux-$TARGET_ARCH.tar.zst" > SHA256SUMS)
      tar --zstd -tf "/out/meowai-deploy-upgrade-linux-$TARGET_ARCH.tar.zst" | grep -qx "migrations/data-1-to-2.sh"
      tar --zstd -xOf "/out/meowai-deploy-upgrade-linux-$TARGET_ARCH.tar.zst" bundle-manifest.json \
        | jq -e "all(.files[]; if .path == \"docker-compose.yml\" then .mode == 420 elif .path == \"meowai-deploy-upgrade-agent\" then .mode == 448 elif (.path | startswith(\"migrations/\")) then .mode == 448 else false end)" >/dev/null
    '
done

for arch in amd64 arm64; do
  test -s "$output_root/$arch/meowai-deploy-upgrade-linux-$arch.tar.zst"
  (cd "$output_root/$arch" && sha256sum -c SHA256SUMS)
done

printf 'linux deployment-upgrade bundles passed for amd64 and arm64\n'
