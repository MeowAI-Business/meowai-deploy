# Development

This document covers contributor and advanced deployment details. End-user instructions live in [README.md](README.md) and [README.zh.md](README.zh.md).

## Build and test

```bash
cargo build
cargo test
cargo run -- doctor
cargo run -- onboard --dry-run
```

Running `cargo run` without a subcommand prints help; it does not start the setup wizard.

## Image resolution

During onboarding, the CLI resolves the manifest currently published as `latest` in `ghcr.io/moorcorpa/new-api-outgap` and saves its immutable `sha256:` digest. A source commit that fails to build or publish therefore cannot become the default deployment image.

The default GHCR package is public and requires no registry credentials. Resolution fails explicitly when the package is unavailable and never falls back to an embedded version.

For a private package, set both variables below:

```bash
export MEOWAI_DEPLOY_REGISTRY_USERNAME='username'
export MEOWAI_DEPLOY_REGISTRY_PASSWORD='password'
```

The CLI uses an isolated temporary Docker configuration to resolve and pull the image. It removes that configuration after the pull and does not persist registry credentials in deployment state or logs.

## State overrides

Set `MEOWAI_DEPLOY_HOME` to an absolute path to use an isolated CLI state directory. Set `MEOWAI_DEPLOY_LOG` to override the default file log filter. Set `MEOWAI_DEPLOY_DISABLE_UPDATE_CHECK=1` to disable the periodic release check.

## Installer overrides

The installer supports Linux and macOS on amd64 and arm64. Linux release binaries are statically linked with musl and do not depend on the target server's glibc version. It verifies the selected release archive against `checksums-sha256.txt` before installing it to `~/.local/bin`.

Use `MEOWAI_DEPLOY_RELEASE_BASE_URL` to test another release host and `MEOWAI_DEPLOY_INSTALL_DIR` to change the installation directory.

## Release process

Release tags use `v<version>` and must match the version in `Cargo.toml`. Pushing a tag builds Linux and macOS archives for amd64 and arm64, creates a combined SHA256 checksum file, and publishes a GitHub Release. Publishing a Release manually runs the same build and uploads or replaces its assets.

To publish a commit-based Canary build, add `Canary-Build: true` to the commit trailers. `Canary-Platforms` is optional and defaults to `all`; otherwise use a comma-separated subset of the supported release targets. The Canary workflow starts only after the ordinary `CI` workflow succeeds, builds the selected platforms, and creates the prerelease tag only after all selected archives pass.
