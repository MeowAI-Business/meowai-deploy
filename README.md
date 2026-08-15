# meowai-deploy

Rust CLI for the MeowAI downstream New API onboard workflow.

## Build and run

```bash
cargo build
cargo test
cargo run -- doctor
cargo run -- onboard --dry-run
```

`onboard` without a config file starts the interactive wizard. For automation, pass a TOML file with `--config FILE --non-interactive`; set `source_account_mode`, `source_username`, and `MEOWAI_DEPLOY_SOURCE_PASSWORD` for the first source login. Missing downstream passwords are read from `MEOWAI_DEPLOY_NEWAPI_ADMIN_PASSWORD` and `MEOWAI_DEPLOY_KUMA_ADMIN_PASSWORD`, or generated randomly and shown once in the terminal.

Running `meowai-deploy` or `cargo run` without a subcommand only prints help. It never starts the wizard implicitly.

## Image version

At the image step, `onboard` resolves the manifest currently published as `latest` in `ghcr.io/moorcorpa/new-api-outgap` and stores its immutable `sha256:` digest. A source commit that fails to build or push cannot become this default. Leave `image_ref` empty in a non-interactive configuration to use the same resolution; provide a commit SHA or digest only when intentionally pinning another build.

The GHCR package must permit the target host to pull it. Automatic resolution fails explicitly when the package is private or unavailable and never falls back to an old embedded version.

## Local state

CLI-owned state is stored in `~/.meowai-deploy` rather than the user-selected target installation directory. The directory is mode `0700`; `deployment.toml`, `state.json`, `credentials.env`, and `session.json` are mode `0600`. `session.json` contains the revocable source access/refresh session so later `sync` commands do not store or require the source password. Set `MEOWAI_DEPLOY_HOME` to an absolute path only when an isolated state directory is required.

The target installation directory contains only Docker runtime artifacts: `docker-compose.yml`, a mode-`0600` `secrets.env` copy required by Compose, and persistent service data. The source account password is never written to either location.

## Doctor

```bash
meowai-deploy doctor
meowai-deploy doctor --json
```

The command checks the supported architecture, Docker, Docker Compose, curl, target-directory permissions, and disk space. It does not contact or validate any source URL; source connectivity and account authentication are checked during `onboard` immediately after those values are entered. A failed blocking check exits non-zero. Port selection and conflict handling belong to `onboard`.

## Installer

```bash
curl -fsSL https://raw.githubusercontent.com/MeowAI-Business/meowai-deploy/main/install.sh | bash
```

The script downloads the latest Linux amd64 release archive and checksum list, verifies the archive, and installs it to `~/.local/bin` by default. Set `MEOWAI_DEPLOY_RELEASE_BASE_URL` or `MEOWAI_DEPLOY_INSTALL_DIR` to override those locations.

## Version updates

```bash
meowai-deploy --version
meowai-deploy update --check
meowai-deploy update
meowai-deploy update --yes
```

Installed release builds check GitHub Releases at most once every 24 hours in an interactive terminal. A failed check never blocks `doctor`, `onboard`, `sync`, or `status`. The check timestamp is stored in `~/.meowai-deploy/update-check.json`; set `MEOWAI_DEPLOY_DISABLE_UPDATE_CHECK=1` to disable periodic checks.

Release tags use `v<version>` and must match the version in `Cargo.toml`. Pushing such a tag creates a GitHub Release with the Linux amd64 archive and SHA256 checksum. Publishing a Release manually runs the same build and uploads or replaces those assets.
