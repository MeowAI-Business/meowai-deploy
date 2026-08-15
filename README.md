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
curl -fsSL https://<release-host>/install.sh | bash
```

The script downloads a release artifact and its SHA256 file, verifies the artifact, and installs it to `~/.local/bin` by default. Set `MEOWAI_DEPLOY_RELEASE_BASE_URL` or `MEOWAI_DEPLOY_INSTALL_DIR` to override those locations.
