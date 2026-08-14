# meowai-deploy

Rust CLI for the MeowAI downstream New API onboard workflow.

## Build and run

```bash
cargo build
cargo test
cargo run -- doctor --skip-network
cargo run -- onboard --dry-run
```

`onboard` without a config file starts the interactive wizard. For automation, pass a TOML file with `--config FILE --non-interactive`; set `source_account_mode`, `source_username`, and `MEOWAI_DEPLOY_SOURCE_PASSWORD` for source account operations. Missing downstream passwords are read from `MEOWAI_DEPLOY_NEWAPI_ADMIN_PASSWORD` and `MEOWAI_DEPLOY_KUMA_ADMIN_PASSWORD`, or generated randomly and shown once in the terminal.

Running `meowai-deploy` or `cargo run` without a subcommand only prints help. It never starts the wizard implicitly.

## Doctor

```bash
meowai-deploy doctor
meowai-deploy doctor --skip-network --json
```

The command checks the supported architecture, Docker, Docker Compose, curl, target-directory permissions, disk space, and source reachability. A failed blocking check exits non-zero. Port selection and conflict handling belong to `onboard`.

## Installer

```bash
curl -fsSL https://<release-host>/install.sh | bash
```

The script downloads a release artifact and its SHA256 file, verifies the artifact, and installs it to `~/.local/bin` by default. Set `MEOWAI_DEPLOY_RELEASE_BASE_URL` or `MEOWAI_DEPLOY_INSTALL_DIR` to override those locations.
