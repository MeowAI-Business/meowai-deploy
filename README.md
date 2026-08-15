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

On Windows 10/11, the executable is a control client for a Linux host over OpenSSH. It does not
run Docker locally and `onboard --local` is rejected before source credentials are requested:

```powershell
meowai-deploy bootstrap
meowai-deploy doctor --ssh user@linux-host
meowai-deploy onboard --ssh user@linux-host
```

The same commands work from `cmd.exe`, PowerShell 5.1, and PowerShell 7. Use `--json` for
non-interactive diagnostics; the report has a versioned schema and never includes credentials.

## Image version

At the image step, `onboard` resolves the manifest currently published as `latest` in `ghcr.io/moorcorpa/new-api-outgap` and stores its immutable `sha256:` digest. A source commit that fails to build or push cannot become this default. Leave `image_ref` empty in a non-interactive configuration to use the same resolution; provide a commit SHA or digest only when intentionally pinning another build.

The default GHCR package is public, so normal installation and deployment do not require registry credentials. Automatic resolution fails explicitly when the package is unavailable and never falls back to an old embedded version.

When testing another private package, set `MEOWAI_DEPLOY_REGISTRY_USERNAME` and `MEOWAI_DEPLOY_REGISTRY_PASSWORD` together. The CLI uses them both to resolve the manifest and to run the initial target-side Compose pull with an isolated temporary Docker configuration. The temporary configuration is removed after the pull, and the credentials are not persisted in deployment configuration, state, or logs.

## Local state

CLI-owned state is stored in `~/.meowai-deploy` rather than the user-selected target installation directory. The directory is mode `0700`; `deployment.toml`, `state.json`, `credentials.env`, `session.json`, and `meowai-deploy.log` are mode `0600`. The log defaults to debug level and never intentionally includes passwords, tokens, or keys. Set `MEOWAI_DEPLOY_LOG` to override the file log filter. `session.json` contains the revocable source access/refresh session so later `sync` commands do not store or require the source password. Set `MEOWAI_DEPLOY_HOME` to an absolute path only when an isolated state directory is required.

Use `meowai-deploy clean` to remove the downstream containers, generated Compose files, and bind-mounted data while keeping the saved onboard form, generated administrator credentials, deployment state, and source login session. Run `meowai-deploy onboard` afterward and choose to resume the saved deployment. `rollback` additionally removes the saved deployment files from `~/.meowai-deploy`.

The target installation directory contains only Docker runtime artifacts: `docker-compose.yml`, a mode-`0600` `secrets.env` copy required by Compose, and persistent service data. The source account password is never written to either location.

## Doctor

```bash
meowai-deploy doctor
meowai-deploy doctor --json
```

The command checks the supported architecture, Docker, Docker Compose, curl, target-directory permissions, and disk space. It does not contact or validate any source URL; source connectivity and account authentication are checked during `onboard` immediately after those values are entered. A failed blocking check exits non-zero. Port selection and conflict handling belong to `onboard`.

On Windows, `doctor` checks the local state directory and OpenSSH Client only. Pass `--ssh
user@linux-host` to run the Docker, Compose, curl, architecture, directory, and disk checks on the
Linux target. A saved SSH configuration is not contacted unless `--ssh` is supplied explicitly.

## Installer

```bash
curl -fsSL https://raw.githubusercontent.com/MeowAI-Business/meowai-deploy/main/install.sh | bash
meowai-deploy doctor
meowai-deploy onboard
```

The script supports Linux and macOS on amd64 and arm64. It downloads the matching release archive and checksum list, verifies the selected archive, and installs it to `~/.local/bin` by default. If that directory is not already in `PATH`, the installer adds it to the current user's shell profile. Open a new terminal, or run the one-line `export PATH=...` command printed by the installer, before invoking `meowai-deploy` directly. Set `MEOWAI_DEPLOY_RELEASE_BASE_URL` or `MEOWAI_DEPLOY_INSTALL_DIR` to override those locations.

For Windows, download and run the native PowerShell 5.1/7 installer as the current user:

```powershell
$installer = Join-Path $env:TEMP 'meowai-deploy-install.ps1'
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/MeowAI-Business/meowai-deploy/main/install.ps1 -OutFile $installer
& $installer
```

From `cmd.exe`, invoke the same user-scoped installer with:

```bat
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%TEMP%\meowai-deploy-install.ps1"
```

It verifies `meowai-deploy-windows-amd64.zip`, installs to
`%LOCALAPPDATA%\Programs\meowai-deploy`, and updates the user-level `PATH` without requiring
administrator rights. Set `MEOWAI_DEPLOY_RELEASE_BASE_URL` or `MEOWAI_DEPLOY_INSTALL_DIR` before
running it to use a mirror or another user-owned directory.

## Version updates

```bash
meowai-deploy --version
meowai-deploy update --check
meowai-deploy update
meowai-deploy update --yes
```

Installed release builds check GitHub Releases at most once every 24 hours in an interactive terminal. A failed check never blocks `doctor`, `onboard`, `sync`, or `status`. The check timestamp is stored in `~/.meowai-deploy/update-check.json`; set `MEOWAI_DEPLOY_DISABLE_UPDATE_CHECK=1` to disable periodic checks.

Release tags use `v<version>` and must match the version in `Cargo.toml`. Pushing such a tag creates a GitHub Release with Linux and macOS archives for amd64 and arm64, a Windows amd64 ZIP containing `meowai-deploy.exe`, and a combined SHA256 checksum file. Publishing a Release manually runs the same build and uploads or replaces those assets. Windows self-update selects the `windows-amd64` asset and handles the `.exe` archive path.
