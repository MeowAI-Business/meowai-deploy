# meowai-deploy

English | [简体中文](README.zh.md)

`meowai-deploy` is the deployment and operations CLI for MeowAI downstream New API sites. It installs New API and Uptime Kuma on the local machine or a remote server, then synchronizes groups, pricing, tokens, and status monitoring from the MeowAI source site.

## Requirements

The machine running the CLI must have:

- Linux or macOS on amd64 or arm64
- Windows 10/11 on amd64 or arm64 when controlling a Linux target over OpenSSH
- `curl`
- Docker with the Compose plugin for local deployments
- `ssh` and `scp` for remote deployments

The deployment target must have Docker with the Compose plugin. Its user must be `root`, have passwordless `sudo`, or have permission to use Docker and write to the deployment directory.

On Windows, the executable is a control client for a Linux host. It does not run Docker locally, and `onboard --local` is rejected before source credentials are requested. The same commands work from `cmd.exe`, PowerShell 5.1, and PowerShell 7:

```powershell
meowai-deploy bootstrap
meowai-deploy doctor --ssh user@linux-host
meowai-deploy onboard --ssh user@linux-host
```

Use `--json` for non-interactive diagnostics. The report has a versioned schema and never includes credentials.

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

On Windows, `doctor` checks the local state directory and OpenSSH Client only. Pass `--ssh user@linux-host` to run the Docker, Compose, curl, architecture, directory, and disk checks on the Linux target. A saved SSH configuration is not contacted unless `--ssh` is supplied explicitly.

## Quick start

Install the latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/MeowAI-Business/meowai-deploy/main/install.sh | bash
```

If the installer updates your `PATH`, open a new terminal or run the command it prints. Then check the environment and start the interactive setup:

```bash
meowai-deploy doctor
meowai-deploy onboard
```

The setup asks for the source-site account, deployment target, ports, and administrator credentials. It displays a complete plan before making changes.

To deploy over SSH instead of to the current machine:

```bash
meowai-deploy onboard --ssh user@example.com
```

By default, New API listens on port `3000` and Uptime Kuma on port `3001`. Both addresses and ports can be changed during setup.

### Windows installer

Download and run the native PowerShell 5.1/7 installer as the current user:

```powershell
$installer = Join-Path $env:TEMP 'meowai-deploy-install.ps1'
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/MeowAI-Business/meowai-deploy/main/install.ps1 -OutFile $installer
& $installer
```

From `cmd.exe`, invoke the same user-scoped installer with:

```bat
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%TEMP%\\meowai-deploy-install.ps1"
```

It detects amd64 or arm64 Windows, verifies the matching `meowai-deploy-windows-<arch>.zip`, and installs a self-contained executable that does not require `VCRUNTIME140.dll`. It installs to `%LOCALAPPDATA%\\Programs\\meowai-deploy` and updates the user-level `PATH` without requiring administrator rights. Set `MEOWAI_DEPLOY_RELEASE_BASE_URL` or `MEOWAI_DEPLOY_INSTALL_DIR` before running it to use a mirror or another user-owned directory.

## Version updates

```bash
meowai-deploy --version
meowai-deploy update --check
meowai-deploy update
meowai-deploy update --channel canary --check
meowai-deploy update --channel canary --yes
```

Installed release builds check stable GitHub Releases at most once every 24 hours in an interactive terminal. Canary is opt-in and never used by the periodic check. A failed check never blocks `doctor`, `onboard`, `sync`, or `status`. The check timestamp is stored in `~/.meowai-deploy/update-check.json`; set `MEOWAI_DEPLOY_DISABLE_UPDATE_CHECK=1` to disable periodic checks.

## Common commands

| Command | Purpose |
| --- | --- |
| `meowai-deploy bootstrap` | Verify or install the local Windows OpenSSH Client capability |
| `meowai-deploy doctor` | Check architecture, Docker, Compose, `curl`, disk space, and directory permissions |
| `meowai-deploy onboard` | Create or resume an interactive deployment |
| `meowai-deploy status` | Show deployment, synchronization, and container status |
| `meowai-deploy sync` | Synchronize groups and managed downstream resources |
| `meowai-deploy sync --pricing` | Also re-import pricing, Seedance, and marketplace settings |
| `meowai-deploy update --check` | Check whether a newer CLI release is available |
| `meowai-deploy update` | Install the latest CLI release |
| `meowai-deploy logout` | Delete the saved source login session only |

Run `meowai-deploy <command> --help` for all options.

## Automated deployment

Generate a non-secret configuration template:

```bash
meowai-deploy onboard --write-config deployment.toml
```

Fill in the template, provide secrets through environment variables, and validate the plan before deploying:

```bash
export MEOWAI_DEPLOY_SOURCE_PASSWORD='source-account-password'
export MEOWAI_DEPLOY_NEWAPI_ADMIN_PASSWORD='new-api-admin-password'
export MEOWAI_DEPLOY_KUMA_ADMIN_PASSWORD='kuma-admin-password'

meowai-deploy onboard --config deployment.toml --non-interactive --dry-run
meowai-deploy onboard --config deployment.toml --non-interactive
```

The source password is required. If either downstream administrator password is omitted, the CLI generates it and displays it once. Do not store secrets in a shared TOML file.

Leave `image_ref` empty to resolve the immutable digest currently published as `latest`. Set a commit SHA or `sha256:` digest only when deliberately pinning another build.

## Data and removal

CLI state is stored in `~/.meowai-deploy`. This includes deployment configuration, generated credentials, the revocable source session, state, and logs. Sensitive files are created with mode `0600`; the source account password is never persisted.

The selected target directory contains Docker Compose files and persistent service data.

| Command | Downstream containers and data | Saved local deployment state | Source tokens and status key |
| --- | --- | --- | --- |
| `meowai-deploy clean` | Removed | Kept, so onboarding can resume | Kept |
| `meowai-deploy rollback` | Removed | Removed | Kept |
| `meowai-deploy rollback --revoke-source` | Removed | Removed | Revoked |

Removal commands ask for confirmation. Use `--yes` only in unattended automation.

## Troubleshooting

Run the environment check in a machine-readable form:

```bash
meowai-deploy doctor --json
```

Detailed logs are written to `~/.meowai-deploy/meowai-deploy.log`. Set `MEOWAI_DEPLOY_LOG` to change the log filter. An update check failure never blocks deployment or synchronization.

Release tags use `v<version>` and must match the version in `Cargo.toml`. Pushing such a tag creates a GitHub Release with Linux, macOS, and Windows archives for amd64 and arm64 plus a combined SHA256 checksum file. Publishing a Release manually runs the same build and uploads or replaces those assets. Windows self-update selects the native `windows-amd64` or `windows-arm64` asset and handles the `.exe` archive path.

### Canary builds

Add these Git trailers to a commit on `main` when it should produce an opt-in commit build after the normal CI passes:

```text
Canary-Build: true
Canary-Platforms: all
```

`Canary-Platforms` defaults to `all` and accepts a comma-separated subset of `linux-amd64`, `linux-arm64`, `macos-amd64`, `macos-arm64`, `windows-amd64`, and `windows-arm64`. The Canary workflow publishes a prerelease tag containing the base version, UTC timestamp, and source commit SHA, plus platform archives, checksums, and a manifest. Canary updates are never selected unless `--channel canary` is passed.

For local development, registry overrides, installer customization, and the release process, see [DEVELOPMENT.md](DEVELOPMENT.md).
