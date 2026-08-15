# meowai-deploy

English | [简体中文](README.zh.md)

`meowai-deploy` is the deployment and operations CLI for MeowAI downstream New API sites. It installs New API and Uptime Kuma on the local machine or a remote server, then synchronizes groups, pricing, tokens, and status monitoring from the MeowAI source site.

## Requirements

The machine running the CLI must have:

- Linux or macOS on amd64 or arm64
- `curl`
- Docker with the Compose plugin for local deployments
- `ssh` and `scp` for remote deployments

The deployment target must have Docker with the Compose plugin. Its user must be `root`, have passwordless `sudo`, or have permission to use Docker and write to the deployment directory.

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

## Common commands

| Command | Purpose |
| --- | --- |
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

For local development, registry overrides, installer customization, and the release process, see [DEVELOPMENT.md](DEVELOPMENT.md).
