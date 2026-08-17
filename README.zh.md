# meowai-deploy

[English](README.md) | 简体中文

`meowai-deploy` 是 MeowAI 下游 New API 站点的部署与运维工具。它可以在本机或远程服务器上部署 New API 和 Uptime Kuma，并从 MeowAI 源站同步分组、价格、Token 与状态监控。

## 环境要求

运行 CLI 的机器需要：

- amd64 或 arm64 架构的 Linux / macOS
- `curl`
- 本机部署时需要 Docker 和 Docker Compose 插件
- 远程部署时需要 `ssh` 和 `scp`

部署目标需要安装 Docker 和 Docker Compose 插件。目标用户应为 `root`、拥有免密 `sudo`，或同时具备 Docker 使用权限和部署目录写入权限。

## 快速开始

安装最新版本：

```bash
curl -fsSL https://raw.githubusercontent.com/MeowAI-Business/meowai-deploy/main/install.sh | bash
```

如果安装脚本修改了 `PATH`，请重新打开终端，或执行脚本最后输出的命令。然后检查环境并进入交互式部署：

```bash
meowai-deploy doctor
meowai-deploy onboard
```

向导会依次询问源站账号、部署目标、端口和管理员凭证，并在执行任何变更前展示完整部署计划。

通过 SSH 部署到远程服务器：

```bash
meowai-deploy onboard --ssh user@example.com
```

New API 默认监听 `3000` 端口，Uptime Kuma 默认监听 `3001` 端口；监听地址和端口都可以在向导中修改。

## 常用命令

| 命令 | 用途 |
| --- | --- |
| `meowai-deploy doctor` | 检查架构、Docker、Compose、`curl`、磁盘空间和目录权限 |
| `meowai-deploy onboard` | 新建部署，或继续上次未完成的部署 |
| `meowai-deploy status` | 查看部署、同步和容器状态 |
| `meowai-deploy sync` | 同步分组及 CLI 管理的下游资源 |
| `meowai-deploy sync --pricing` | 额外重新导入价格、Seedance 和市场配置 |
| `meowai-deploy update --check` | 检查 CLI 新版本 |
| `meowai-deploy update` | 更新到最新 CLI 版本 |
| `meowai-deploy update --channel canary` | 更新到当前平台最新的 Canary commit 构建 |
| `meowai-deploy logout` | 仅删除本地保存的源站登录会话 |

使用 `meowai-deploy <命令> --help` 查看完整参数。

默认更新通道为 `stable`，后台周期检查也只检查正式版本。Canary 必须通过 `--channel canary` 明确选择，不会自动安装。维护者可以在 `main` commit 末尾添加 `Canary-Build: true` trailer 生成 Canary prerelease；`Canary-Platforms` 省略或设为 `all` 时构建所有平台，也可以填写逗号分隔的平台子集。

## 自动化部署

先生成一份不包含密钥的配置模板：

```bash
meowai-deploy onboard --write-config deployment.toml
```

填写模板后，通过环境变量传入密码。建议先执行 dry run，再正式部署：

```bash
export MEOWAI_DEPLOY_SOURCE_PASSWORD='源站账号密码'
export MEOWAI_DEPLOY_NEWAPI_ADMIN_PASSWORD='New API 管理员密码'
export MEOWAI_DEPLOY_KUMA_ADMIN_PASSWORD='Uptime Kuma 管理员密码'

meowai-deploy onboard --config deployment.toml --non-interactive --dry-run
meowai-deploy onboard --config deployment.toml --non-interactive
```

源站密码必须提供。未设置下游管理员密码时，CLI 会自动生成，并只在终端显示一次。不要把密钥写入共享的 TOML 文件。

将 `image_ref` 留空，会自动解析当前 `latest` 对应的不可变镜像摘要。只有在明确需要固定其他构建时，才填写 commit SHA 或 `sha256:` 摘要。

## 数据与清理

CLI 自身的状态保存在 `~/.meowai-deploy`，包括部署配置、生成的凭证、可撤销的源站会话、运行状态和日志。敏感文件权限为 `0600`，源站账号密码不会被持久化。

你选择的目标部署目录只存放 Docker Compose 文件和服务持久化数据。

| 命令 | 下游容器与数据 | 本地部署状态 | 源站 Token 与状态密钥 |
| --- | --- | --- | --- |
| `meowai-deploy clean` | 删除 | 保留，可继续 onboard | 保留 |
| `meowai-deploy rollback` | 删除 | 删除 | 保留 |
| `meowai-deploy rollback --revoke-source` | 删除 | 删除 | 撤销 |

清理命令默认会要求确认。只有在无人值守的自动化流程中才建议追加 `--yes`。

## 排查问题

以 JSON 格式运行环境检查：

```bash
meowai-deploy doctor --json
```

详细日志位于 `~/.meowai-deploy/meowai-deploy.log`。可通过 `MEOWAI_DEPLOY_LOG` 调整日志过滤规则。版本检查失败不会阻塞部署或同步。

本地开发、私有镜像仓库、安装器定制和发版流程见 [DEVELOPMENT.md](DEVELOPMENT.md)。
