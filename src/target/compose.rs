use std::collections::BTreeMap;

use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

use crate::{
    config::{DEFAULT_IMAGE, DeploymentConfig},
    error::{AppError, Result},
    registry::credentials_from_env,
    security::{random_secret, validate_env_value},
    state::{DOWNSTREAM_CLEANUP_PHASE, DeploymentState},
    storage::{self, CONFIG_FILE, CREDENTIALS_FILE, STATE_FILE},
    target::TargetExecutor,
};

const TARGET_SECRETS_FILE: &str = "secrets.env";
const COMPOSE_FILE: &str = "docker-compose.yml";
const KUMA_IMAGE: &str = "louislam/uptime-kuma:2.5.0";

#[derive(Clone, Debug)]
pub struct DeploymentSecrets {
    pub postgres_password: SecretString,
    pub redis_password: SecretString,
    pub session_secret: SecretString,
    pub newapi_admin_password: SecretString,
    pub kuma_admin_password: SecretString,
    pub public_status_source_key: SecretString,
}

impl DeploymentSecrets {
    fn create(config: &DeploymentConfig, status_key: &SecretString) -> Result<Self> {
        let newapi_admin_password = config.newapi_admin_password.as_deref().ok_or_else(|| {
            AppError::State("New API administrator password was not resolved".to_owned())
        })?;
        let kuma_admin_password = config.kuma_admin_password.as_deref().ok_or_else(|| {
            AppError::State("Uptime Kuma administrator password was not resolved".to_owned())
        })?;
        let secrets = Self {
            postgres_password: SecretString::from(random_secret(48)),
            redis_password: SecretString::from(random_secret(48)),
            session_secret: SecretString::from(random_secret(64)),
            newapi_admin_password: SecretString::from(newapi_admin_password.to_owned()),
            kuma_admin_password: SecretString::from(kuma_admin_password.to_owned()),
            public_status_source_key: status_key.clone(),
        };
        secrets.validate()?;
        Ok(secrets)
    }

    pub(crate) fn parse(content: &[u8]) -> Result<Self> {
        let content = std::str::from_utf8(content)
            .map_err(|_| AppError::State("secrets.env is not UTF-8".to_owned()))?;
        let mut values = BTreeMap::new();
        for (index, line) in content.lines().enumerate() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                AppError::State(format!("invalid secrets.env line {}", index + 1))
            })?;
            if values.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(AppError::State(format!("duplicate secrets.env key {key}")));
            }
        }
        let take = |name: &str| -> Result<SecretString> {
            values
                .get(name)
                .filter(|value| !value.is_empty())
                .cloned()
                .map(SecretString::from)
                .ok_or_else(|| AppError::State(format!("secrets.env is missing {name}")))
        };
        let secrets = Self {
            postgres_password: take("POSTGRES_PASSWORD")?,
            redis_password: take("REDIS_PASSWORD")?,
            session_secret: take("SESSION_SECRET")?,
            newapi_admin_password: take("NEWAPI_ADMIN_PASSWORD")?,
            kuma_admin_password: take("KUMA_ADMIN_PASSWORD")?,
            public_status_source_key: take("PUBLIC_STATUS_SOURCE_KEY")?,
        };
        secrets.validate()?;
        Ok(secrets)
    }

    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("POSTGRES_PASSWORD", &self.postgres_password),
            ("REDIS_PASSWORD", &self.redis_password),
            ("SESSION_SECRET", &self.session_secret),
            ("NEWAPI_ADMIN_PASSWORD", &self.newapi_admin_password),
            ("KUMA_ADMIN_PASSWORD", &self.kuma_admin_password),
            ("PUBLIC_STATUS_SOURCE_KEY", &self.public_status_source_key),
        ] {
            validate_env_value(name, value.expose_secret())?;
        }
        Ok(())
    }

    fn render(&self) -> String {
        [
            ("POSTGRES_PASSWORD", &self.postgres_password),
            ("REDIS_PASSWORD", &self.redis_password),
            ("SESSION_SECRET", &self.session_secret),
            ("NEWAPI_ADMIN_PASSWORD", &self.newapi_admin_password),
            ("KUMA_ADMIN_PASSWORD", &self.kuma_admin_password),
            ("PUBLIC_STATUS_SOURCE_KEY", &self.public_status_source_key),
        ]
        .into_iter()
        .map(|(name, value)| format!("{name}={}", value.expose_secret()))
        .collect::<Vec<_>>()
        .join("\n")
            + "\n"
    }
}

#[derive(Clone, Debug)]
pub struct DeploymentRuntime {
    pub executor: TargetExecutor,
    pub state: DeploymentState,
    pub secrets: DeploymentSecrets,
    pub container_source_url: String,
    pub credentials_should_display: bool,
}

impl DeploymentRuntime {
    pub fn prepare(
        config: &DeploymentConfig,
        source_user_id: i64,
        source_group_sha256: &str,
        status_key_id: i64,
        issued_status_key: Option<&SecretString>,
    ) -> Result<Self> {
        let executor = TargetExecutor::new(config.target.clone(), config.directory.clone());
        executor.prepare()?;
        let target_fingerprint = executor.fingerprint()?;
        let existing_state = load_state()?;
        let existing_secrets = storage::read(CREDENTIALS_FILE)?
            .map(|content| DeploymentSecrets::parse(&content))
            .transpose()?;

        let was_existing = existing_state.is_some();
        let mut state = match existing_state {
            Some(state) => {
                validate_existing_state(config, &target_fingerprint, &state)?;
                state
            }
            None => {
                let newapi_port = executor.allocate_port(config.newapi_port, &[])?;
                let kuma_port = executor.allocate_port(config.kuma_port, &[newapi_port])?;
                DeploymentState {
                    schema_version: 1,
                    deployment_id: config.deployment_id(),
                    target_fingerprint: target_fingerprint.clone(),
                    container_name: config.container_name.clone(),
                    directory: config.directory.to_string_lossy().into_owned(),
                    newapi_port,
                    kuma_port,
                    image: config.image.clone(),
                    image_ref: config.image_ref.clone(),
                    image_digest: String::new(),
                    source_user_id,
                    source_group_sha256: source_group_sha256.to_owned(),
                    status_key_id,
                    manifest_sha256: String::new(),
                    pricing_sha256: BTreeMap::new(),
                    channels: BTreeMap::new(),
                    kuma_monitors: BTreeMap::new(),
                    phases: BTreeMap::new(),
                    last_sync_at: 0,
                    last_sync_success: false,
                    operation: None,
                }
            }
        };

        if source_user_id != 0
            && state.source_user_id != 0
            && state.source_user_id != source_user_id
        {
            return Err(AppError::State(format!(
                "当前部署属于源站用户 {}，与本次登录用户 {} 不一致",
                state.source_user_id, source_user_id
            )));
        }
        if source_user_id != 0 {
            state.source_user_id = source_user_id;
        }
        if !source_group_sha256.is_empty() {
            state.source_group_sha256 = source_group_sha256.to_owned();
        }
        if status_key_id != 0 {
            state.status_key_id = status_key_id;
        }

        let secrets = match (existing_secrets, issued_status_key) {
            (Some(mut secrets), Some(key)) => {
                secrets.public_status_source_key = key.clone();
                secrets.validate()?;
                secrets
            }
            (Some(secrets), None) => secrets,
            (None, Some(key)) => DeploymentSecrets::create(config, key)?,
            (None, None) => {
                return Err(AppError::State(
                    "源站已存在公共状态密钥，但本机没有保存密钥内容，无法继续部署；请重新运行 onboard，并按提示生成新的公共状态密钥"
                        .to_owned(),
                ));
            }
        };
        let container_source_url = container_source_url(&config.source_url)?;
        let credentials_should_display = !was_existing
            || state
                .phases
                .get("base_stack")
                .is_none_or(|phase| phase.status != "DONE");
        let runtime = Self {
            executor,
            state,
            secrets,
            container_source_url,
            credentials_should_display,
        };
        runtime.persist(config)?;
        Ok(runtime)
    }

    pub fn deploy_base_stack<F>(&mut self, config: &DeploymentConfig, mut progress: F) -> Result<()>
    where
        F: FnMut(&str),
    {
        self.state.phases.remove(DOWNSTREAM_CLEANUP_PHASE);
        self.state.mark_phase(
            "base_stack",
            "IN_PROGRESS",
            "rendering and starting containers",
        );
        self.persist_state()?;

        let result = (|| {
            progress("正在写入 Docker Compose 部署配置");
            let compose = render_compose(config, self)?;
            self.executor
                .write_file(COMPOSE_FILE, compose.as_bytes(), false)?;
            if let Some(credentials) = credentials_from_env()? {
                progress("正在认证镜像仓库并拉取 New API 镜像");
                let registry = config.image.split('/').next().ok_or_else(|| {
                    AppError::InvalidConfig(
                        "image must include a registry and repository".to_owned(),
                    )
                })?;
                self.executor.pull_image_with_registry_credentials(
                    &image_reference(&config.image, &config.image_ref),
                    registry,
                    &credentials,
                )?;
            }
            progress("正在创建并启动 PostgreSQL、Redis 和 New API 容器");
            self.executor.compose(
                &config.container_name,
                &["up", "-d", "postgres", "redis", "new-api"],
            )?;
            progress("容器已启动，正在检查服务健康状态");
            self.wait_for_base_stack(config, &mut progress)?;
            let image_output = self.executor.run_script(&format!(
                "docker inspect --format '{{{{.Image}}}}' {}",
                config.container_name
            ))?;
            self.state.image_digest = String::from_utf8_lossy(&image_output.stdout)
                .trim()
                .to_owned();
            Ok::<(), AppError>(())
        })();

        match result {
            Ok(()) => {
                self.state.mark_phase(
                    "base_stack",
                    "DONE",
                    "New API, PostgreSQL and Redis are healthy",
                );
                self.persist_state()
            }
            Err(error) => {
                self.state
                    .mark_phase("base_stack", "FAILED", error.to_string());
                let _ = self.persist_state();
                Err(error)
            }
        }
    }

    pub fn deploy_kuma<F>(&mut self, config: &DeploymentConfig, mut progress: F) -> Result<()>
    where
        F: FnMut(&str),
    {
        self.state.mark_phase(
            "kuma_stack",
            "IN_PROGRESS",
            "starting the isolated Uptime Kuma container",
        );
        self.persist_state()?;
        let result = (|| {
            progress("正在写入 Uptime Kuma 部署配置");
            let compose = render_compose(config, self)?;
            self.executor
                .write_file(COMPOSE_FILE, compose.as_bytes(), false)?;
            progress("正在创建并启动 Uptime Kuma 容器");
            self.executor
                .compose(&config.container_name, &["up", "-d", "uptime-kuma"])?;
            progress("Uptime Kuma 容器已启动，正在检查服务状态");
            self.wait_for_kuma(config, &mut progress)
        })();
        match result {
            Ok(()) => {
                self.state.mark_phase(
                    "kuma_stack",
                    "DONE",
                    "Uptime Kuma 2.5.0 is accepting HTTP connections",
                );
                self.persist_state()
            }
            Err(error) => {
                self.state
                    .mark_phase("kuma_stack", "FAILED", error.to_string());
                let _ = self.persist_state();
                Err(error)
            }
        }
    }

    pub fn persist(&self, config: &DeploymentConfig) -> Result<()> {
        let config_toml = toml::to_string_pretty(config)
            .map_err(|error| AppError::State(format!("serialize deployment config: {error}")))?;
        storage::write(CONFIG_FILE, config_toml.as_bytes())?;
        storage::write(CREDENTIALS_FILE, self.secrets.render().as_bytes())?;
        self.executor
            .write_file(TARGET_SECRETS_FILE, self.secrets.render().as_bytes(), true)?;
        self.persist_state()
    }

    pub fn persist_state(&self) -> Result<()> {
        let state = serde_json::to_vec_pretty(&self.state)
            .map_err(|error| AppError::State(format!("serialize state.json: {error}")))?;
        storage::write(STATE_FILE, &state)
    }

    fn wait_for_base_stack<F>(&self, config: &DeploymentConfig, progress: &mut F) -> Result<()>
    where
        F: FnMut(&str),
    {
        let postgres_container = format!("{}-postgres", config.container_name);
        let redis_container = format!("{}-redis", config.container_name);
        let script = format!(
            r#"set -eu
newapi={newapi}
pg_container={pg}
redis_container={redis}
last=''
for attempt in $(seq 1 120); do
  pg=$(docker inspect --format '{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}}' "$pg_container" 2>/dev/null || true)
  redis=$(docker inspect --format '{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}}' "$redis_container" 2>/dev/null || true)
  new_state=$(docker inspect --format '{{{{.State.Status}}}}' "$newapi" 2>/dev/null || true)
  new_health=$(docker inspect --format '{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}}' "$newapi" 2>/dev/null || true)
  new_restarts=$(docker inspect --format '{{{{.RestartCount}}}}' "$newapi" 2>/dev/null || true)
  new_state=${{new_state:-missing}}
  new_health=${{new_health:-none}}
  new_restarts=${{new_restarts:-0}}
  signature="$pg|$redis|$new_state|$new_health|$new_restarts"
  if [ "$signature" != "$last" ] || [ $((attempt % 10)) -eq 1 ]; then
    elapsed=$((attempt - 1))
    printf '已等待 %ss · PostgreSQL %s · Redis %s · New API %s/%s · 重启 %s 次\n' "$elapsed" "$pg" "$redis" "$new_state" "$new_health" "$new_restarts"
    last=$signature
  fi
  if [ "$pg" = healthy ] && [ "$redis" = healthy ] && curl --fail --silent --max-time 2 http://127.0.0.1:{port}/api/status >/dev/null; then
    printf 'PostgreSQL、Redis 和 New API 均已就绪\n'
    exit 0
  fi
  if [ "$new_state" = restarting ] && [ "$new_restarts" -ge 2 ]; then
    echo "New API 容器已连续重启 $new_restarts 次，停止等待" >&2
    docker inspect --format '容器状态={{{{.State.Status}}}}，退出码={{{{.State.ExitCode}}}}，错误={{{{.State.Error}}}}' "$newapi" >&2 || true
    docker logs --tail 24 "$newapi" 2>&1 | tail -n 16 >&2 || true
    exit 1
  fi
  if [ "$new_state" = exited ] || [ "$new_state" = dead ] || [ "$new_health" = unhealthy ]; then
    echo "New API 容器状态异常：$new_state/$new_health" >&2
    docker inspect --format '容器状态={{{{.State.Status}}}}，退出码={{{{.State.ExitCode}}}}，错误={{{{.State.Error}}}}' "$newapi" >&2 || true
    docker logs --tail 24 "$newapi" 2>&1 | tail -n 16 >&2 || true
    exit 1
  fi
  sleep 1
done
echo '等待基础服务就绪超时（120 秒）' >&2
docker compose --env-file secrets.env -p {project} ps >&2 || true
docker logs --tail 24 "$newapi" 2>&1 | tail -n 16 >&2 || true
exit 1"#,
            newapi = config.container_name,
            pg = postgres_container,
            redis = redis_container,
            port = self.state.newapi_port,
            project = config.container_name,
        );
        self.executor.run_script_streaming(
            &format!(
                "cd {}\n{}",
                shell_escape::escape(self.executor.directory().to_string_lossy()),
                script
            ),
            progress,
        )?;
        Ok(())
    }

    fn wait_for_kuma<F>(&self, config: &DeploymentConfig, progress: &mut F) -> Result<()>
    where
        F: FnMut(&str),
    {
        let kuma_container = format!("{}-uptime-kuma", config.container_name);
        let script = format!(
            r#"set -eu
kuma={kuma}
last=''
for attempt in $(seq 1 120); do
  kuma_state=$(docker inspect --format '{{{{.State.Status}}}}' "$kuma" 2>/dev/null || true)
  kuma_health=$(docker inspect --format '{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}}' "$kuma" 2>/dev/null || true)
  kuma_restarts=$(docker inspect --format '{{{{.RestartCount}}}}' "$kuma" 2>/dev/null || true)
  kuma_state=${{kuma_state:-missing}}
  kuma_health=${{kuma_health:-none}}
  kuma_restarts=${{kuma_restarts:-0}}
  signature="$kuma_state|$kuma_health|$kuma_restarts"
  if [ "$signature" != "$last" ] || [ $((attempt % 10)) -eq 1 ]; then
    elapsed=$((attempt - 1))
    printf '已等待 %ss · Uptime Kuma %s/%s · 重启 %s 次\n' "$elapsed" "$kuma_state" "$kuma_health" "$kuma_restarts"
    last=$signature
  fi
  if curl --fail --silent --max-time 2 http://127.0.0.1:{port}/setup-database-info >/dev/null || curl --fail --silent --max-time 2 http://127.0.0.1:{port}/api/entry-page >/dev/null; then
    printf 'Uptime Kuma 已就绪\n'
    exit 0
  fi
  if [ "$kuma_state" = restarting ] && [ "$kuma_restarts" -ge 2 ]; then
    echo "Uptime Kuma 容器已连续重启 $kuma_restarts 次，停止等待" >&2
    docker inspect --format '容器状态={{{{.State.Status}}}}，退出码={{{{.State.ExitCode}}}}，错误={{{{.State.Error}}}}' "$kuma" >&2 || true
    docker logs --tail 24 "$kuma" 2>&1 | tail -n 16 >&2 || true
    exit 1
  fi
  if [ "$kuma_state" = exited ] || [ "$kuma_state" = dead ] || [ "$kuma_health" = unhealthy ]; then
    echo "Uptime Kuma 容器状态异常：$kuma_state/$kuma_health" >&2
    docker inspect --format '容器状态={{{{.State.Status}}}}，退出码={{{{.State.ExitCode}}}}，错误={{{{.State.Error}}}}' "$kuma" >&2 || true
    docker logs --tail 24 "$kuma" 2>&1 | tail -n 16 >&2 || true
    exit 1
  fi
  sleep 1
done
echo '等待 Uptime Kuma 就绪超时（120 秒）' >&2
docker compose --env-file secrets.env -p {project} ps >&2 || true
docker logs --tail 24 "$kuma" 2>&1 | tail -n 16 >&2 || true
exit 1"#,
            kuma = kuma_container,
            port = self.state.kuma_port,
            project = config.container_name,
        );
        self.executor.run_script_streaming(
            &format!(
                "cd {}\n{}",
                shell_escape::escape(self.executor.directory().to_string_lossy()),
                script
            ),
            progress,
        )?;
        Ok(())
    }
}

fn render_compose(config: &DeploymentConfig, runtime: &DeploymentRuntime) -> Result<String> {
    let image = image_reference(&config.image, &config.image_ref);
    let newapi = json!({
        "image": image,
        "platform": "linux/amd64",
        "pull_policy": "missing",
        "container_name": config.container_name,
        "restart": "unless-stopped",
        "ports": [format!("{}:{}:3000", config.newapi_bind, runtime.state.newapi_port)],
        "volumes": ["./data/newapi:/data"],
        "environment": {
            "SQL_DSN": "postgresql://meowai:${POSTGRES_PASSWORD}@postgres:5432/newapi",
            "REDIS_CONN_STRING": "redis://:${REDIS_PASSWORD}@redis:6379",
            "SESSION_SECRET": "${SESSION_SECRET}",
            "TZ": "Asia/Shanghai",
            "SESSION_COOKIE_SECURE": "false"
        },
        "extra_hosts": ["host.docker.internal:host-gateway"],
        "depends_on": {
            "postgres": {"condition": "service_healthy"},
            "redis": {"condition": "service_healthy"}
        },
        "healthcheck": {
            "test": ["CMD", "wget", "-qO-", "http://127.0.0.1:3000/api/status"],
            "interval": "5s",
            "timeout": "3s",
            "retries": 30
        }
    });
    let postgres = json!({
        "image": "postgres:15-alpine",
        "container_name": format!("{}-postgres", config.container_name),
        "restart": "unless-stopped",
        "environment": {
            "POSTGRES_USER": "meowai",
            "POSTGRES_PASSWORD": "${POSTGRES_PASSWORD}",
            "POSTGRES_DB": "newapi"
        },
        "volumes": ["./data/postgres:/var/lib/postgresql/data"],
        "healthcheck": {
            "test": ["CMD-SHELL", "pg_isready -U meowai -d newapi"],
            "interval": "5s",
            "timeout": "3s",
            "retries": 30
        }
    });
    let redis = json!({
        "image": "redis:7-alpine",
        "container_name": format!("{}-redis", config.container_name),
        "restart": "unless-stopped",
        "command": ["redis-server", "--appendonly", "yes", "--requirepass", "${REDIS_PASSWORD}"],
        "environment": {"REDIS_PASSWORD": "${REDIS_PASSWORD}"},
        "volumes": ["./data/redis:/data"],
        "healthcheck": {
            "test": ["CMD-SHELL", "redis-cli -a \"$$REDIS_PASSWORD\" ping | grep -q PONG"],
            "interval": "5s",
            "timeout": "3s",
            "retries": 30
        }
    });
    let kuma = json!({
        "image": KUMA_IMAGE,
        "container_name": format!("{}-uptime-kuma", config.container_name),
        "restart": "unless-stopped",
        "ports": [format!("{}:{}:3001", config.kuma_bind, runtime.state.kuma_port)],
        "volumes": ["./data/uptime-kuma:/app/data"],
        "healthcheck": {
            "test": [
                "CMD",
                "node",
                "-e",
                "fetch('http://127.0.0.1:3001/api/entry-page').then(response => { if (!response.ok) process.exit(1); }).catch(() => process.exit(1))"
            ],
            "interval": "5s",
            "timeout": "3s",
            "retries": 30
        }
    });
    let document = json!({
        "name": config.container_name,
        "services": {
            "new-api": newapi,
            "postgres": postgres,
            "redis": redis,
            "uptime-kuma": kuma
        }
    });
    serde_json::to_string_pretty(&document)
        .map_err(|error| AppError::State(format!("serialize Compose file: {error}")))
}

fn image_reference(image: &str, image_ref: &str) -> String {
    if image_ref.starts_with("sha256:") {
        format!("{image}@{image_ref}")
    } else if image == DEFAULT_IMAGE
        && image_ref.bytes().all(|byte| byte.is_ascii_hexdigit())
        && image_ref.len() >= 7
    {
        format!("{image}:sha-{}", &image_ref[..7])
    } else {
        format!("{image}:{image_ref}")
    }
}

fn container_source_url(source_url: &str) -> Result<String> {
    let mut parsed = Url::parse(source_url)
        .map_err(|error| AppError::State(format!("parse source URL: {error}")))?;
    if matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1")) {
        parsed
            .set_host(Some("host.docker.internal"))
            .map_err(|_| AppError::State("replace loopback source host".to_owned()))?;
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn load_state() -> Result<Option<DeploymentState>> {
    storage::read(STATE_FILE)?
        .map(|content| {
            serde_json::from_slice(&content)
                .map_err(|error| AppError::State(format!("parse state.json: {error}")))
        })
        .transpose()
}

fn validate_existing_state(
    config: &DeploymentConfig,
    target_fingerprint: &str,
    state: &DeploymentState,
) -> Result<()> {
    if state.schema_version != 1 {
        return Err(AppError::State(format!(
            "unsupported state schema {}",
            state.schema_version
        )));
    }
    if state.deployment_id != config.deployment_id()
        || state.container_name != config.container_name
        || state.directory != config.directory.to_string_lossy()
    {
        return Err(AppError::State(
            "state.json 属于另一个部署，无法继续操作".to_owned(),
        ));
    }
    if state.target_fingerprint != target_fingerprint {
        return Err(AppError::State(
            "目标主机与上次部署时不一致，无法继续操作".to_owned(),
        ));
    }
    if state.image != config.image || state.image_ref != config.image_ref {
        return Err(AppError::State(
            "configured image differs from state.json; use an explicit upgrade workflow".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeploymentConfig;
    use serde_json::Value;

    fn runtime(config: &DeploymentConfig) -> DeploymentRuntime {
        DeploymentRuntime {
            executor: TargetExecutor::new(config.target.clone(), config.directory.clone()),
            state: DeploymentState {
                schema_version: 1,
                deployment_id: "test".to_owned(),
                target_fingerprint: "host".to_owned(),
                container_name: config.container_name.clone(),
                directory: config.directory.to_string_lossy().into_owned(),
                newapi_port: 3000,
                kuma_port: 3001,
                image: config.image.clone(),
                image_ref: config.image_ref.clone(),
                image_digest: String::new(),
                source_user_id: 1,
                source_group_sha256: String::new(),
                status_key_id: 1,
                manifest_sha256: String::new(),
                pricing_sha256: BTreeMap::new(),
                channels: BTreeMap::new(),
                kuma_monitors: BTreeMap::new(),
                phases: BTreeMap::new(),
                last_sync_at: 0,
                last_sync_success: false,
                operation: None,
            },
            secrets: DeploymentSecrets {
                postgres_password: SecretString::from("postgres".to_owned()),
                redis_password: SecretString::from("redis".to_owned()),
                session_secret: SecretString::from("session".to_owned()),
                newapi_admin_password: SecretString::from("newapi".to_owned()),
                kuma_admin_password: SecretString::from("kuma".to_owned()),
                public_status_source_key: SecretString::from("status".to_owned()),
            },
            container_source_url: "http://host.docker.internal:3004".to_owned(),
            credentials_should_display: true,
        }
    }

    #[test]
    fn compose_keeps_databases_internal_and_pins_kuma() {
        let config = DeploymentConfig::default();
        let rendered = render_compose(&config, &runtime(&config)).expect("render compose");
        let value: Value = serde_json::from_str(&rendered).expect("parse compose");
        assert!(value["services"]["postgres"].get("ports").is_none());
        assert!(value["services"]["redis"].get("ports").is_none());
        assert_eq!(value["services"]["uptime-kuma"]["image"], KUMA_IMAGE);
        assert_eq!(value["services"]["new-api"]["platform"], "linux/amd64");
        assert_eq!(value["services"]["new-api"]["pull_policy"], "missing");
        let environment = &value["services"]["new-api"]["environment"];
        assert!(environment.get("PUBLIC_STATUS_MODE").is_none());
        assert!(environment.get("PUBLIC_STATUS_SOURCE_URL").is_none());
        assert!(environment.get("PUBLIC_STATUS_SOURCE_KEY").is_none());
    }

    #[test]
    fn loopback_source_is_rewritten_for_container_access() {
        assert_eq!(
            container_source_url("http://localhost:3004").expect("rewrite"),
            "http://host.docker.internal:3004"
        );
        assert_eq!(
            container_source_url("https://source.example").expect("keep source"),
            "https://source.example"
        );
    }

    #[test]
    fn default_image_accepts_digest_and_commit_pins() {
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            image_reference(DEFAULT_IMAGE, digest),
            format!("{DEFAULT_IMAGE}@{digest}")
        );
        assert_eq!(
            image_reference(DEFAULT_IMAGE, "7ab352138e4837608b8acdfa92a51f7809c9443d"),
            format!("{DEFAULT_IMAGE}:sha-7ab3521")
        );
    }
}
