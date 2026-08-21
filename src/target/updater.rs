use std::path::Path;

use crate::{config::DeploymentConfig, error::Result, security::random_secret};

use super::TargetExecutor;

const SCRIPT: &str = r#"#!/bin/sh
set -eu
umask 077
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOCK="$ROOT/.meowai-updater.lock"
SOCKET="$ROOT/run/updater.sock"
STATE="$ROOT/run/updater-status.json"
PROJECT="__PROJECT__"
CONTAINER="__CONTAINER__"
REPOSITORY="__REPOSITORY__"
COMPOSE_BASE="$ROOT/docker-compose.yml"
COMPOSE_OVERRIDE="$ROOT/docker-compose.updater.yml"

if ! mkdir "$LOCK" 2>/dev/null; then exit 0; fi
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT HUP INT TERM

report() {
  event=$1 current=$2 approved=$3 backup_id=$4 error_code=$5 reason=$6
  payload=$(printf '{"type":"%s","current_digest":"%s","approved_digest":"%s","backup_id":"%s","error_code":"%s","reason":"%s"}' "$event" "$current" "$approved" "$backup_id" "$error_code" "$reason")
  now=$(date +%s)
  status_tmp="$STATE.tmp"
  printf '{"status":"%s","updated_at":%s}\n' "$event" "$now" > "$status_tmp"
  chmod 600 "$status_tmp"
  mv "$status_tmp" "$STATE"
  curl --fail --silent --show-error --max-time 10 --unix-socket "$SOCKET" \
    -H "Authorization: Bearer $MEOWAI_UPDATER_LOCAL_CREDENTIAL" \
    -H 'Content-Type: application/json' --data-binary "$payload" http://localhost/result >/dev/null || true
}

current_digest() {
  image_id=$(docker inspect --format '{{.Image}}' "$CONTAINER" 2>/dev/null || true)
  [ -n "$image_id" ] || return 0
  docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image_id" 2>/dev/null \
    | awk -F@ -v repo="$REPOSITORY" '$1 == repo && $2 ~ /^sha256:[0-9a-f]{64}$/ {print $2; exit}'
}

newapi_healthy() {
  curl --fail --silent --max-time 2 http://127.0.0.1:__PORT__/api/status >/dev/null &&
    curl --fail --silent --max-time 2 http://127.0.0.1:__PORT__/api/setup >/dev/null
}

health_attempts=${MEOWAI_UPDATER_HEALTH_ATTEMPTS:-60}
case "$health_attempts" in ''|*[!0-9]*) health_attempts=60 ;; esac
[ "$health_attempts" -ge 1 ] || health_attempts=60

policy=$(curl --fail --silent --show-error --max-time 10 --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $MEOWAI_UPDATER_LOCAL_CREDENTIAL" http://localhost/policy) || {
  report update_failed "$(current_digest)" '' '' POLICY_FETCH_FAILED 'control plane policy fetch failed; no update was attempted'
  exit 1
}
approved=$(printf '%s' "$policy" | sed -n 's/.*"image_digest":"\(sha256:[0-9a-f]\{64\}\)".*/\1/p')
repository=$(printf '%s' "$policy" | sed -n 's/.*"image_repository":"\([a-z0-9][a-z0-9._\/-]*\)".*/\1/p')
silent=$(printf '%s' "$policy" | sed -n 's/.*"silent_updates_enabled":[[:space:]]*true.*/true/p; s/.*"silent_updates_enabled":[[:space:]]*false.*/false/p')
decision=$(printf '%s' "$policy" | sed -n 's/.*"decision":"\([^"]*\)".*/\1/p')
execution_authorized=$(printf '%s' "$policy" | sed -n 's/.*"execution_authorized":[[:space:]]*true.*/true/p; s/.*"execution_authorized":[[:space:]]*false.*/false/p')
if [ "$decision" = upgrade_required ]; then
  [ "$execution_authorized" = true ] || { report update_check "$(current_digest)" '' '' UPGRADE_AUTHORIZATION_REQUIRED 'structural release is waiting for operator authorization'; exit 0; }
  report upgrade_started "$(current_digest)" '' '' '' 'structural release requires target deployment agent'
  if [ ! -x "$ROOT/bin/meowai-deploy-upgrade-agent" ]; then
    report upgrade_failed "$(current_digest)" '' '' AGENT_MISSING 'target deployment upgrade agent is not installed; run bootstrap'
    exit 1
  fi
  if "$ROOT/bin/meowai-deploy-upgrade-agent" agent --root "$ROOT" --auto >/dev/null 2>&1; then
    report upgrade_succeeded "$(current_digest)" '' '' '' 'structural deployment upgrade completed'
    exit 0
  fi
  report upgrade_failed "$(current_digest)" '' '' AGENT_EXECUTION_FAILED 'target deployment upgrade agent failed; current deployment was left protected'
  exit 1
fi
[ "$decision" = blocked ] && { report update_check "$(current_digest)" '' '' UPGRADE_BLOCKED 'structural release is blocked pending bootstrap or manual intervention'; exit 0; }
[ -n "$approved" ] || { report update_check "$(current_digest)" '' '' '' 'no approved image update; current structural release is up to date'; exit 0; }
[ "$repository" = "$REPOSITORY" ] || exit 0
[ "$silent" = true ] || { report update_check "$(current_digest)" "$approved" '' '' 'approved update waiting for manual policy'; exit 0; }

current=$(current_digest)
[ "$current" != "$approved" ] || { report update_check "$current" "$approved" '' '' 'already on approved digest'; exit 0; }
report update_check "$current" "$approved" '' '' 'approved update available'

for command in docker curl sha256sum tar awk sed; do command -v "$command" >/dev/null 2>&1 || { report update_failed "$current" "$approved" '' PRECHECK_TOOL_MISSING 'required backup or update tool is missing'; exit 1; }; done
docker compose version >/dev/null 2>&1 || { report update_failed "$current" "$approved" '' PRECHECK_COMPOSE_MISSING 'Docker Compose is unavailable'; exit 1; }
available_kb=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
[ "${available_kb:-0}" -ge 1048576 ] || { report update_failed "$current" "$approved" '' PRECHECK_DISK_LOW 'less than one GiB is available'; exit 1; }

backup_id=$(date -u +%Y%m%dT%H%M%SZ)
backup="$ROOT/backups/$backup_id"
mkdir -p "$backup"
chmod 700 "$ROOT/backups" "$backup"
report backup_started "$current" "$approved" "$backup_id" '' 'backup started'

cp "$COMPOSE_BASE" "$backup/docker-compose.yml"
[ ! -f "$COMPOSE_OVERRIDE" ] || cp "$COMPOSE_OVERRIDE" "$backup/docker-compose.updater.yml"
cp "$ROOT/secrets.env" "$backup/secrets.env"
cp "$ROOT/downstream-credentials.env" "$backup/downstream-credentials.env"
cp "$ROOT/updater-credentials.env" "$backup/updater-credentials.env"
printf '%s\n' "$current" > "$backup/previous-digest"

pg_container="${PROJECT}-postgres"
redis_container="${PROJECT}-redis"
if ! docker exec "$pg_container" sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U meowai -d newapi -Fc' > "$backup/postgres.dump"; then
  report backup_failed "$current" "$approved" "$backup_id" POSTGRES_BACKUP_FAILED 'PostgreSQL backup failed'
  exit 1
fi
docker exec "$redis_container" sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning SAVE >/dev/null' || { report backup_failed "$current" "$approved" "$backup_id" REDIS_BACKUP_FAILED 'Redis backup failed'; exit 1; }
tar -C "$ROOT" -czf "$backup/redis-data.tar.gz" data/redis
tar -C "$ROOT" -czf "$backup/kuma-data.tar.gz" data/uptime-kuma
(cd "$backup" && sha256sum docker-compose.yml secrets.env downstream-credentials.env updater-credentials.env previous-digest postgres.dump redis-data.tar.gz kuma-data.tar.gz > SHA256SUMS && sha256sum -c SHA256SUMS >/dev/null) || { report backup_failed "$current" "$approved" "$backup_id" BACKUP_CHECKSUM_FAILED 'backup checksum verification failed'; exit 1; }
report backup_succeeded "$current" "$approved" "$backup_id" '' 'backup completed and verified'

docker pull "$REPOSITORY@$approved" >/dev/null || { report update_failed "$current" "$approved" "$backup_id" IMAGE_PULL_FAILED 'approved image pull failed'; exit 1; }
temporary_override="$ROOT/.docker-compose.updater.yml.tmp"
printf 'services:\n  new-api:\n    image: %s@%s\n    environment:\n      MEOWAI_CURRENT_IMAGE_DIGEST: %s\n' "$REPOSITORY" "$approved" "$approved" > "$temporary_override"
chmod 600 "$temporary_override"
docker compose --env-file "$ROOT/secrets.env" -p "$PROJECT" -f "$COMPOSE_BASE" -f "$temporary_override" config >/dev/null || { rm -f "$temporary_override"; report update_failed "$current" "$approved" "$backup_id" COMPOSE_VALIDATION_FAILED 'approved Compose override is invalid'; exit 1; }
mv "$temporary_override" "$COMPOSE_OVERRIDE"
report update_started "$current" "$approved" "$backup_id" '' 'replacing New API with approved digest'

if docker compose --env-file "$ROOT/secrets.env" -p "$PROJECT" -f "$COMPOSE_BASE" -f "$COMPOSE_OVERRIDE" up -d --no-deps new-api >/dev/null; then
  healthy=false
  for attempt in $(seq 1 "$health_attempts"); do
    if newapi_healthy; then healthy=true; break; fi
    sleep 2
  done
  actual=$(current_digest)
  if [ "$healthy" = true ] && [ "$actual" = "$approved" ]; then
    report update_succeeded "$actual" "$approved" "$backup_id" '' 'approved digest is healthy'
    find "$ROOT/backups" -mindepth 1 -maxdepth 1 -type d -print | sort -r | awk 'NR>3' | while IFS= read -r old; do rm -rf -- "$old"; done
    exit 0
  fi
fi

if [ -f "$backup/docker-compose.updater.yml" ]; then cp "$backup/docker-compose.updater.yml" "$COMPOSE_OVERRIDE"; else rm -f "$COMPOSE_OVERRIDE"; fi
files="-f $COMPOSE_BASE"
[ ! -f "$COMPOSE_OVERRIDE" ] || files="$files -f $COMPOSE_OVERRIDE"
# shellcheck disable=SC2086
if docker compose --env-file "$ROOT/secrets.env" -p "$PROJECT" $files up -d --no-deps new-api >/dev/null; then
  for attempt in $(seq 1 "$health_attempts"); do
    if newapi_healthy; then
      report update_rolled_back "$(current_digest)" "$approved" "$backup_id" UPDATE_HEALTH_FAILED 'new image failed health verification; previous image restored'
      exit 1
    fi
    sleep 2
  done
fi

docker compose --env-file "$ROOT/secrets.env" -p "$PROJECT" $files stop new-api redis >/dev/null 2>&1 || true
restore_ok=true
rm -rf "$ROOT/data/redis"
tar -C "$ROOT" -xzf "$backup/redis-data.tar.gz" || restore_ok=false
docker compose --env-file "$ROOT/secrets.env" -p "$PROJECT" $files up -d --no-deps redis >/dev/null 2>&1 || restore_ok=false
cat "$backup/postgres.dump" | docker exec -i "$pg_container" sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_restore -U meowai -d newapi --clean --if-exists' >/dev/null 2>&1 || restore_ok=false
docker compose --env-file "$ROOT/secrets.env" -p "$PROJECT" $files up -d --no-deps new-api >/dev/null 2>&1 || restore_ok=false
if [ "$restore_ok" = true ]; then
  for attempt in $(seq 1 "$health_attempts"); do
    if newapi_healthy; then
      report update_rolled_back "$(current_digest)" "$approved" "$backup_id" UPDATE_HEALTH_FAILED 'previous image and required data backups restored'
      exit 1
    fi
    sleep 2
  done
fi
report update_failed "$(current_digest)" "$approved" "$backup_id" UPDATE_ROLLBACK_FAILED 'new image and automatic rollback both failed'
exit 1
"#;

fn render_script(config: &DeploymentConfig, newapi_port: u16) -> String {
    SCRIPT
        .replace("__PROJECT__", &config.container_name)
        .replace("__CONTAINER__", &config.container_name)
        .replace("__REPOSITORY__", &config.image)
        .replace("__PORT__", &newapi_port.to_string())
}

fn render_service_unit(directory: &Path) -> String {
    let raw_directory = directory.to_string_lossy();
    let directory = systemd_quote(&raw_directory);
    let credentials = systemd_quote(&format!("{raw_directory}/updater-credentials.env"));
    let state_home = systemd_quote(&format!(
        "MEOWAI_DEPLOY_HOME={raw_directory}/run/agent-state"
    ));
    let executable = systemd_quote(&format!("{raw_directory}/meowai-deploy-updater.sh"));
    format!(
        "[Unit]\nDescription=MeowAI downstream approved-digest updater\nAfter=docker.service\nRequires=docker.service\n\n[Service]\nType=oneshot\nWorkingDirectory={directory}\nEnvironmentFile={credentials}\nEnvironment={state_home}\nExecStart={executable}\nUMask=0077\nPrivateTmp=true\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\nReadWritePaths={directory} /etc/systemd/system /run/systemd/system\n",
    )
}

fn systemd_quote(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(' ', "\\x20")
        .replace('"', "\\\"")
        .replace('%', "%%")
}

const TIMER_UNIT: &[u8] = b"[Unit]\nDescription=Periodic MeowAI approved-digest check\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=15min\nRandomizedDelaySec=2min\nPersistent=true\nUnit=meowai-deploy-updater.service\n\n[Install]\nWantedBy=timers.target\n";

pub fn install(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    newapi_port: u16,
) -> Result<()> {
    install_paused(executor, config, newapi_port)?;
    executor.run_in_directory(
        "set -eu\nsystemctl daemon-reload\nsystemctl enable --now meowai-deploy-updater.timer",
    )?;
    Ok(())
}

pub fn install_paused(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    newapi_port: u16,
) -> Result<()> {
    prepare_credentials(executor)?;
    let script = render_script(config, newapi_port);
    executor.write_file("meowai-deploy-updater.sh", script.as_bytes(), true)?;
    let unit = render_service_unit(&config.directory);
    executor.write_file("meowai-deploy-updater.service", unit.as_bytes(), false)?;
    executor.write_file("meowai-deploy-updater.timer", TIMER_UNIT, false)?;
    executor.run_in_directory(
        "set -eu\nchmod 700 meowai-deploy-updater.sh\nmkdir -p run backups\nchmod 700 run backups\nnow=$(date +%s)\nprintf '{\"status\":\"installed\",\"updated_at\":%s}\\n' \"$now\" > run/updater-status.json\nchmod 600 run/updater-status.json\ninstall -m 0644 meowai-deploy-updater.service /etc/systemd/system/meowai-deploy-updater.service\ninstall -m 0644 meowai-deploy-updater.timer /etc/systemd/system/meowai-deploy-updater.timer\nsystemctl daemon-reload",
    )?;
    Ok(())
}

pub fn prepare_credentials(executor: &TargetExecutor) -> Result<()> {
    let token = random_secret(48);
    crate::security::validate_env_value("MEOWAI_UPDATER_LOCAL_CREDENTIAL", &token)?;
    let token = shell_escape::escape(token.into());
    executor.run_in_directory(&format!("set -eu\nif [ ! -s updater-credentials.env ]; then\n  umask 077\n  printf 'MEOWAI_UPDATER_LOCAL_CREDENTIAL=%s\\n' {token} > updater-credentials.env\n  chmod 600 updater-credentials.env\nfi\ntest -s updater-credentials.env"))?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        os::unix::{fs::PermissionsExt, net::UnixListener},
        path::{Path, PathBuf},
        process::{Command, Output},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };

    use crate::config::DeploymentConfig;
    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::{SCRIPT, TIMER_UNIT, render_script, render_service_unit};

    const CURRENT_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const APPROVED_DIGEST: &str =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    struct RuntimeResult {
        _temporary: TempDir,
        root: PathBuf,
        output: Output,
        events: Vec<Value>,
    }

    #[derive(Clone, Copy)]
    struct RuntimeScenario {
        current_is_approved: bool,
        silent_updates: bool,
        decision: &'static str,
        execution_authorized: bool,
        agent_installed: bool,
        agent_fails: bool,
        policy_unavailable: bool,
        postgres_backup_fails: bool,
        redis_backup_fails: bool,
        image_pull_fails: bool,
        compose_start_fails: bool,
        health_fails: bool,
        setup_fails: bool,
        rollback_fails: bool,
    }

    impl Default for RuntimeScenario {
        fn default() -> Self {
            Self {
                current_is_approved: false,
                silent_updates: true,
                decision: "image_only",
                execution_authorized: true,
                agent_installed: false,
                agent_fails: false,
                policy_unavailable: false,
                postgres_backup_fails: false,
                redis_backup_fails: false,
                image_pull_fails: false,
                compose_start_fails: false,
                health_fails: false,
                setup_fails: false,
                rollback_fails: false,
            }
        }
    }

    fn write_executable(path: &Path, content: &str) {
        fs::write(path, content).expect("write fake executable");
        let mut permissions = fs::metadata(path)
            .expect("read fake executable metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).expect("make fake executable runnable");
    }

    fn serve_control_socket(
        listener: UnixListener,
        repository: String,
        silent_updates: bool,
        decision: &'static str,
        execution_authorized: bool,
        policy_unavailable: bool,
        events: Arc<Mutex<Vec<Value>>>,
        stop: Arc<AtomicBool>,
    ) {
        listener
            .set_nonblocking(true)
            .expect("make control socket nonblocking");
        while !stop.load(Ordering::Relaxed) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(5));
                continue;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set socket timeout");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => {
                        request.extend_from_slice(&chunk[..count]);
                        let Some(headers_end) =
                            request.windows(4).position(|part| part == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let headers = String::from_utf8_lossy(&request[..headers_end]);
                        let content_length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        if request.len() >= headers_end + 4 + content_length {
                            break;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(error) => panic!("read control socket request: {error}"),
                }
            }

            let Some(headers_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                // A client may close a probe socket before sending a complete request.
                // Ignore that connection; the updater test server must not turn it into a
                // process-wide panic.
                continue;
            };
            let request_line = String::from_utf8_lossy(&request[..headers_end])
                .lines()
                .next()
                .expect("HTTP request line")
                .to_owned();
            let response = if request_line.starts_with("GET /policy ") {
                json!({
                    "image_digest": APPROVED_DIGEST,
                    "image_repository": repository,
                    "silent_updates_enabled": silent_updates,
                    "decision": decision,
                    "execution_authorized": execution_authorized,
                })
                .to_string()
            } else {
                let event: Value = serde_json::from_slice(&request[headers_end + 4..])
                    .expect("valid updater event JSON");
                events.lock().expect("events lock").push(event);
                "{}".to_owned()
            };
            let status = if policy_unavailable && request_line.starts_with("GET /policy ") {
                "503 Service Unavailable"
            } else {
                "200 OK"
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .expect("write control socket response");
        }
    }

    fn run_runtime(scenario: RuntimeScenario) -> RuntimeResult {
        let _env_guard = crate::target::TEST_ENV_LOCK
            .get_or_init(Default::default)
            .lock()
            .expect("runtime test environment lock");
        let temporary = tempfile::tempdir_in("/tmp").expect("create updater runtime directory");
        let root = temporary.path().join("deployment");
        let fake_bin = temporary.path().join("bin");
        fs::create_dir_all(root.join("run")).expect("create run directory");
        fs::create_dir_all(root.join("backups")).expect("create backups directory");
        fs::create_dir_all(root.join("data/redis")).expect("create redis data directory");
        fs::create_dir_all(root.join("data/uptime-kuma")).expect("create Kuma data directory");
        fs::create_dir_all(&fake_bin).expect("create fake bin directory");
        for (name, content) in [
            (
                "docker-compose.yml",
                "services:\n  new-api:\n    image: old\n",
            ),
            ("secrets.env", "SECRET=value\n"),
            ("downstream-credentials.env", "REPORT=value\n"),
            (
                "updater-credentials.env",
                "MEOWAI_UPDATER_LOCAL_CREDENTIAL=runtime-test-token\n",
            ),
            ("data/redis/dump.rdb", "redis"),
            ("data/uptime-kuma/kuma.db", "kuma"),
        ] {
            fs::write(root.join(name), content).expect("write runtime fixture");
        }
        fs::write(
            root.join("current-digest"),
            if scenario.current_is_approved {
                APPROVED_DIGEST
            } else {
                CURRENT_DIGEST
            },
        )
        .expect("write current digest");

        let config = DeploymentConfig {
            directory: root.clone(),
            container_name: "runtime-test".to_owned(),
            ..DeploymentConfig::default()
        };
        let script = render_script(&config, 43127);
        let script_path = root.join("meowai-deploy-updater.sh");
        write_executable(&script_path, &script);
        if scenario.agent_installed {
            fs::create_dir_all(root.join("bin")).expect("create agent directory");
            write_executable(
                &root.join("bin/meowai-deploy-upgrade-agent"),
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$FAKE_ROOT/agent-invocation\"\n[ \"$FAKE_AGENT_FAIL\" != 1 ]\n",
            );
        }

        let docker = format!(
            r#"#!/bin/sh
set -eu
case "$1" in
  inspect) printf '%s\n' fake-image-id ;;
  image) printf '%s@%s\n' '{repository}' "$(cat "$FAKE_ROOT/current-digest")" ;;
  pull) [ "${{FAKE_PULL_FAIL:-0}}" != 1 ] ;;
  exec)
    case "$2" in
      *-postgres)
        [ "${{FAKE_PG_FAIL:-0}}" != 1 ] || exit 1
        printf '%s\n' pg-dump
        ;;
      *-redis) [ "${{FAKE_REDIS_FAIL:-0}}" != 1 ] ;;
      *) exit 1 ;;
    esac
    ;;
  compose)
    case "$*" in
      *' version') exit 0 ;;
      *' config') exit 0 ;;
      *' up '*new-api*)
        if [ -f "$FAKE_ROOT/docker-compose.updater.yml" ]; then
          : > "$FAKE_ROOT/update-attempted"
          [ "${{FAKE_COMPOSE_START_FAIL:-0}}" != 1 ] || exit 1
          digest=$(sed -n 's/.*@\(sha256:[0-9a-f]\{{64\}}\).*/\1/p' "$FAKE_ROOT/docker-compose.updater.yml")
          [ -z "$digest" ] || printf '%s' "$digest" > "$FAKE_ROOT/current-digest"
        else
          [ ! -f "$FAKE_ROOT/update-attempted" ] || [ "${{FAKE_ROLLBACK_FAIL:-0}}" != 1 ] || exit 1
          printf '%s' '{current_digest}' > "$FAKE_ROOT/current-digest"
        fi
        exit 0
        ;;
      *' stop '*new-api*) exit 0 ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 1 ;;
esac
"#,
            repository = config.image,
            current_digest = CURRENT_DIGEST,
        );
        write_executable(&fake_bin.join("docker"), &docker);

        let real_curl = String::from_utf8(
            Command::new("sh")
                .args(["-c", "command -v curl"])
                .output()
                .expect("locate curl")
                .stdout,
        )
        .expect("curl path is UTF-8")
        .trim()
        .to_owned();
        write_executable(
            &fake_bin.join("curl"),
            &format!(
                "#!/bin/sh\ncase \"$*\" in\n  *--unix-socket*) exec {real_curl} \"$@\" ;;\n  *127.0.0.1:43127/api/setup*)\n    if [ \"${{FAKE_SETUP_FAIL:-0}}\" = 1 ] && [ \"$(cat \"$FAKE_ROOT/current-digest\")\" = \"{approved_digest}\" ]; then exit 1; fi\n    exit 0 ;;\n  *127.0.0.1:43127/api/status*)\n    if [ \"${{FAKE_HEALTH_FAIL:-0}}\" = 1 ] && [ \"$(cat \"$FAKE_ROOT/current-digest\")\" = \"{approved_digest}\" ]; then exit 1; fi\n    exit 0 ;;\n  *) exec {real_curl} \"$@\" ;;\nesac\n",
                approved_digest = APPROVED_DIGEST,
            ),
        );
        write_executable(
            &fake_bin.join("sha256sum"),
            "#!/bin/sh\nif [ \"${1:-}\" = -c ]; then exit 0; fi\nfor file in \"$@\"; do printf 'fixture  %s\\n' \"$file\"; done\n",
        );

        let socket_path = root.join("run/updater.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind updater control socket");
        let events = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let server = {
            let events = Arc::clone(&events);
            let stop = Arc::clone(&stop);
            let repository = config.image.clone();
            let silent_updates = scenario.silent_updates;
            let decision = scenario.decision;
            let execution_authorized = scenario.execution_authorized;
            let policy_unavailable = scenario.policy_unavailable;
            thread::spawn(move || {
                serve_control_socket(
                    listener,
                    repository,
                    silent_updates,
                    decision,
                    execution_authorized,
                    policy_unavailable,
                    events,
                    stop,
                )
            })
        };

        let path = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = Command::new("sh")
            .arg(&script_path)
            .env("PATH", path)
            .env("FAKE_ROOT", &root)
            .env("FAKE_PG_FAIL", flag(scenario.postgres_backup_fails))
            .env("FAKE_REDIS_FAIL", flag(scenario.redis_backup_fails))
            .env("FAKE_PULL_FAIL", flag(scenario.image_pull_fails))
            .env(
                "FAKE_COMPOSE_START_FAIL",
                flag(scenario.compose_start_fails),
            )
            .env("FAKE_HEALTH_FAIL", flag(scenario.health_fails))
            .env("FAKE_SETUP_FAIL", flag(scenario.setup_fails))
            .env("FAKE_ROLLBACK_FAIL", flag(scenario.rollback_fails))
            .env("FAKE_AGENT_FAIL", flag(scenario.agent_fails))
            .env("MEOWAI_UPDATER_HEALTH_ATTEMPTS", "1")
            .env("MEOWAI_UPDATER_LOCAL_CREDENTIAL", "runtime-test-token")
            .output()
            .expect("run updater script");
        stop.store(true, Ordering::Relaxed);
        server.join().expect("join control socket server");
        let captured_events = events.lock().expect("events lock").clone();

        RuntimeResult {
            _temporary: temporary,
            root,
            output,
            events: captured_events,
        }
    }

    fn flag(value: bool) -> &'static str {
        if value { "1" } else { "0" }
    }

    fn event_types(result: &RuntimeResult) -> Vec<&str> {
        result
            .events
            .iter()
            .map(|event| event["type"].as_str().expect("event type"))
            .collect()
    }

    #[test]
    fn updater_is_limited_to_approved_digest_and_fixed_workflow() {
        assert!(SCRIPT.contains("--unix-socket \"$SOCKET\""));
        assert!(SCRIPT.contains("docker pull \"$REPOSITORY@$approved\""));
        assert!(SCRIPT.contains("pg_dump"));
        assert!(SCRIPT.contains("sha256sum -c"));
        assert!(SCRIPT.contains("update_rolled_back"));
        assert!(SCRIPT.contains("updater-status.json"));
        assert!(!SCRIPT.contains("eval "));
        assert!(!SCRIPT.contains("sh -c \"$"));
    }

    #[test]
    fn updater_health_check_uses_allocated_runtime_port() {
        let config = DeploymentConfig {
            directory: PathBuf::from("/tmp/meowai"),
            newapi_port: 3000,
            ..DeploymentConfig::default()
        };

        let script = render_script(&config, 43127);

        assert!(script.contains("http://127.0.0.1:43127/api/status"));
        assert!(!script.contains("http://127.0.0.1:3000/api/status"));
    }

    #[test]
    fn updater_systemd_units_run_persistently_on_the_target_host() {
        let directory = Path::new("/srv/meowai/downstream");
        let service = render_service_unit(directory);
        let timer = String::from_utf8_lossy(TIMER_UNIT);

        assert!(service.contains("WorkingDirectory=/srv/meowai/downstream\n"));
        assert!(
            service.contains("EnvironmentFile=/srv/meowai/downstream/updater-credentials.env\n")
        );
        assert!(
            service.contains(
                "Environment=MEOWAI_DEPLOY_HOME=/srv/meowai/downstream/run/agent-state\n"
            )
        );
        assert!(service.contains("ExecStart=/srv/meowai/downstream/meowai-deploy-updater.sh\n"));
        assert!(service.contains("ProtectSystem=strict\n"));
        assert!(service.contains("NoNewPrivileges=true\n"));
        assert!(!service.contains("ssh"));
        assert!(timer.contains("Persistent=true\n"));
        assert!(timer.contains("WantedBy=timers.target\n"));
    }

    #[test]
    fn updater_systemd_unit_quotes_remote_paths_and_specifiers() {
        let service = render_service_unit(Path::new("/srv/Meow AI/tenant%20"));
        assert!(service.contains("WorkingDirectory=/srv/Meow\\x20AI/tenant%%20\n"));
        assert!(
            service.contains("ExecStart=/srv/Meow\\x20AI/tenant%%20/meowai-deploy-updater.sh\n")
        );
        assert!(!service.contains("tenant%20/meowai"));
    }

    #[test]
    fn updater_runtime_backs_up_and_applies_approved_digest_over_real_ipc() {
        let result = run_runtime(RuntimeScenario::default());

        assert!(
            result.output.status.success(),
            "updater failed: {}",
            String::from_utf8_lossy(&result.output.stderr)
        );
        assert_eq!(
            event_types(&result),
            [
                "update_check",
                "backup_started",
                "backup_succeeded",
                "update_started",
                "update_succeeded",
            ],
            "events: {:?}; stdout: {}; stderr: {}",
            result.events,
            String::from_utf8_lossy(&result.output.stdout),
            String::from_utf8_lossy(&result.output.stderr)
        );
        assert_eq!(
            fs::read_to_string(result.root.join("current-digest")).expect("read final digest"),
            APPROVED_DIGEST
        );
        let compose_override = fs::read_to_string(result.root.join("docker-compose.updater.yml"))
            .expect("read updater Compose override");
        assert!(
            compose_override.contains(&format!("MEOWAI_CURRENT_IMAGE_DIGEST: {APPROVED_DIGEST}\n"))
        );
        let updater_state: Value = serde_json::from_slice(
            &fs::read(result.root.join("run/updater-status.json")).expect("read updater status"),
        )
        .expect("parse updater status");
        assert_eq!(updater_state["status"], "update_succeeded");
        assert!(
            updater_state["updated_at"]
                .as_i64()
                .is_some_and(|value| value > 0)
        );
        let backup = fs::read_dir(result.root.join("backups"))
            .expect("read backups")
            .next()
            .expect("backup directory")
            .expect("read backup entry")
            .path();
        for artifact in [
            "SHA256SUMS",
            "postgres.dump",
            "redis-data.tar.gz",
            "kuma-data.tar.gz",
            "previous-digest",
        ] {
            assert!(backup.join(artifact).is_file(), "missing {artifact}");
        }
    }

    #[test]
    fn updater_runtime_delegates_structural_release_to_installed_agent() {
        let result = run_runtime(RuntimeScenario {
            decision: "upgrade_required",
            agent_installed: true,
            ..RuntimeScenario::default()
        });

        assert!(result.output.status.success());
        assert_eq!(
            event_types(&result),
            ["upgrade_started", "upgrade_succeeded"]
        );
        assert_eq!(
            fs::read_to_string(result.root.join("agent-invocation"))
                .expect("read agent invocation")
                .trim(),
            format!("agent --root {} --auto", result.root.display())
        );
        assert!(!result.root.join("update-attempted").exists());
        assert_eq!(
            fs::read_to_string(result.root.join("current-digest")).expect("read current digest"),
            CURRENT_DIGEST
        );
    }

    #[test]
    fn updater_runtime_waits_cleanly_for_structural_authorization() {
        let result = run_runtime(RuntimeScenario {
            decision: "upgrade_required",
            execution_authorized: false,
            agent_installed: true,
            ..RuntimeScenario::default()
        });

        assert!(result.output.status.success());
        assert_eq!(event_types(&result), ["update_check"]);
        assert_eq!(
            result.events[0]["error_code"],
            "UPGRADE_AUTHORIZATION_REQUIRED"
        );
        assert!(!result.root.join("agent-invocation").exists());
        assert!(!result.root.join("update-attempted").exists());
    }

    #[test]
    fn updater_runtime_blocks_structural_release_when_agent_is_missing() {
        let result = run_runtime(RuntimeScenario {
            decision: "upgrade_required",
            ..RuntimeScenario::default()
        });

        assert!(!result.output.status.success());
        assert_eq!(event_types(&result), ["upgrade_started", "upgrade_failed"]);
        assert_eq!(result.events[1]["error_code"], "AGENT_MISSING");
        assert!(!result.root.join("update-attempted").exists());
        assert_eq!(
            fs::read_to_string(result.root.join("current-digest")).expect("read current digest"),
            CURRENT_DIGEST
        );
    }

    #[test]
    fn updater_runtime_stops_before_update_when_postgres_backup_fails() {
        let result = run_runtime(RuntimeScenario {
            postgres_backup_fails: true,
            ..RuntimeScenario::default()
        });

        assert!(
            !result.output.status.success(),
            "events: {:?}; stdout: {}; stderr: {}",
            result.events,
            String::from_utf8_lossy(&result.output.stdout),
            String::from_utf8_lossy(&result.output.stderr)
        );
        assert_eq!(
            event_types(&result),
            ["update_check", "backup_started", "backup_failed"]
        );
        assert_eq!(
            result.events.last().expect("failure event")["error_code"],
            "POSTGRES_BACKUP_FAILED"
        );
        assert!(!result.root.join("docker-compose.updater.yml").exists());
        assert_eq!(
            fs::read_to_string(result.root.join("current-digest")).expect("read current digest"),
            CURRENT_DIGEST
        );
    }

    #[test]
    fn updater_runtime_does_not_rebuild_for_same_digest_disabled_policy_or_unavailable_source() {
        for (name, scenario, expected_events) in [
            (
                "same digest",
                RuntimeScenario {
                    current_is_approved: true,
                    ..RuntimeScenario::default()
                },
                vec!["update_check"],
            ),
            (
                "silent policy disabled",
                RuntimeScenario {
                    silent_updates: false,
                    ..RuntimeScenario::default()
                },
                vec!["update_check"],
            ),
            (
                "control plane unavailable",
                RuntimeScenario {
                    policy_unavailable: true,
                    ..RuntimeScenario::default()
                },
                vec!["update_failed"],
            ),
        ] {
            let result = run_runtime(scenario);
            if scenario.policy_unavailable {
                assert!(
                    !result.output.status.success(),
                    "{name}: {:?}",
                    result.events
                );
                assert_eq!(result.events[0]["error_code"], "POLICY_FETCH_FAILED");
                let updater_state: Value = serde_json::from_slice(
                    &fs::read(result.root.join("run/updater-status.json"))
                        .expect("read updater status"),
                )
                .expect("parse updater status");
                assert_eq!(updater_state["status"], "update_failed");
            } else {
                assert!(
                    result.output.status.success(),
                    "{name}: {:?}",
                    result.events
                );
            }
            assert_eq!(event_types(&result), expected_events, "{name}");
            assert!(
                fs::read_dir(result.root.join("backups"))
                    .expect("read backups")
                    .next()
                    .is_none(),
                "{name} must not create a backup or rebuild"
            );
            let expected_digest = if scenario.current_is_approved {
                APPROVED_DIGEST
            } else {
                CURRENT_DIGEST
            };
            assert_eq!(
                fs::read_to_string(result.root.join("current-digest"))
                    .expect("read current digest"),
                expected_digest,
                "{name}"
            );
        }
    }

    #[test]
    fn updater_runtime_stops_safely_on_redis_backup_or_image_pull_failure() {
        for (name, scenario, error_code) in [
            (
                "redis backup",
                RuntimeScenario {
                    redis_backup_fails: true,
                    ..RuntimeScenario::default()
                },
                "REDIS_BACKUP_FAILED",
            ),
            (
                "image pull",
                RuntimeScenario {
                    image_pull_fails: true,
                    ..RuntimeScenario::default()
                },
                "IMAGE_PULL_FAILED",
            ),
        ] {
            let result = run_runtime(scenario);
            assert!(
                !result.output.status.success(),
                "{name}: {:?}",
                result.events
            );
            assert_eq!(
                result.events.last().expect("failure event")["error_code"],
                error_code,
                "{name}"
            );
            assert_eq!(
                fs::read_to_string(result.root.join("current-digest"))
                    .expect("read current digest"),
                CURRENT_DIGEST,
                "{name}"
            );
            assert!(
                !result.root.join("docker-compose.updater.yml").exists(),
                "{name}"
            );
        }
    }

    #[test]
    fn updater_runtime_rolls_back_start_health_and_setup_failures() {
        for (name, scenario) in [
            (
                "compose start",
                RuntimeScenario {
                    compose_start_fails: true,
                    ..RuntimeScenario::default()
                },
            ),
            (
                "health endpoint",
                RuntimeScenario {
                    health_fails: true,
                    ..RuntimeScenario::default()
                },
            ),
            (
                "setup and migration endpoint",
                RuntimeScenario {
                    setup_fails: true,
                    ..RuntimeScenario::default()
                },
            ),
        ] {
            let result = run_runtime(scenario);
            assert!(
                !result.output.status.success(),
                "{name}: {:?}",
                result.events
            );
            assert_eq!(
                event_types(&result).last(),
                Some(&"update_rolled_back"),
                "{name}: {:?}",
                result.events
            );
            assert_eq!(
                fs::read_to_string(result.root.join("current-digest"))
                    .expect("read rolled back digest"),
                CURRENT_DIGEST,
                "{name}"
            );
        }
    }

    #[test]
    fn updater_runtime_reports_when_automatic_rollback_and_backup_restore_fail() {
        let result = run_runtime(RuntimeScenario {
            health_fails: true,
            rollback_fails: true,
            ..RuntimeScenario::default()
        });

        assert!(
            !result.output.status.success(),
            "events: {:?}",
            result.events
        );
        assert_eq!(event_types(&result).last(), Some(&"update_failed"));
        assert_eq!(
            result.events.last().expect("failure event")["error_code"],
            "UPDATE_ROLLBACK_FAILED"
        );
    }
}
