use std::{
    collections::{BTreeMap, BTreeSet},
    sync::mpsc,
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use shell_escape::escape;

use crate::{
    error::{AppError, Result},
    security::{random_secret, sha256_hex},
    state::unix_timestamp,
    target::TargetExecutor,
};

const LOCK_STALE_SECONDS: i64 = 900;
const MANAGED_FILES: &[&str] = &[
    "docker-compose.yml",
    "docker-compose.updater.yml",
    "secrets.env",
    "downstream-credentials.env",
    "updater-credentials.env",
    "bin/meowai-deploy-upgrade-agent",
    "meowai-deploy-updater.sh",
    "data/state.json",
    "meowai-deploy-updater.service",
    "meowai-deploy-updater.timer",
];
const SENSITIVE_FILES: &[&str] = &[
    "secrets.env",
    "downstream-credentials.env",
    "updater-credentials.env",
];
const MANAGED_ENV_KEYS: &[&str] = &[
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
    "SESSION_SECRET",
    "CRYPTO_SECRET",
    "NEWAPI_ADMIN_PASSWORD",
    "KUMA_ADMIN_PASSWORD",
    "PUBLIC_STATUS_SOURCE_KEY",
    "MEOWAI_DEPLOYMENT_ID",
    "MEOWAI_INSTALLATION_GENERATION",
    "MEOWAI_CONTROL_PLANE_URL",
    "MEOWAI_REPORT_CREDENTIAL",
    "MEOWAI_PULL_CREDENTIAL",
    "MEOWAI_HEARTBEAT_INTERVAL_SECONDS",
    "MEOWAI_SNAPSHOT_INTERVAL_SECONDS",
    "MEOWAI_CURRENT_IMAGE_DIGEST",
    "MEOWAI_DEPLOYMENT_SCHEMA",
    "MEOWAI_UPDATER_SCHEMA",
    "MEOWAI_DATA_SCHEMA",
    "MEOWAI_CLI_SCHEMA",
    "MEOWAI_ALLOWED_IMAGE_REPOSITORY",
    "MEOWAI_CONTAINER_NAME",
    "MEOWAI_NEWAPI_PORT",
    "MEOWAI_KUMA_PORT",
    "MEOWAI_RELEASE_SCHEMA_VERSION",
    "MEOWAI_RELEASE_MANIFEST_PUBLIC_KEY",
    "MEOWAI_RELEASE_ARTIFACT_ALLOWED_HOSTS",
    "MEOWAI_UPDATER_SOCKET_PATH",
    "CHECKER_PROXY_URL",
    "CHECKER_ENCRYPTION_KEY",
    "CHECKER_FINGERPRINT_KEY",
    "CHECKER_ENCRYPTION_KEY_ID",
    "CHECKER_FINGERPRINT_KEY_ID",
];

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TargetFileObservation {
    pub exists: bool,
    pub regular: bool,
    pub symlink: bool,
    pub mode: String,
    pub uid: u64,
    pub gid: u64,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub keys: BTreeMap<String, TargetEnvKeyObservation>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TargetEnvKeyObservation {
    pub count: u32,
    pub non_empty: bool,
    pub value_sha256: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TargetServiceObservation {
    pub container_id: String,
    pub image_id: String,
    pub state: String,
    pub health: String,
    #[serde(default)]
    pub started_at: String,
    #[serde(default)]
    pub restart_count: u64,
    #[serde(default)]
    pub mounts: Vec<TargetMountObservation>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TargetMountObservation {
    pub destination: String,
    pub mount_type: String,
    pub name: String,
    pub source: String,
    pub read_write: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TargetPathIdentity {
    pub exists: bool,
    pub symlink: bool,
    pub device: u64,
    pub inode: u64,
    pub canonical_sha256: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TargetObservation {
    pub schema_version: u32,
    pub observed_at: i64,
    pub target_fingerprint: String,
    pub deployment_id: String,
    pub installation_generation: u32,
    pub directory_exists: bool,
    pub directory_symlink: bool,
    pub disk_available_bytes: u64,
    pub docker_available: bool,
    pub compose_v2_available: bool,
    #[serde(default)]
    pub docker_version: String,
    #[serde(default)]
    pub compose_version: String,
    pub systemd_available: bool,
    pub compose_valid: bool,
    pub compose_fingerprint: String,
    #[serde(default)]
    pub compose_project_name: String,
    #[serde(default)]
    pub external_dependency_fingerprints: BTreeMap<String, String>,
    pub postgres_select_1: bool,
    pub redis_ping: bool,
    pub newapi_status: bool,
    #[serde(default)]
    pub newapi_status_success: bool,
    #[serde(default)]
    pub local_health_status: bool,
    pub kuma_status: bool,
    pub upgrade_agent_active: bool,
    pub upgrade_timer_active: bool,
    #[serde(default)]
    pub agent_version: String,
    #[serde(default)]
    pub agent_schema: String,
    /// Whether the installed agent binary advertises the `--proof` repair
    /// capability. Binaries that predate the repair protocol cannot generate
    /// a target-applied proof and must be refreshed through the signed
    /// release engine before a credential rotation can run.
    #[serde(default)]
    pub agent_proof_capable: bool,
    #[serde(default)]
    pub files: BTreeMap<String, TargetFileObservation>,
    #[serde(default)]
    pub services: BTreeMap<String, TargetServiceObservation>,
    #[serde(default)]
    pub data_paths: BTreeMap<String, TargetPathIdentity>,
    #[serde(default)]
    pub project_volumes: Vec<String>,
    #[serde(default)]
    pub volume_identities: BTreeMap<String, String>,
    #[serde(default)]
    pub project_networks: Vec<String>,
    #[serde(default)]
    pub unknown_resources: Vec<String>,
}

impl TargetObservation {
    pub fn fingerprint(&self) -> String {
        let normalized = self.normalized_for_fingerprint();
        let encoded = serde_json::to_vec(&normalized).expect("target observation serializes");
        format!("sha256:{}", sha256_hex(&encoded))
    }

    /// Normalize live operational metrics that legitimately change between a
    /// reviewed plan and its execution without any managed resource drifting:
    /// observation time, free disk, container start times/restart counters,
    /// and the operational-state marker `data/state.json` whose content is
    /// expected to change with routine reporting. Managed configuration
    /// digests, container identities, image digests, health states, and data
    /// mount identities all remain part of the fingerprint.
    pub fn normalized_for_fingerprint(&self) -> Self {
        let mut normalized = self.clone();
        normalized.observed_at = 0;
        normalized.disk_available_bytes = 0;
        for service in normalized.services.values_mut() {
            service.started_at.clear();
            service.restart_count = 0;
        }
        if let Some(file) = normalized.files.get_mut("data/state.json") {
            file.sha256.clear();
            file.size = 0;
        }
        normalized
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BackupFileEntry {
    pub path: String,
    pub backup_path: String,
    pub existed: bool,
    pub sensitive: bool,
    pub mode: String,
    #[serde(default)]
    pub uid: u64,
    #[serde(default)]
    pub gid: u64,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub operation_id: String,
    pub created_at: i64,
    pub observation_fingerprint: String,
    pub files: Vec<BackupFileEntry>,
    #[serde(default)]
    pub systemd_files: Vec<BackupFileEntry>,
    #[serde(default)]
    pub data_backups: Vec<String>,
    pub resource_identity: BTreeMap<String, TargetPathIdentity>,
    #[serde(default)]
    pub volume_identities: BTreeMap<String, String>,
}

/// Persist a secret-free target checkpoint. The payload is deliberately
/// caller-supplied JSON so the application layer can add only hashes/state,
/// never credentials or command output.
pub fn write_journal(
    executor: &TargetExecutor,
    operation_id: &str,
    phase: &str,
    metadata: &serde_json::Value,
) -> Result<()> {
    validate_identifier("operation id", operation_id)?;
    validate_identifier("repair phase", phase)?;
    let mut journal = serde_json::Map::new();
    journal.insert("schema_version".to_owned(), serde_json::json!(1));
    journal.insert("operation_id".to_owned(), serde_json::json!(operation_id));
    journal.insert("phase".to_owned(), serde_json::json!(phase));
    if let Some(object) = metadata.as_object() {
        for (key, value) in object {
            if !sensitive_key(key) {
                journal.insert(key.clone(), redact_value(value));
            }
        }
    }
    let bytes = serde_json::to_vec_pretty(&serde_json::Value::Object(journal))
        .map_err(|error| AppError::State(format!("serialize target repair journal: {error}")))?;
    executor.write_file(
        &format!(".repair/{operation_id}/journal.json"),
        &bytes,
        true,
    )
}

pub struct TargetOperationLock {
    executor: TargetExecutor,
    token: String,
    stop: Option<mpsc::Sender<()>>,
    heartbeat: Option<thread::JoinHandle<()>>,
}

impl TargetOperationLock {
    pub fn acquire(executor: &TargetExecutor, kind: &str, operation_id: &str) -> Result<Self> {
        validate_identifier("operation kind", kind)?;
        validate_identifier("operation id", operation_id)?;
        let token = random_secret(32);
        acquire_lock(executor, &token, kind, operation_id)?;
        let (stop, receiver) = mpsc::channel();
        let heartbeat_executor = executor.clone();
        let heartbeat_token = token.clone();
        let heartbeat = thread::spawn(move || {
            while receiver.recv_timeout(Duration::from_secs(30)).is_err() {
                let _ = refresh_lock(&heartbeat_executor, &heartbeat_token);
            }
        });
        Ok(Self {
            executor: executor.clone(),
            token,
            stop: Some(stop),
            heartbeat: Some(heartbeat),
        })
    }
}

impl Drop for TargetOperationLock {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.join();
        }
        let token = quote(&self.token);
        let _ = self.executor.run_in_directory(&format!(
            r#"set -eu
lock=.meowai-operation.lock
token={token}
if [ "$(sed -n '1p' "$lock/owner" 2>/dev/null || true)" = "$token" ]; then
  rm -f "$lock/owner" "$lock/kind" "$lock/operation_id" "$lock/heartbeat"
  rmdir "$lock" 2>/dev/null || true
fi"#,
        ));
    }
}

pub fn observe(
    executor: &TargetExecutor,
    project: &str,
    newapi_port: u16,
    kuma_port: u16,
) -> Result<TargetObservation> {
    validate_identifier("Compose project", project)?;
    let output = executor.run_in_directory(&observation_script(project, newapi_port, kuma_port))?;
    let target_fingerprint = executor.fingerprint()?;
    let raw = String::from_utf8_lossy(&output.stdout);
    parse_observation(&raw, target_fingerprint)
}

pub fn create_b1_backup(
    executor: &TargetExecutor,
    operation_id: &str,
    observation: &TargetObservation,
) -> Result<BackupManifest> {
    validate_identifier("operation id", operation_id)?;
    let operation_dir = format!(".repair/{operation_id}");
    let backup_dir = format!("{operation_dir}/backup");
    executor.run_in_directory(&format!(
        r#"set -eu
umask 077
operation_dir={operation_dir}
backup_dir={backup_dir}
if [ -L "$operation_dir" ] || [ -L "$backup_dir" ]; then
  echo 'repair backup path must not be a symlink' >&2
  exit 1
fi
mkdir -p "$backup_dir/systemd" "$backup_dir/data"
chmod 700 .repair "$operation_dir" "$backup_dir" "$backup_dir/systemd"
for file in {managed_files}; do
  if [ -L "$file" ]; then
    echo "managed file is a symlink: $file" >&2
    exit 1
  fi
  if [ -f "$file" ]; then
    mkdir -p "$(dirname "$backup_dir/$file")"
    cp -p "$file" "$backup_dir/$file"
    case "$file" in
      secrets.env|downstream-credentials.env|updater-credentials.env)
        chmod 600 "$backup_dir/$file"
        ;;
    esac
  fi
done
for unit in meowai-deploy-updater.service meowai-deploy-updater.timer; do
  source="/etc/systemd/system/$unit"
  if [ -L "$source" ]; then
    echo "managed systemd unit is a symlink: $source" >&2
    exit 1
  fi
  if [ -f "$source" ]; then
    cp -p "$source" "$backup_dir/systemd/$unit"
  fi
done
find "$backup_dir" -type d -exec chmod 700 {{}} +
if sync -f "$backup_dir" 2>/dev/null; then :; else sync; fi"#,
        operation_dir = quote(&operation_dir),
        backup_dir = quote(&backup_dir),
        managed_files = MANAGED_FILES
            .iter()
            .map(|value| quote(value))
            .collect::<Vec<_>>()
            .join(" "),
    ))?;

    let files: Vec<BackupFileEntry> = MANAGED_FILES
        .iter()
        .map(|path| {
            let observed = observation.files.get(*path).cloned().unwrap_or_default();
            BackupFileEntry {
                path: (*path).to_owned(),
                backup_path: format!("{backup_dir}/{path}"),
                existed: observed.exists,
                sensitive: SENSITIVE_FILES.contains(path),
                mode: observed.mode,
                uid: observed.uid,
                gid: observed.gid,
                size: observed.size,
                sha256: observed.sha256,
            }
        })
        .collect();
    let systemd_files = observe_systemd_backup_entries(executor, &backup_dir)?;
    for entry in files.iter().chain(systemd_files.iter()) {
        verify_backup_entry(executor, entry)?;
    }
    let manifest = BackupManifest {
        schema_version: 1,
        operation_id: operation_id.to_owned(),
        created_at: unix_timestamp(),
        observation_fingerprint: observation.fingerprint(),
        files,
        systemd_files,
        data_backups: Vec::new(),
        resource_identity: observation.data_paths.clone(),
        volume_identities: observation.volume_identities.clone(),
    };
    let content = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| AppError::State(format!("serialize repair backup manifest: {error}")))?;
    executor.write_file(
        &format!("{operation_dir}/backup-manifest.json"),
        &content,
        true,
    )?;
    Ok(manifest)
}

/// Extend a B1 manifest with explicit database/data backups for structural or
/// schema-changing repair actions. This never removes volumes or runs
/// `docker compose down -v`.
pub fn create_b2_backup(
    executor: &TargetExecutor,
    operation_id: &str,
    observation: &TargetObservation,
    project: &str,
) -> Result<BackupManifest> {
    validate_identifier("operation id", operation_id)?;
    validate_identifier("Compose project", project)?;
    let mut manifest = create_b1_backup(executor, operation_id, observation)?;
    let data_dir = format!(".repair/{operation_id}/backup/data");
    executor.run_in_directory(&format!(
        r#"set -eu
mkdir -p {data_dir}
chmod 700 {data_dir}
project={project}
compose_files='-f docker-compose.yml'
[ ! -f docker-compose.updater.yml ] || compose_files="$compose_files -f docker-compose.updater.yml"
pg=$(docker compose --env-file secrets.env -p "$project" $compose_files ps -q postgres)
test -n "$pg"
docker exec "$pg" sh -c 'pg_dumpall --clean --if-exists' > {data_dir}/postgres.sql
chmod 600 {data_dir}/postgres.sql
redis=$(docker compose --env-file secrets.env -p "$project" $compose_files ps -q redis)
test -n "$redis"
docker exec "$redis" sh -c 'redis-cli --no-auth-warning -a "$REDIS_PASSWORD" SAVE' >/dev/null
docker cp "$redis:/data/dump.rdb" {data_dir}/redis-dump.rdb
chmod 600 {data_dir}/redis-dump.rdb
if [ -d data ]; then find data -xdev -type f -print | sort > {data_dir}/data-inventory.txt; else : > {data_dir}/data-inventory.txt; fi
chmod 600 {data_dir}/data-inventory.txt
if sync -f {data_dir} 2>/dev/null; then :; else sync; fi"#,
        data_dir = quote(&data_dir),
        project = quote(project),
    ))?;
    manifest.data_backups = vec![
        format!("{data_dir}/postgres.sql"),
        format!("{data_dir}/redis-dump.rdb"),
        format!("{data_dir}/data-inventory.txt"),
    ];
    let content = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| AppError::State(format!("serialize repair B2 manifest: {error}")))?;
    executor.write_file(
        &format!(".repair/{operation_id}/backup-manifest.json"),
        &content,
        true,
    )?;
    Ok(manifest)
}

pub fn atomic_replace(
    executor: &TargetExecutor,
    operation_id: &str,
    path: &str,
    content: &[u8],
    mode: u32,
) -> Result<()> {
    validate_identifier("operation id", operation_id)?;
    if !MANAGED_FILES.contains(&path) || !matches!(mode, 0o600 | 0o644 | 0o755) {
        return Err(AppError::State(
            "REPAIR_MANAGED_PATH_NOT_ALLOWED".to_owned(),
        ));
    }
    let next = format!("{path}.next-{operation_id}");
    executor.write_file(&next, content, true)?;
    executor.run_in_directory(&format!(
        r#"set -eu
next={next}
destination={destination}
[ -f "$next" ] && [ ! -L "$next" ]
chmod {mode:o} "$next"
if sync -f "$next" 2>/dev/null; then :; else sync; fi
mv -f "$next" "$destination"
if sync -f . 2>/dev/null; then :; else sync; fi"#,
        next = quote(&next),
        destination = quote(path),
    ))?;
    Ok(())
}

pub fn restore_b1_backup(
    executor: &TargetExecutor,
    operation_id: &str,
    manifest: &BackupManifest,
) -> Result<()> {
    validate_identifier("operation id", operation_id)?;
    if manifest.operation_id != operation_id {
        return Err(AppError::State(
            "REPAIR_BACKUP_IDENTITY_MISMATCH".to_owned(),
        ));
    }
    for entry in &manifest.files {
        if !MANAGED_FILES.contains(&entry.path.as_str()) {
            return Err(AppError::State("REPAIR_BACKUP_PATH_NOT_ALLOWED".to_owned()));
        }
        if entry.existed {
            let source = &entry.backup_path;
            verify_backup_entry(executor, entry)?;
            executor.run_in_directory(&format!(
                r#"set -eu
source={source}
destination={destination}
[ -f "$source" ] && [ ! -L "$source" ]
temporary="$destination.restore-{operation_id}"
cp "$source" "$temporary"
chmod {mode} "$temporary"
if sync -f "$temporary" 2>/dev/null; then :; else sync; fi
mv -f "$temporary" "$destination"
if sync -f . 2>/dev/null; then :; else sync; fi"#,
                source = quote(source),
                destination = quote(&entry.path),
                operation_id = operation_id,
                mode = if entry.mode.chars().all(|ch| ch.is_ascii_digit()) && !entry.mode.is_empty()
                {
                    entry.mode.as_str()
                } else if entry.sensitive {
                    "600"
                } else {
                    "644"
                },
            ))?;
            if entry.uid > 0 || entry.gid > 0 {
                executor.run_in_directory(&format!(
                    "chown {}:{} {}",
                    entry.uid,
                    entry.gid,
                    quote(&entry.path)
                ))?;
            }
        } else {
            executor.run_in_directory(&format!("rm -f {}", quote(&entry.path)))?;
        }
    }
    for entry in &manifest.systemd_files {
        if !matches!(
            entry.path.as_str(),
            "/etc/systemd/system/meowai-deploy-updater.service"
                | "/etc/systemd/system/meowai-deploy-updater.timer"
        ) {
            return Err(AppError::State(
                "REPAIR_BACKUP_SYSTEMD_PATH_NOT_ALLOWED".to_owned(),
            ));
        }
        let unit = entry.path.rsplit('/').next().unwrap_or_default();
        let script = if entry.existed {
            let ownership = if entry.uid > 0 || entry.gid > 0 {
                format!(
                    "\nchown {}:{} -- {}",
                    entry.uid,
                    entry.gid,
                    quote(&entry.path)
                )
            } else {
                String::new()
            };
            format!(
                "set -eu\nsource={source}\ndestination={destination}\n[ -f \"$source\" ] && [ ! -L \"$source\" ]\ninstall -m {mode} \"$source\" \"$destination\"{ownership}",
                source = quote(&format!(".repair/{operation_id}/backup/systemd/{unit}")),
                destination = quote(&entry.path),
                ownership = ownership,
                mode = if entry.mode.chars().all(|ch| ch.is_ascii_digit()) && !entry.mode.is_empty()
                {
                    entry.mode.as_str()
                } else {
                    "644"
                },
            )
        } else {
            format!("rm -f {}", quote(&entry.path))
        };
        executor.run_in_directory(&script)?;
    }
    if !manifest.systemd_files.is_empty() {
        executor.run_in_directory(
            "if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload; fi",
        )?;
    }
    Ok(())
}

fn verify_backup_entry(executor: &TargetExecutor, entry: &BackupFileEntry) -> Result<()> {
    if !entry.existed {
        return executor.run_in_directory(&format!(
            "if [ -e {path} ] || [ -L {path} ]; then echo 'REPAIR_BACKUP_UNEXPECTED_FILE' >&2; exit 1; fi",
            path = quote(&entry.backup_path),
        )).map(|_| ());
    }
    if entry.sha256.is_empty() {
        return Err(AppError::State(
            "REPAIR_BACKUP_MANIFEST_HASH_MISSING".to_owned(),
        ));
    }
    executor.run_in_directory(&format!(
        r#"set -eu
path={path}
[ -f "$path" ] && [ ! -L "$path" ]
size=$(stat -c '%s' "$path" 2>/dev/null || stat -f '%z' "$path")
mode=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path")
if command -v sha256sum >/dev/null 2>&1; then hash=$(sha256sum "$path" | awk '{{print $1}}'); else hash=$(shasum -a 256 "$path" | awk '{{print $1}}'); fi
[ "$size" = {size} ]
[ "$mode" = {mode} ]
[ "$hash" = {hash} ]"#,
        path = quote(&entry.backup_path),
        size = quote(&entry.size.to_string()),
        mode = quote(&entry.mode),
        hash = quote(&entry.sha256),
    ))
    .map(|_| ())
}

fn observe_systemd_backup_entries(
    executor: &TargetExecutor,
    backup_dir: &str,
) -> Result<Vec<BackupFileEntry>> {
    let output = executor.run_in_directory(
        r#"set -eu
for unit in meowai-deploy-updater.service meowai-deploy-updater.timer; do
  source="/etc/systemd/system/$unit"
  if [ -f "$source" ] && [ ! -L "$source" ]; then
    mode=$(stat -c '%a' "$source" 2>/dev/null || stat -f '%Lp' "$source")
    size=$(stat -c '%s' "$source" 2>/dev/null || stat -f '%z' "$source")
    if command -v sha256sum >/dev/null 2>&1; then sha=$(sha256sum "$source" | awk '{print $1}'); else sha=$(shasum -a 256 "$source" | awk '{print $1}'); fi
    uid=$(stat -c '%u' "$source" 2>/dev/null || stat -f '%u' "$source")
    gid=$(stat -c '%g' "$source" 2>/dev/null || stat -f '%g' "$source")
    printf '%s|1|%s|%s|%s|%s|%s\n' "$unit" "$mode" "$uid" "$gid" "$size" "$sha"
  else
    printf '%s|0|||\n' "$unit"
  fi
done"#,
    )?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            let fields = line.split('|').collect::<Vec<_>>();
            if fields.len() != 5 && fields.len() != 7 {
                return Err(AppError::State("REPAIR_SYSTEMD_BACKUP_INVALID".to_owned()));
            }
            let (uid, gid, size, sha256) = if fields.len() == 7 {
                (
                    fields[3].parse().unwrap_or(0),
                    fields[4].parse().unwrap_or(0),
                    fields[5].parse().unwrap_or(0),
                    fields[6].to_owned(),
                )
            } else {
                (0, 0, fields[3].parse().unwrap_or(0), fields[4].to_owned())
            };
            Ok(BackupFileEntry {
                path: format!("/etc/systemd/system/{}", fields[0]),
                backup_path: format!("{backup_dir}/systemd/{}", fields[0]),
                existed: fields[1] == "1",
                sensitive: false,
                mode: fields[2].to_owned(),
                uid,
                gid,
                size,
                sha256,
            })
        })
        .collect()
}

pub fn verify_resource_identity(
    before: &BTreeMap<String, TargetPathIdentity>,
    after: &BTreeMap<String, TargetPathIdentity>,
) -> Result<()> {
    for (path, expected) in before {
        let Some(actual) = after.get(path) else {
            return Err(AppError::State(format!(
                "PERSISTENT_RESOURCE_IDENTITY_CHANGED: missing {path}"
            )));
        };
        if expected != actual {
            return Err(AppError::State(format!(
                "PERSISTENT_RESOURCE_IDENTITY_CHANGED: {path}"
            )));
        }
    }
    Ok(())
}

pub fn verify_volume_identity(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Result<()> {
    for (name, expected) in before {
        let Some(actual) = after.get(name) else {
            return Err(AppError::State(format!(
                "PERSISTENT_RESOURCE_IDENTITY_CHANGED: missing volume {name}"
            )));
        };
        if expected != actual {
            return Err(AppError::State(format!(
                "PERSISTENT_RESOURCE_IDENTITY_CHANGED: volume {name}"
            )));
        }
    }
    Ok(())
}

pub fn verify_service_mount_identity(
    before: &BTreeMap<String, TargetServiceObservation>,
    after: &BTreeMap<String, TargetServiceObservation>,
) -> Result<()> {
    for (service, expected) in before {
        let Some(actual) = after.get(service) else {
            return Err(AppError::State(format!(
                "PERSISTENT_RESOURCE_IDENTITY_CHANGED: missing service {service}"
            )));
        };
        if expected.mounts != actual.mounts {
            return Err(AppError::State(format!(
                "PERSISTENT_RESOURCE_IDENTITY_CHANGED: mounts {service}"
            )));
        }
    }
    Ok(())
}

/// Generate the activation proof through the protected local updater socket or
/// the signed target agent binary. The CLI must never calculate it from the
/// newly issued secret.
pub fn target_applied_proof_with_mode(
    executor: &TargetExecutor,
    operation_id: &str,
    generation: u32,
    challenge: &str,
    observation_fingerprint: &str,
) -> Result<(String, &'static str)> {
    validate_identifier("operation id", operation_id)?;
    validate_identifier("target challenge", challenge)?;
    validate_fingerprint(observation_fingerprint)?;
    let agent_script = format!(
        r#"set +e
operation_id={operation_id}
generation={generation}
challenge={challenge}
observation_fingerprint={observation_fingerprint}
socket=$(sed -n 's/^MEOWAI_UPDATER_SOCKET_PATH=//p' downstream-credentials.env secrets.env updater-credentials.env 2>/dev/null | head -n 1)
token=$(sed -n 's/^MEOWAI_UPDATER_LOCAL_CREDENTIAL=//p' updater-credentials.env 2>/dev/null | head -n 1)
nonce=''
if command -v openssl >/dev/null 2>&1; then nonce=$(openssl rand -hex 16 2>/dev/null || true); fi
case "$socket" in /run/*|run/*|/*) ;; *) socket='' ;; esac
if [ -n "$socket" ] && [ -n "$token" ] && [ -n "$nonce" ] && command -v curl >/dev/null 2>&1; then
  request=$(printf '{{"operation_id":"%s","generation":%s,"challenge":"%s","observation_fingerprint":"%s","nonce":"%s","issued_at":%s}}' "$operation_id" "$generation" "$challenge" "$observation_fingerprint" "$nonce" "$(date +%s)")
  response=$(curl --silent --max-time 5 --unix-socket "$socket" -w '\n__MEOWAI_STATUS__%{{http_code}}' \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    --data-binary "$request" http://localhost/repair/proof 2>/dev/null || true)
  status=$(printf '%s' "$response" | sed -n 's/^__MEOWAI_STATUS__//p' | tail -n 1)
  response=$(printf '%s' "$response" | sed '/^__MEOWAI_STATUS__/d')
  proof=$(printf '%s' "$response" | sed -n 's/.*"proof":"\([0-9a-f]\{{64\}}\)".*/\1/p')
  case "$status" in
    2??) case "$proof" in [0-9a-f][0-9a-f]*) [ "${{#proof}}" = 64 ] && printf 'AGENT|%s\n' "$proof" || printf 'AGENT_INVALID\n' ;; esac ;;
    404|501|000|'') : ;;
    *) printf 'AGENT_ERROR\n' ;;
  esac
fi
if [ -x bin/meowai-deploy-upgrade-agent ]; then
  proof=$(bin/meowai-deploy-upgrade-agent agent --root . --auto --proof \
    --operation-id {operation_id} --generation {generation} --challenge {challenge} \
    --observation-fingerprint {observation_fingerprint} 2>/dev/null || true)
  case "$proof" in
    [0-9a-f][0-9a-f]*) [ "${{#proof}}" = 64 ] && printf 'AGENT|%s\n' "$proof" || printf 'AGENT_INVALID\n' ;;
  esac
fi
exit 0"#,
        operation_id = quote(operation_id),
        generation = generation,
        challenge = quote(challenge),
        observation_fingerprint = quote(observation_fingerprint),
    );
    let agent_output = executor.run_in_directory(&agent_script)?;
    if let Some(proof) = String::from_utf8_lossy(&agent_output.stdout)
        .lines()
        .find_map(|line| {
            line.strip_prefix("AGENT|").filter(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        })
    {
        return Ok((proof.to_owned(), "agent"));
    }
    let agent_stdout = String::from_utf8_lossy(&agent_output.stdout);
    if agent_stdout
        .lines()
        .any(|line| matches!(line, "AGENT_INVALID" | "AGENT_ERROR"))
    {
        return Err(AppError::State("TARGET_AGENT_PROOF_FAILED".to_owned()));
    }
    Err(AppError::State("TARGET_AGENT_PROOF_UNAVAILABLE".to_owned()))
}

fn acquire_lock(
    executor: &TargetExecutor,
    token: &str,
    kind: &str,
    operation_id: &str,
) -> Result<()> {
    executor.run_in_directory(&format!(
        r#"set -eu
lock=.meowai-operation.lock
legacy=.meowai-upgrade.lock
token={token}
kind={kind}
operation_id={operation_id}
now=$(date +%s)
stale_after={stale_after}
read_updated() {{
  value=$(cat "$1/heartbeat" 2>/dev/null || sed -n '2p' "$1/owner" 2>/dev/null || true)
  case "$value" in ''|*[!0-9]*) value=0 ;; esac
  printf '%s' "$value"
}}
for existing in "$legacy" "$lock"; do
  if [ -d "$existing" ]; then
    updated=$(read_updated "$existing")
    if [ $((now - updated)) -le "$stale_after" ]; then
      echo 'TARGET_OPERATION_CONFLICT' >&2
      exit 1
    fi
    stale="$existing.stale-$token"
    if ! mv "$existing" "$stale" 2>/dev/null; then
      echo 'TARGET_OPERATION_LOCK_CHANGED' >&2
      exit 1
    fi
    rm -rf "$stale"
  elif [ -e "$existing" ]; then
    echo 'TARGET_OPERATION_LOCK_INVALID' >&2
    exit 1
  fi
done
mkdir "$lock"
if [ -e "$legacy" ]; then
  rmdir "$lock" 2>/dev/null || true
  echo 'TARGET_OPERATION_CONFLICT' >&2
  exit 1
fi
chmod 700 "$lock"
printf '%s\n' "$token" > "$lock/owner"
printf '%s\n' "$kind" > "$lock/kind"
printf '%s\n' "$operation_id" > "$lock/operation_id"
printf '%s\n' "$now" > "$lock/heartbeat"
chmod 600 "$lock/owner" "$lock/kind" "$lock/operation_id" "$lock/heartbeat""#,
        token = quote(token),
        kind = quote(kind),
        operation_id = quote(operation_id),
        stale_after = LOCK_STALE_SECONDS,
    ))?;
    Ok(())
}

fn refresh_lock(executor: &TargetExecutor, token: &str) -> Result<()> {
    executor.run_in_directory(&format!(
        r#"set -eu
lock=.meowai-operation.lock
token={token}
[ "$(sed -n '1p' "$lock/owner" 2>/dev/null || true)" = "$token" ] || exit 0
now=$(date +%s)
printf '%s\n' "$now" > "$lock/heartbeat.next-$token"
chmod 600 "$lock/heartbeat.next-$token"
mv "$lock/heartbeat.next-$token" "$lock/heartbeat""#,
        token = quote(token),
    ))?;
    Ok(())
}

fn observation_script(project: &str, newapi_port: u16, kuma_port: u16) -> String {
    let project = quote(project);
    let files = MANAGED_FILES
        .iter()
        .map(|value| quote(value))
        .collect::<Vec<_>>()
        .join(" ");
    let env_keys = MANAGED_ENV_KEYS
        .iter()
        .map(|value| quote(value))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"set +e
project={project}
hash_file() {{ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{{print $1}}'; else shasum -a 256 "$1" | awk '{{print $1}}'; fi; }}
stat_mode() {{ stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || printf 0; }}
stat_uid() {{ stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1" 2>/dev/null || printf 0; }}
stat_gid() {{ stat -c '%g' "$1" 2>/dev/null || stat -f '%g' "$1" 2>/dev/null || printf 0; }}
stat_size() {{ stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1" 2>/dev/null || printf 0; }}
stat_dev() {{ stat -c '%d' "$1" 2>/dev/null || stat -f '%d' "$1" 2>/dev/null || printf 0; }}
stat_ino() {{ stat -c '%i' "$1" 2>/dev/null || stat -f '%i' "$1" 2>/dev/null || printf 0; }}
bool() {{ if "$@" >/dev/null 2>&1; then printf 1; else printf 0; fi; }}
printf 'META|directory_exists|%s\n' "$(bool test -d .)"
printf 'META|directory_symlink|%s\n' "$(bool test -L .)"
disk=$(df -Pk . 2>/dev/null | awk 'NR==2 {{printf "%.0f", $4 * 1024}}')
printf 'META|disk_available_bytes|%s\n' "${{disk:-0}}"
printf 'META|docker_available|%s\n' "$(bool docker info)"
printf 'META|compose_v2_available|%s\n' "$(bool docker compose version)"
docker_version=$(docker version --format '{{{{.Server.Version}}}}' 2>/dev/null | tr -cd '[:alnum:]._+-' || true)
printf 'META|docker_version|%s\n' "$docker_version"
compose_version=$(docker compose version --short 2>/dev/null | tr -cd '[:alnum:]._+-' || true)
printf 'META|compose_version|%s\n' "$compose_version"
printf 'META|systemd_available|%s\n' "$(bool test -d /run/systemd/system)"
printf 'META|compose_project|%s\n' "$project"
for file in {files}; do
  if [ -e "$file" ] || [ -L "$file" ]; then
    regular=$(bool test -f "$file")
    symlink=$(bool test -L "$file")
    sha=''
    [ "$regular" = 1 ] && [ "$symlink" = 0 ] && sha=$(hash_file "$file" 2>/dev/null || true)
    printf 'FILE|%s|1|%s|%s|%s|%s|%s|%s|%s\n' "$file" "$regular" "$symlink" "$(stat_mode "$file")" "$(stat_uid "$file")" "$(stat_gid "$file")" "$(stat_size "$file")" "$sha"
  else
    printf 'FILE|%s|0|0|0|0|0|0|0|\n' "$file"
  fi
done
for file in secrets.env downstream-credentials.env updater-credentials.env; do
  [ -f "$file" ] && [ ! -L "$file" ] || continue
  for key in {env_keys}; do
    count=$(awk -F= -v key="$key" '$1 == key {{count++}} END {{print count+0}}' "$file")
    nonempty=$(awk -F= -v key="$key" '$1 == key && length(substr($0, index($0,"=")+1)) > 0 {{found=1}} END {{print found+0}}' "$file")
    value_sha=''
    if [ "$count" = 1 ] && [ "$nonempty" = 1 ]; then
      value_file=$(mktemp "/tmp/meowai-repair-value.XXXXXX")
      trap 'rm -f "$value_file"' EXIT HUP INT TERM
      awk -F= -v key="$key" '$1 == key {{print substr($0, index($0,"=")+1)}}' "$file" > "$value_file"
      value_sha=$(hash_file "$value_file" 2>/dev/null || true)
      rm -f "$value_file"
    fi
    [ "$count" = 0 ] || printf 'ENV|%s|%s|%s|%s|%s\n' "$file" "$key" "$count" "$nonempty" "$value_sha"
  done
done
for key in POSTGRES_HOST POSTGRES_PORT REDIS_HOST REDIS_PORT DATABASE_URL REDIS_URL; do
  value=$(awk -F= -v key="$key" '$1 == key {{print substr($0, index($0,"=")+1); exit}}' secrets.env 2>/dev/null || true)
  [ -n "$value" ] || continue
  value_file=$(mktemp "/tmp/meowai-repair-endpoint.XXXXXX")
  printf '%s' "$value" > "$value_file"
  value_sha=$(hash_file "$value_file" 2>/dev/null || true)
  rm -f "$value_file"
  [ -n "$value_sha" ] && printf 'ENDPOINT|%s|%s\n' "$key" "$value_sha"
done
if [ -f downstream-credentials.env ] && [ ! -L downstream-credentials.env ]; then
  deployment_id=$(sed -n 's/^MEOWAI_DEPLOYMENT_ID=//p' downstream-credentials.env)
  generation=$(sed -n 's/^MEOWAI_INSTALLATION_GENERATION=//p' downstream-credentials.env)
  case "$generation" in ''|*[!0-9]*) generation=0 ;; esac
  printf 'META|deployment_id|%s\n' "$deployment_id"
  printf 'META|installation_generation|%s\n' "$generation"
else
  printf 'META|deployment_id|\n'
  printf 'META|installation_generation|0\n'
fi
compose_valid=0
compose_sha=''
if [ -f docker-compose.yml ] && [ -f secrets.env ]; then
  compose_json=$(mktemp "/tmp/meowai-repair-compose.XXXXXX")
  if docker compose --env-file secrets.env -p "$project" -f docker-compose.yml $([ -f docker-compose.updater.yml ] && printf '%s' '-f docker-compose.updater.yml') config --format json > "$compose_json" 2>/dev/null; then
    compose_valid=1
    compose_sha=$(hash_file "$compose_json" 2>/dev/null || true)
  fi
  rm -f "$compose_json"
fi
printf 'META|compose_valid|%s\n' "$compose_valid"
printf 'META|compose_fingerprint|%s\n' "$compose_sha"
for container in $(docker ps -aq --filter "label=com.docker.compose.project=$project" 2>/dev/null); do
  service=$(docker inspect --format '{{{{index .Config.Labels "com.docker.compose.service"}}}}' "$container" 2>/dev/null || true)
  cid=$(docker inspect --format '{{{{.Id}}}}' "$container" 2>/dev/null || true)
  image=$(docker inspect --format '{{{{.Image}}}}' "$container" 2>/dev/null || true)
  state=$(docker inspect --format '{{{{.State.Status}}}}' "$container" 2>/dev/null || true)
  health=$(docker inspect --format '{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}}' "$container" 2>/dev/null || true)
  started_at=$(docker inspect --format '{{{{.State.StartedAt}}}}' "$container" 2>/dev/null | tr -cd '[:alnum:][:space:]:+.-' || true)
  restart_count=$(docker inspect --format '{{{{.RestartCount}}}}' "$container" 2>/dev/null || printf 0)
  case "$restart_count" in ''|*[!0-9]*) restart_count=0 ;; esac
  printf 'SERVICE|%s|%s|%s|%s|%s|%s|%s\n' "$service" "$cid" "$image" "$state" "$health" "$started_at" "$restart_count"
  for mount in $(docker inspect --format '{{{{range .Mounts}}}}{{{{.Destination}}}}|{{{{.Type}}}}|{{{{.Name}}}}|{{{{.Source}}}}|{{{{.RW}}}} {{{{end}}}}' "$container" 2>/dev/null); do
    printf '%s\n' "$mount" | while IFS='|' read -r destination mount_type name source read_write; do
      [ -n "$destination" ] && printf 'MOUNT|%s|%s|%s|%s|%s|%s\n' "$service" "$destination" "$mount_type" "$name" "$source" "$read_write"
    done
  done
done
for name in data/newapi data/postgres data/redis data/uptime-kuma; do
  if [ -e "$name" ] || [ -L "$name" ]; then
    symlink=$(bool test -L "$name")
    canonical=$(cd "$name" 2>/dev/null && pwd -P || true)
    canonical_sha=''
    if [ -n "$canonical" ]; then
      canonical_file=$(mktemp "/tmp/meowai-repair-path.XXXXXX")
      printf '%s' "$canonical" > "$canonical_file"
      canonical_sha=$(hash_file "$canonical_file" 2>/dev/null || true)
      rm -f "$canonical_file"
    fi
    printf 'PATH|%s|1|%s|%s|%s|%s\n' "$name" "$symlink" "$(stat_dev "$name")" "$(stat_ino "$name")" "$canonical_sha"
  else
    printf 'PATH|%s|0|0|0|0|\n' "$name"
  fi
done
docker volume ls -q --filter "label=com.docker.compose.project=$project" 2>/dev/null | while IFS= read -r name; do
  [ -n "$name" ] || continue
  printf 'VOLUME|%s\n' "$name"
  volume_meta=$(docker volume inspect --format '{{{{index .Labels "com.docker.compose.project"}}}}|{{{{.Mountpoint}}}}' "$name" 2>/dev/null || true)
  label=$(printf '%s' "$volume_meta" | cut -d'|' -f1)
  mountpoint=$(printf '%s' "$volume_meta" | cut -d'|' -f2-)
  mount_hash=''
  if [ -n "$mountpoint" ]; then
    volume_file=$(mktemp "/tmp/meowai-repair-volume.XXXXXX")
    printf '%s' "$mountpoint" > "$volume_file"
    mount_hash=$(hash_file "$volume_file" 2>/dev/null || true)
    rm -f "$volume_file"
  fi
  printf 'VOLUME_ID|%s|%s|%s\n' "$name" "$label" "$mount_hash"
done
docker network ls --format '{{{{.Name}}}}' --filter "label=com.docker.compose.project=$project" 2>/dev/null | while IFS= read -r name; do [ -n "$name" ] && printf 'NETWORK|%s\n' "$name"; done
pg_container="${{project}}-postgres"
redis_container="${{project}}-redis"
printf 'META|postgres_select_1|%s\n' "$(bool docker exec "$pg_container" psql -U meowai -d newapi -tAc 'SELECT 1')"
printf 'META|redis_ping|%s\n' "$(bool docker exec "$redis_container" sh -c 'redis-cli -a "$REDIS_PASSWORD" ping | grep -q PONG')"
newapi_status_body=$(curl --fail --silent --max-time 5 http://127.0.0.1:{newapi_port}/api/status 2>/dev/null || true)
[ -n "$newapi_status_body" ] && printf 'META|newapi_status|1\n' || printf 'META|newapi_status|0\n'
if command -v jq >/dev/null 2>&1; then
  printf 'META|newapi_status_success|%s\n' "$(printf '%s' "$newapi_status_body" | jq -e '.success == true' >/dev/null 2>&1 && printf 1 || printf 0)"
else
  printf 'META|newapi_status_success|%s\n' "$(printf '%s' "$newapi_status_body" | tr -d '[:space:]' | grep -q '"success":true' && printf 1 || printf 0)"
fi
pull_credential=$(sed -n 's/^MEOWAI_PULL_CREDENTIAL=//p' downstream-credentials.env 2>/dev/null | head -n 1)
health_nonce=$(openssl rand -hex 8 2>/dev/null || printf '%s' "$$")
health_challenge="repair-observation-$(date +%s)-$health_nonce"
printf 'META|local_health_status|%s\n' "$(bool curl --fail --silent --max-time 5 -H "Authorization: Bearer $pull_credential" -H "X-MeowAI-Challenge: $health_challenge" http://127.0.0.1:{newapi_port}/api/meowai-deploy/health)"
printf 'META|kuma_status|%s\n' "$(bool curl --fail --silent --max-time 5 http://127.0.0.1:{kuma_port}/api/entry-page)"
agent_service_ready=0
if systemctl is-enabled --quiet meowai-deploy-updater.service 2>/dev/null || systemctl is-active --quiet meowai-deploy-updater.service 2>/dev/null; then agent_service_ready=1; fi
printf 'META|upgrade_agent_active|%s\n' "$agent_service_ready"
timer_ready=0
if systemctl is-enabled --quiet meowai-deploy-updater.timer 2>/dev/null && systemctl is-active --quiet meowai-deploy-updater.timer 2>/dev/null; then timer_ready=1; fi
printf 'META|upgrade_timer_active|%s\n' "$timer_ready"
agent_version=''
agent_proof_capable=0
if [ -x bin/meowai-deploy-upgrade-agent ]; then
  agent_version=$(bin/meowai-deploy-upgrade-agent --version 2>/dev/null | head -n 1 | tr -cd '[:alnum:]._+-')
  if bin/meowai-deploy-upgrade-agent agent --help 2>/dev/null | grep -q -- '--proof'; then agent_proof_capable=1; fi
fi
printf 'META|agent_version|%s\n' "$agent_version"
printf 'META|agent_proof_capable|%s\n' "$agent_proof_capable"
agent_schema=$(awk -F= '$1 == "MEOWAI_UPDATER_SCHEMA" {{print $2; exit}}' downstream-credentials.env 2>/dev/null || true)
case "$agent_schema" in ''|*[!0-9]*) agent_schema='' ;; esac
printf 'META|agent_schema|%s\n' "$agent_schema"
exit 0"#,
    )
}

fn parse_observation(raw: &str, target_fingerprint: String) -> Result<TargetObservation> {
    let mut observation = TargetObservation {
        schema_version: 1,
        observed_at: unix_timestamp(),
        target_fingerprint,
        ..TargetObservation::default()
    };
    for line in raw.lines() {
        let fields = line.split('|').collect::<Vec<_>>();
        match fields.as_slice() {
            ["META", key, value] => set_meta(&mut observation, key, value)?,
            [
                "FILE",
                path,
                exists,
                regular,
                symlink,
                mode,
                uid,
                gid,
                size,
                sha256,
            ] => {
                observation.files.insert(
                    (*path).to_owned(),
                    TargetFileObservation {
                        exists: parse_bool(exists)?,
                        regular: parse_bool(regular)?,
                        symlink: parse_bool(symlink)?,
                        mode: (*mode).to_owned(),
                        uid: parse_number(uid)?,
                        gid: parse_number(gid)?,
                        size: parse_number(size)?,
                        sha256: (*sha256).to_owned(),
                        keys: BTreeMap::new(),
                    },
                );
            }
            ["ENV", path, key, count, non_empty, value_sha256] => {
                observation
                    .files
                    .entry((*path).to_owned())
                    .or_default()
                    .keys
                    .insert(
                        (*key).to_owned(),
                        TargetEnvKeyObservation {
                            count: parse_number(count)?,
                            non_empty: parse_bool(non_empty)?,
                            value_sha256: (*value_sha256).to_owned(),
                        },
                    );
            }
            ["SERVICE", name, container_id, image_id, state, health]
            | ["SERVICE", name, container_id, image_id, state, health, _, _]
                if !name.is_empty() =>
            {
                observation.services.insert(
                    (*name).to_owned(),
                    TargetServiceObservation {
                        container_id: (*container_id).to_owned(),
                        image_id: (*image_id).to_owned(),
                        state: (*state).to_owned(),
                        health: (*health).to_owned(),
                        started_at: if fields.len() == 8 {
                            fields[6].to_owned()
                        } else {
                            String::new()
                        },
                        restart_count: if fields.len() == 8 {
                            parse_number(fields[7])?
                        } else {
                            0
                        },
                        mounts: Vec::new(),
                    },
                );
            }
            [
                "MOUNT",
                service,
                destination,
                mount_type,
                name,
                source,
                read_write,
            ] if !service.is_empty() && !destination.is_empty() => {
                observation
                    .services
                    .entry((*service).to_owned())
                    .or_default()
                    .mounts
                    .push(TargetMountObservation {
                        destination: (*destination).to_owned(),
                        mount_type: (*mount_type).to_owned(),
                        name: (*name).to_owned(),
                        source: (*source).to_owned(),
                        read_write: parse_bool(read_write)?,
                    });
            }
            [
                "PATH",
                path,
                exists,
                symlink,
                device,
                inode,
                canonical_sha256,
            ] => {
                observation.data_paths.insert(
                    (*path).to_owned(),
                    TargetPathIdentity {
                        exists: parse_bool(exists)?,
                        symlink: parse_bool(symlink)?,
                        device: parse_number(device)?,
                        inode: parse_number(inode)?,
                        canonical_sha256: (*canonical_sha256).to_owned(),
                    },
                );
            }
            ["VOLUME", name] => observation.project_volumes.push((*name).to_owned()),
            ["VOLUME_ID", name, label, mount_hash] => {
                observation
                    .volume_identities
                    .insert((*name).to_owned(), format!("{label}|{mount_hash}"));
            }
            ["NETWORK", name] => observation.project_networks.push((*name).to_owned()),
            ["ENDPOINT", key, value] if !key.is_empty() && !value.is_empty() => {
                observation
                    .external_dependency_fingerprints
                    .insert((*key).to_owned(), (*value).to_owned());
            }
            _ if line.trim().is_empty() => {}
            _ => {
                return Err(AppError::State(
                    "TARGET_OBSERVATION_INVALID_OUTPUT".to_owned(),
                ));
            }
        }
    }
    let expected_services = BTreeSet::from([
        "new-api",
        "postgres",
        "redis",
        "uptime-kuma",
        "checker-proxy",
        "meowai-deploy-updater",
    ]);
    for service in observation.services.keys() {
        if !expected_services.contains(service.as_str()) {
            observation
                .unknown_resources
                .push(format!("service:{service}"));
        }
    }
    let managed_volume_names = observation
        .services
        .values()
        .flat_map(|service| service.mounts.iter())
        .filter(|mount| mount.mount_type == "volume" && !mount.name.is_empty())
        .map(|mount| mount.name.as_str())
        .collect::<BTreeSet<_>>();
    for volume in &observation.project_volumes {
        if !managed_volume_names.contains(volume.as_str()) {
            observation
                .unknown_resources
                .push(format!("volume:{volume}"));
        }
    }
    for (service, details) in &observation.services {
        for mount in &details.mounts {
            if !managed_mount_destination(service, &mount.destination) {
                observation
                    .unknown_resources
                    .push(format!("mount:{service}:{}", mount.destination));
            }
        }
    }
    observation.project_volumes.sort();
    observation.project_networks.sort();
    observation.unknown_resources.sort();
    // Docker does not guarantee a stable mount order in `docker inspect`.
    // Sort so mount-identity comparisons and fingerprints are deterministic.
    for service in observation.services.values_mut() {
        service
            .mounts
            .sort_by(|left, right| left.destination.cmp(&right.destination));
    }
    Ok(observation)
}

fn managed_mount_destination(service: &str, destination: &str) -> bool {
    match service {
        "new-api" => matches!(destination, "/data" | "/run/meowai"),
        "postgres" => destination == "/var/lib/postgresql/data",
        "redis" => destination == "/data",
        "uptime-kuma" => destination == "/app/data",
        "checker-proxy" => false,
        "meowai-deploy-updater" => false,
        _ => false,
    }
}

fn set_meta(observation: &mut TargetObservation, key: &str, value: &str) -> Result<()> {
    match key {
        "directory_exists" => observation.directory_exists = parse_bool(value)?,
        "deployment_id" => observation.deployment_id = value.to_owned(),
        "installation_generation" => observation.installation_generation = parse_number(value)?,
        "directory_symlink" => observation.directory_symlink = parse_bool(value)?,
        "disk_available_bytes" => observation.disk_available_bytes = parse_number(value)?,
        "docker_available" => observation.docker_available = parse_bool(value)?,
        "compose_v2_available" => observation.compose_v2_available = parse_bool(value)?,
        "docker_version" => observation.docker_version = value.to_owned(),
        "compose_version" => observation.compose_version = value.to_owned(),
        "systemd_available" => observation.systemd_available = parse_bool(value)?,
        "compose_valid" => observation.compose_valid = parse_bool(value)?,
        "compose_fingerprint" => observation.compose_fingerprint = value.to_owned(),
        "compose_project" => observation.compose_project_name = value.to_owned(),
        "postgres_select_1" => observation.postgres_select_1 = parse_bool(value)?,
        "redis_ping" => observation.redis_ping = parse_bool(value)?,
        "newapi_status" => observation.newapi_status = parse_bool(value)?,
        "newapi_status_success" => observation.newapi_status_success = parse_bool(value)?,
        "local_health_status" => observation.local_health_status = parse_bool(value)?,
        "kuma_status" => observation.kuma_status = parse_bool(value)?,
        "upgrade_agent_active" => observation.upgrade_agent_active = parse_bool(value)?,
        "upgrade_timer_active" => observation.upgrade_timer_active = parse_bool(value)?,
        "agent_version" => observation.agent_version = value.to_owned(),
        "agent_schema" => observation.agent_schema = value.to_owned(),
        "agent_proof_capable" => observation.agent_proof_capable = parse_bool(value)?,
        _ => {
            return Err(AppError::State(
                "TARGET_OBSERVATION_UNKNOWN_FIELD".to_owned(),
            ));
        }
    }
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(AppError::State(
            "TARGET_OBSERVATION_INVALID_BOOL".to_owned(),
        )),
    }
}

fn parse_number<T: std::str::FromStr>(value: &str) -> Result<T> {
    value
        .parse()
        .map_err(|_| AppError::State("TARGET_OBSERVATION_INVALID_NUMBER".to_owned()))
}

fn validate_identifier(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AppError::State(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<()> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(AppError::State(
            "invalid target observation fingerprint".to_owned(),
        ));
    }
    Ok(())
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("secret")
        || key.contains("credential")
        || key.contains("token")
        || key.contains("password")
        || key.contains("private_key")
}

fn redact_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) => serde_json::Value::Object(
            object
                .iter()
                .filter(|(key, _)| !sensitive_key(key))
                .map(|(key, value)| (key.clone(), redact_value(value)))
                .collect(),
        ),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(redact_value).collect())
        }
        _ => value.clone(),
    }
}

fn quote(value: &str) -> String {
    escape(value.into()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Target;

    #[test]
    fn observation_parser_never_contains_env_values() {
        let raw = "META|directory_exists|1\nMETA|directory_symlink|0\nMETA|disk_available_bytes|42\nMETA|docker_available|1\nMETA|compose_v2_available|1\nMETA|systemd_available|0\nMETA|compose_valid|1\nMETA|compose_fingerprint|abc\nMETA|compose_project|newapi\nENDPOINT|DATABASE_URL|endpoint-hash\nFILE|downstream-credentials.env|1|1|0|600|1|1|100|filehash\nENV|downstream-credentials.env|MEOWAI_REPORT_CREDENTIAL|1|1|valuehash\nSERVICE|new-api|container|image|running|healthy\nPATH|data/newapi|1|0|2|3|pathhash\nVOLUME_ID|newapi_data|newapi|mount-hash\nMETA|postgres_select_1|1\nMETA|redis_ping|1\nMETA|newapi_status|1\nMETA|newapi_status_success|1\nMETA|local_health_status|1\nMETA|kuma_status|1\nMETA|upgrade_agent_active|0\nMETA|upgrade_timer_active|1\nMETA|agent_version|meowai-deploy1.2.5\nMETA|agent_schema|2\n";
        let observation = parse_observation(raw, "target".to_owned()).unwrap();
        let encoded = serde_json::to_string(&observation).unwrap();
        assert!(encoded.contains("valuehash"));
        assert!(!encoded.contains("secret-value"));
        assert!(observation.unknown_resources.is_empty());
        assert_eq!(observation.compose_project_name, "newapi");
        assert!(observation.newapi_status_success);
        assert!(observation.local_health_status);
        assert_eq!(observation.agent_version, "meowai-deploy1.2.5");
        assert_eq!(observation.agent_schema, "2");
        assert_eq!(
            observation.volume_identities["newapi_data"],
            "newapi|mount-hash"
        );
        assert_eq!(
            observation.external_dependency_fingerprints["DATABASE_URL"],
            "endpoint-hash"
        );
        assert_eq!(observation.fingerprint(), observation.fingerprint());
    }

    #[test]
    fn fingerprint_ignores_live_operational_metrics() {
        let raw = "META|directory_exists|1\nMETA|directory_symlink|0\nMETA|disk_available_bytes|42\nMETA|docker_available|1\nMETA|compose_v2_available|1\nMETA|systemd_available|0\nMETA|compose_valid|1\nMETA|compose_fingerprint|abc\nMETA|compose_project|newapi\nFILE|data/state.json|1|1|0|600|1|1|100|statehash\nSERVICE|new-api|container|image|running|healthy|2026-01-01T00:00:00Z|0\nMETA|postgres_select_1|1\nMETA|redis_ping|1\nMETA|newapi_status|1\nMETA|newapi_status_success|1\nMETA|local_health_status|1\nMETA|kuma_status|1\nMETA|upgrade_agent_active|1\nMETA|upgrade_timer_active|1\n";
        let observation = parse_observation(raw, "target".to_owned()).unwrap();
        let mut later = observation.clone();
        later.observed_at += 300;
        later.disk_available_bytes = 7;
        later
            .services
            .get_mut("new-api")
            .expect("new-api service observed")
            .started_at = "2026-01-01T00:05:00Z".to_owned();
        later
            .services
            .get_mut("new-api")
            .expect("new-api service observed")
            .restart_count = 3;
        let state = later
            .files
            .get_mut("data/state.json")
            .expect("state marker observed");
        state.sha256 = "differenthash".to_owned();
        state.size = 250;
        assert_eq!(observation.fingerprint(), later.fingerprint());
        // Managed drift must still change the fingerprint.
        let mut drifted = observation.clone();
        drifted.compose_fingerprint = "drifted".to_owned();
        assert_ne!(observation.fingerprint(), drifted.fingerprint());
        let mut container_replaced = observation.clone();
        container_replaced
            .services
            .get_mut("new-api")
            .expect("new-api service observed")
            .container_id = "replacement".to_owned();
        assert_ne!(observation.fingerprint(), container_replaced.fingerprint());
        let mut state_removed = observation;
        state_removed
            .files
            .get_mut("data/state.json")
            .expect("state marker observed")
            .exists = false;
        assert_ne!(state_removed.fingerprint(), later.fingerprint());
    }

    #[test]
    fn unknown_compose_resources_are_manual_boundaries() {
        let raw = "META|directory_exists|1\nMETA|directory_symlink|0\nMETA|disk_available_bytes|42\nMETA|docker_available|1\nMETA|compose_v2_available|1\nMETA|systemd_available|0\nMETA|compose_valid|1\nMETA|compose_fingerprint|abc\nSERVICE|custom|container|image|running|healthy\nVOLUME|custom-data\nMETA|postgres_select_1|0\nMETA|redis_ping|0\nMETA|newapi_status|0\nMETA|kuma_status|0\nMETA|upgrade_agent_active|0\nMETA|upgrade_timer_active|0\n";
        let observation = parse_observation(raw, "target".to_owned()).unwrap();
        assert_eq!(
            observation.unknown_resources,
            vec!["service:custom", "volume:custom-data"]
        );
    }

    #[test]
    fn managed_compose_volumes_and_mounts_are_not_unknown_resources() {
        let raw = "META|directory_exists|1\nMETA|directory_symlink|0\nMETA|disk_available_bytes|42\nMETA|docker_available|1\nMETA|compose_v2_available|1\nMETA|systemd_available|1\nMETA|compose_valid|1\nMETA|compose_fingerprint|abc\nSERVICE|new-api|container|image|running|healthy\nMOUNT|new-api|/data|volume|newapi_data|/var/lib/docker/volumes/newapi_data|1\nMOUNT|new-api|/run/meowai|bind||/srv/run|1\nVOLUME|newapi_data\nMETA|postgres_select_1|1\nMETA|redis_ping|1\nMETA|newapi_status|1\nMETA|newapi_status_success|1\nMETA|local_health_status|1\nMETA|kuma_status|1\nMETA|upgrade_agent_active|1\nMETA|upgrade_timer_active|1\n";
        let observation = parse_observation(raw, "target".to_owned()).unwrap();
        assert!(observation.unknown_resources.is_empty());
    }

    #[test]
    fn additional_managed_mount_is_a_manual_boundary() {
        let raw = "META|directory_exists|1\nMETA|directory_symlink|0\nMETA|disk_available_bytes|42\nMETA|docker_available|1\nMETA|compose_v2_available|1\nMETA|systemd_available|1\nMETA|compose_valid|1\nMETA|compose_fingerprint|abc\nSERVICE|new-api|container|image|running|healthy\nMOUNT|new-api|/unmanaged|bind||/srv/unmanaged|1\nMETA|postgres_select_1|1\nMETA|redis_ping|1\nMETA|newapi_status|1\nMETA|newapi_status_success|1\nMETA|local_health_status|1\nMETA|kuma_status|1\nMETA|upgrade_agent_active|1\nMETA|upgrade_timer_active|1\n";
        let observation = parse_observation(raw, "target".to_owned()).unwrap();
        assert_eq!(
            observation.unknown_resources,
            vec!["mount:new-api:/unmanaged"]
        );
    }

    #[test]
    fn updater_readiness_accepts_oneshot_service_installation() {
        let script = observation_script("newapi", 3000, 3001);
        assert!(script.contains("is-enabled --quiet meowai-deploy-updater.service"));
        assert!(script.contains("is-enabled --quiet meowai-deploy-updater.timer"));
        assert!(script.contains("is-active --quiet meowai-deploy-updater.timer"));
        assert!(!script.contains("META|upgrade_agent_active|%s\\n\"$(bool systemctl is-active"));
    }

    #[test]
    fn volume_identity_changes_are_rejected() {
        let before = BTreeMap::from([("newapi_data".to_owned(), "project|hash-a".to_owned())]);
        let after = BTreeMap::from([("newapi_data".to_owned(), "project|hash-b".to_owned())]);
        let error = verify_volume_identity(&before, &after).unwrap_err();
        assert!(error.to_string().contains("volume newapi_data"));
    }

    #[test]
    fn b1_backup_and_atomic_restore_preserve_original() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temporary.path().join("data/newapi")).unwrap();
        std::fs::write(
            temporary.path().join("secrets.env"),
            b"SESSION_SECRET=old\n",
        )
        .unwrap();
        let executor = TargetExecutor::new(Target::Local, temporary.path().to_path_buf());
        let mut observation = TargetObservation::default();
        observation.files.insert(
            "secrets.env".to_owned(),
            TargetFileObservation {
                exists: true,
                regular: true,
                mode: "600".to_owned(),
                size: 19,
                sha256: sha256_hex(b"SESSION_SECRET=old\n"),
                ..TargetFileObservation::default()
            },
        );
        let manifest = create_b1_backup(&executor, "repair_test", &observation).unwrap();
        std::fs::write(
            temporary
                .path()
                .join(".repair/repair_test/backup/secrets.env"),
            b"tampered\n",
        )
        .unwrap();
        assert!(restore_b1_backup(&executor, "repair_test", &manifest).is_err());
        std::fs::write(
            temporary
                .path()
                .join(".repair/repair_test/backup/secrets.env"),
            b"SESSION_SECRET=old\n",
        )
        .unwrap();
        atomic_replace(
            &executor,
            "repair_test",
            "secrets.env",
            b"SESSION_SECRET=new\n",
            0o600,
        )
        .unwrap();
        restore_b1_backup(&executor, "repair_test", &manifest).unwrap();
        assert_eq!(
            std::fs::read(temporary.path().join("secrets.env")).unwrap(),
            b"SESSION_SECRET=old\n"
        );
    }

    #[test]
    fn b2_manifest_round_trips_data_backup_inventory_without_plaintext() {
        let manifest = BackupManifest {
            schema_version: 1,
            operation_id: "repair_b2".to_owned(),
            created_at: 1,
            observation_fingerprint:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            files: Vec::new(),
            systemd_files: Vec::new(),
            data_backups: vec![
                ".repair/repair_b2/backup/data/postgres.sql".to_owned(),
                ".repair/repair_b2/backup/data/redis-dump.rdb".to_owned(),
            ],
            resource_identity: BTreeMap::new(),
            volume_identities: BTreeMap::new(),
        };
        let encoded = serde_json::to_string(&manifest).unwrap();
        let decoded: BackupManifest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.data_backups, manifest.data_backups);
        assert!(!encoded.contains("password"));
    }

    #[test]
    fn target_lock_rejects_concurrent_writer_and_releases() {
        let temporary = tempfile::tempdir().unwrap();
        let executor = TargetExecutor::new(Target::Local, temporary.path().to_path_buf());
        let first = TargetOperationLock::acquire(&executor, "repair", "repair_one").unwrap();
        let error = TargetOperationLock::acquire(&executor, "repair", "repair_two")
            .err()
            .expect("second lock should fail");
        assert!(error.to_string().contains("TARGET_OPERATION_CONFLICT"));
        drop(first);
        TargetOperationLock::acquire(&executor, "repair", "repair_two").unwrap();
    }

    #[test]
    fn target_fingerprint_accepts_sha256_format() {
        let fingerprint = format!("sha256:{}", "a".repeat(64));
        validate_fingerprint(&fingerprint).unwrap();
        assert!(validate_fingerprint("a".repeat(64).as_str()).is_err());
    }

    #[test]
    fn journal_redacts_nested_sensitive_values() {
        let value = serde_json::json!({
            "safe": {"value": 1},
            "nested": {"credentials": "secret", "ok": "yes"},
            "items": [{"token": "secret"}, {"name": "kept"}]
        });
        let redacted = redact_value(&value);
        assert_eq!(redacted["nested"].get("credentials"), None);
        assert_eq!(redacted["nested"]["ok"], "yes");
        assert_eq!(redacted["items"][0].get("token"), None);
    }

    #[test]
    fn mount_identity_changes_are_rejected() {
        let before = BTreeMap::from([(
            "postgres".to_owned(),
            TargetServiceObservation {
                mounts: vec![TargetMountObservation {
                    destination: "/var/lib/postgresql/data".to_owned(),
                    mount_type: "volume".to_owned(),
                    name: "newapi-postgres".to_owned(),
                    source: "newapi-postgres".to_owned(),
                    read_write: true,
                }],
                ..TargetServiceObservation::default()
            },
        )]);
        let mut after = before.clone();
        after.get_mut("postgres").unwrap().mounts[0].name = "other".to_owned();
        assert!(verify_service_mount_identity(&before, &after).is_err());
    }
}
