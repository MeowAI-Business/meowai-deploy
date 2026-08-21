use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
};

use secrecy::SecretString;
use serde_json::json;
use tempfile::{TempDir, tempdir};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path_regex},
};

use super::{BundleComposeChange, BundleEnvChange, BundleFile, BundleManifest, apply};
use crate::{
    config::{DeploymentConfig, Target},
    source::DeploymentRegistration,
    state::DeploymentState,
    upgrade::{
        ManifestArtifact, ManifestHealthPolicy, ManifestMigrationPlan, ManifestRollback,
        ReleaseManifest, UpgradeDecision, UpgradePlan,
    },
};

const OLD_DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW_DIGEST: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

struct Fixture {
    _temporary: TempDir,
    root: PathBuf,
    _socket: UnixListener,
    _server: MockServer,
    _home: PathBuf,
}

impl Fixture {
    async fn new() -> Self {
        let temporary = tempdir().expect("fixture tempdir");
        let root = temporary.path().join("deployment");
        let fake_bin = temporary.path().join("bin");
        let home = temporary.path().join("agent-home");
        for dir in [
            "data/postgres",
            "data/redis",
            "data/uptime-kuma",
            "run/migrations",
        ] {
            fs::create_dir_all(root.join(dir)).expect("fixture directory");
        }
        fs::create_dir_all(&fake_bin).expect("fake bin");
        fs::create_dir_all(&home).expect("agent home");
        fs::write(root.join("data/postgres/business"), "postgres-original\n").unwrap();
        fs::write(root.join("data/redis/dump.rdb"), "redis-original\n").unwrap();
        fs::write(root.join("data/uptime-kuma/kuma.db"), "kuma-original\n").unwrap();
        fs::write(
            root.join("secrets.env"),
            "POSTGRES_PASSWORD=pg\nREDIS_PASSWORD=redis\nSESSION_SECRET=session\n",
        )
        .unwrap();
        fs::write(root.join("downstream-credentials.env"), credentials()).unwrap();
        fs::write(
            root.join("updater-credentials.env"),
            "MEOWAI_UPDATER_LOCAL_CREDENTIAL=local-token\n",
        )
        .unwrap();
        fs::write(root.join("docker-compose.yml"), current_compose()).unwrap();
        fs::write(root.join("meowai-deploy-updater.service"), "old-service\n").unwrap();
        fs::write(root.join("meowai-deploy-updater.timer"), "old-timer\n").unwrap();
        let socket = UnixListener::bind(root.join("run/updater.sock")).expect("updater socket");
        write_executable(&fake_bin.join("docker"), &docker_script());
        write_executable(&fake_bin.join("systemctl"), &systemctl_script());
        write_executable(&fake_bin.join("curl"), &curl_script());
        let path = format!(
            "{}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            fake_bin.display()
        );
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/api/.*"))
            .respond_with(ControlPlaneResponder)
            .mount(&server)
            .await;
        unsafe {
            std::env::set_var("PATH", path);
            std::env::set_var("FAKE_ROOT", &root);
            std::env::set_var("FAKE_OLD_DIGEST", OLD_DIGEST);
            std::env::set_var("FAKE_NEW_DIGEST", NEW_DIGEST);
            std::env::set_var("MEOWAI_DEPLOY_HOME", &home);
            for key in [
                "FAKE_SWITCH_FAIL",
                "FAKE_HEALTH_FAIL",
                "FAKE_TIMER_FAIL",
                "FAKE_EMPTY_PG_DUMP",
            ] {
                std::env::remove_var(key);
            }
        }
        Self {
            _temporary: temporary,
            root,
            _socket: socket,
            _server: server,
            _home: home,
        }
    }

    fn config(&self) -> DeploymentConfig {
        DeploymentConfig {
            directory: self.root.clone(),
            target: Target::Local,
            container_name: "e2e-newapi".to_owned(),
            image: "ghcr.io/example/newapi".to_owned(),
            newapi_port: 3100,
            kuma_port: 3101,
            ..DeploymentConfig::default()
        }
    }

    fn state(&self) -> DeploymentState {
        serde_json::from_value(json!({"schema_version":1,"deployment_id":"local-deployment","target_fingerprint":"fixture","container_name":"e2e-newapi","directory":self.root,"newapi_port":3100,"kuma_port":3101,"image":"ghcr.io/example/newapi","image_ref":OLD_DIGEST,"deployment_schema":"1","updater_schema":"1","cli_schema":"1","data_schema":"1"})).unwrap()
    }

    fn registration(&self) -> DeploymentRegistration {
        DeploymentRegistration {
            deployment_id: "dep_e2e".to_owned(),
            installation_generation: 1,
            control_plane_url: self._server.uri(),
            report_credential: SecretString::from("report-secret"),
            pull_credential: SecretString::from("pull-secret"),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: false,
            release_schema_version: "2".to_owned(),
            release_manifest_public_key: "public-key".to_owned(),
            release_artifact_allowed_hosts: vec!["assets.example".to_owned()],
        }
    }
}

struct ControlPlaneResponder;

impl Respond for ControlPlaneResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        if request.url.path().ends_with("/upgrades/plan") {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            return ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "data": {
                    "accepted": true,
                    "operation_id": body["operation_id"],
                    "release_id": body["release_id"],
                    "state": "PLANNED",
                    "plan_fingerprint": body["plan_fingerprint"],
                    "execution_mode": body["execution_mode"].as_str().unwrap_or("manual"),
                    "authorization_id": body["authorization_id"].as_str().unwrap_or("")
                }
            }));
        }
        ResponseTemplate::new(200).set_body_json(json!({"success": true, "data": {}}))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_apply_covers_success_failures_data_rollback_and_recovery() {
    let fixture = Fixture::new().await;
    let config = fixture.config();
    let registration = fixture.registration();
    let plan = plan();
    let (manifest, artifact, bytes) = bundle(false, false);
    let result = apply(
        &config,
        &fixture.state(),
        &registration,
        &manifest,
        &artifact,
        &bytes,
        &plan,
        true,
        false,
    )
    .await
    .expect("successful apply");
    assert_eq!(result.image_digest, NEW_DIGEST);
    assert!(
        fs::read_to_string(fixture.root.join("secrets.env"))
            .unwrap()
            .contains("FEATURE=enabled")
    );
    assert!(
        fs::read_to_string(fixture.root.join("docker-compose.yml"))
            .unwrap()
            .contains("worker")
    );
    assert!(
        fixture
            .root
            .join("bin/meowai-deploy-upgrade-agent")
            .exists()
    );
    assert!(fixture.root.join("run/upgrade-status.json").exists());
    assert!(fixture.root.join("pg-restore-list-checked").exists());
    let events = fs::read_to_string(fixture.root.join("events.log")).unwrap();
    assert!(events.find("curl --fail").unwrap() < events.rfind("systemctl enable --now").unwrap());

    unsafe {
        std::env::set_var("FAKE_SWITCH_FAIL", "1");
    }
    let (manifest, artifact, bytes) = bundle(false, false);
    assert!(
        apply(
            &config,
            &fixture.state(),
            &registration,
            &manifest,
            &artifact,
            &bytes,
            &plan,
            false,
            false
        )
        .await
        .is_err()
    );
    unsafe {
        std::env::remove_var("FAKE_SWITCH_FAIL");
    }
    assert_eq!(
        fs::read_to_string(fixture.root.join("data/postgres/business")).unwrap(),
        "postgres-original\n"
    );

    // A successful non-noop migration must change both data stores before a
    // later health failure exercises the restore path.
    fs::write(
        fixture.root.join("data/postgres/business"),
        "postgres-before-real-migration\n",
    )
    .unwrap();
    fs::write(
        fixture.root.join("data/redis/dump.rdb"),
        "redis-before-real-migration\n",
    )
    .unwrap();
    unsafe {
        std::env::set_var("FAKE_HEALTH_FAIL", "1");
    }
    let (manifest, artifact, bytes) = bundle(true, false);
    assert!(
        apply(
            &config,
            &fixture.state(),
            &registration,
            &manifest,
            &artifact,
            &bytes,
            &plan,
            false,
            false,
        )
        .await
        .is_err()
    );
    unsafe {
        std::env::remove_var("FAKE_HEALTH_FAIL");
    }
    assert_eq!(
        fs::read_to_string(fixture.root.join("data/postgres/business")).unwrap(),
        "postgres-before-real-migration\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("data/redis/dump.rdb")).unwrap(),
        "redis-before-real-migration\n"
    );

    unsafe {
        std::env::set_var("FAKE_HEALTH_FAIL", "1");
    }
    let (manifest, artifact, bytes) = bundle(false, false);
    assert!(
        apply(
            &config,
            &fixture.state(),
            &registration,
            &manifest,
            &artifact,
            &bytes,
            &plan,
            false,
            false
        )
        .await
        .is_err()
    );
    unsafe {
        std::env::remove_var("FAKE_HEALTH_FAIL");
    }

    let (manifest, artifact, bytes) = bundle(true, true);
    fs::write(
        fixture.root.join("data/postgres/business"),
        "postgres-before-migration\n",
    )
    .unwrap();
    fs::write(
        fixture.root.join("data/redis/dump.rdb"),
        "redis-before-migration\n",
    )
    .unwrap();
    assert!(
        apply(
            &config,
            &fixture.state(),
            &registration,
            &manifest,
            &artifact,
            &bytes,
            &plan,
            false,
            false
        )
        .await
        .is_err()
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("data/postgres/business")).unwrap(),
        "postgres-before-migration\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("data/redis/dump.rdb")).unwrap(),
        "redis-before-migration\n"
    );

    fs::write(fixture.root.join("run/upgrade-status.json"), json!({"operation_id":result.operation_id,"release_id":"rel_e2e","state":"HEALTH_CHECKING","phase":"HEALTH_CHECKING","backup_id":result.backup_id,"data_rollback_required":false,"updated_at":1}).to_string()).unwrap();
    fs::write(fixture.root.join("docker-compose.yml"), "corrupt\n").unwrap();
    let (manifest, artifact, bytes) = bundle(false, false);
    let recovered = apply(
        &config,
        &fixture.state(),
        &registration,
        &manifest,
        &artifact,
        &bytes,
        &plan,
        false,
        false,
    )
    .await
    .expect("recover incomplete operation and continue upgrade");
    assert_eq!(recovered.image_digest, NEW_DIGEST);
    assert_ne!(
        fs::read_to_string(fixture.root.join("docker-compose.yml")).unwrap(),
        "corrupt\n"
    );

    // A crash before BACKUP_VERIFIED has no target changes to roll back. The
    // next run must discard the incomplete backup instead of requiring a
    // SHA256SUMS file that could not have been created yet.
    let interrupted = Fixture::new().await;
    let interrupted_config = interrupted.config();
    let interrupted_registration = interrupted.registration();
    let interrupted_operation = "op_interrupted_backup";
    fs::create_dir_all(
        interrupted
            .root
            .join(format!(".upgrade/{interrupted_operation}")),
    )
    .unwrap();
    fs::create_dir_all(
        interrupted
            .root
            .join(format!("backups/{interrupted_operation}")),
    )
    .unwrap();
    fs::write(
        interrupted
            .root
            .join(format!("backups/{interrupted_operation}/postgres.dump")),
        "partial",
    )
    .unwrap();
    fs::write(
        interrupted.root.join("run/upgrade-status.json"),
        json!({
            "operation_id": interrupted_operation,
            "release_id": "rel_e2e",
            "state": "BACKUP_STARTED",
            "phase": "BACKUP_STARTED",
            "backup_id": interrupted_operation,
            "data_rollback_required": false,
            "updated_at": 1
        })
        .to_string(),
    )
    .unwrap();
    let compose_before_recovery = fs::read(interrupted.root.join("docker-compose.yml")).unwrap();
    let (manifest, artifact, bytes) = bundle(false, false);
    assert!(
        apply(
            &interrupted_config,
            &interrupted.state(),
            &interrupted_registration,
            &manifest,
            &artifact,
            &bytes,
            &plan,
            false,
            false,
        )
        .await
        .is_err()
    );
    assert_eq!(
        fs::read(interrupted.root.join("docker-compose.yml")).unwrap(),
        compose_before_recovery
    );
    assert!(
        !interrupted
            .root
            .join(format!(".upgrade/{interrupted_operation}"))
            .exists()
    );
    assert!(
        !interrupted
            .root
            .join(format!("backups/{interrupted_operation}"))
            .exists()
    );
    let recovered_journal: serde_json::Value = serde_json::from_slice(
        &fs::read(interrupted.root.join("run/upgrade-status.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(recovered_journal["state"], "BACKUP_FAILED");

    let (manifest, artifact, bytes) = bundle(false, false);
    apply(
        &interrupted_config,
        &interrupted.state(),
        &interrupted_registration,
        &manifest,
        &artifact,
        &bytes,
        &plan,
        false,
        false,
    )
    .await
    .expect("a new operation can continue after pre-switch recovery");

    // A successful pg_dump process is insufficient if it produced no usable
    // archive. The backup phase must stop before any target switch.
    let empty_backup = Fixture::new().await;
    let empty_backup_config = empty_backup.config();
    let empty_backup_registration = empty_backup.registration();
    let empty_backup_compose = fs::read(empty_backup.root.join("docker-compose.yml")).unwrap();
    unsafe {
        std::env::set_var("FAKE_EMPTY_PG_DUMP", "1");
    }
    let (manifest, artifact, bytes) = bundle(false, false);
    assert!(
        apply(
            &empty_backup_config,
            &empty_backup.state(),
            &empty_backup_registration,
            &manifest,
            &artifact,
            &bytes,
            &plan,
            false,
            false,
        )
        .await
        .is_err()
    );
    unsafe {
        std::env::remove_var("FAKE_EMPTY_PG_DUMP");
    }
    assert_eq!(
        fs::read(empty_backup.root.join("docker-compose.yml")).unwrap(),
        empty_backup_compose
    );
    let failed_backup_journal: serde_json::Value = serde_json::from_slice(
        &fs::read(empty_backup.root.join("run/upgrade-status.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(failed_backup_journal["state"], "BACKUP_FAILED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an explicitly provisioned Linux SSH target and local control plane"]
async fn real_linux_ssh_upgrade_against_local_control_plane() {
    let required = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is required for real Linux E2E"))
    };
    let root = PathBuf::from(required("MEOWAI_REAL_E2E_ROOT"));
    let ssh_destination = required("MEOWAI_REAL_E2E_SSH_DESTINATION");
    let current_compose = std::process::Command::new("ssh")
        .args([
            &ssh_destination,
            &format!("sudo -n cat {}/docker-compose.yml", root.display()),
        ])
        .output()
        .expect("read live compose over SSH");
    assert!(
        current_compose.status.success(),
        "read live compose over SSH: {}",
        String::from_utf8_lossy(&current_compose.stderr)
    );
    let mut staged: serde_json::Value =
        serde_json::from_slice(&current_compose.stdout).expect("live compose is JSON");
    staged["services"]["new-api"]["image"] = json!("${MEOWAI_IMAGE_REFERENCE}");
    staged["services"]["new-api"]["environment"]["MEOWAI_STRUCTURAL_RELEASE_ID"] =
        json!(required("MEOWAI_REAL_E2E_RELEASE_ID"));
    staged["services"]["upgrade-probe"] = json!({
        "image": "redis:7-alpine",
        "command": ["sh", "-c", "while true; do sleep 3600; done"],
        "restart": "unless-stopped"
    });
    let staged_compose = serde_json::to_vec_pretty(&staged).expect("encode staged compose");
    let agent_binary = fs::read(required("MEOWAI_REAL_E2E_AGENT_BINARY"))
        .expect("read production upgrade agent binary");
    let files = vec![
        ("docker-compose.yml", 0o644, staged_compose),
        ("meowai-deploy-upgrade-agent", 0o700, agent_binary),
        (
            "secrets.env.patch",
            0o600,
            b"MEOWAI_STRUCTURAL_TEST=enabled\n".to_vec(),
        ),
        ("downstream-credentials.env.patch", 0o600, Vec::new()),
    ];
    let bundle_manifest = BundleManifest {
        bundle_schema: 1,
        release_id: required("MEOWAI_REAL_E2E_RELEASE_ID"),
        deployment_schema: 2,
        files: files
            .iter()
            .map(|(path, mode, body)| BundleFile {
                path: (*path).to_owned(),
                sha256: sha256(body),
                mode: *mode,
            })
            .collect(),
        migration_steps: vec!["deployment-1-to-2".to_owned()],
        compose_changes: vec![
            change("service", "new-api", "modify"),
            change("service", "upgrade-probe", "add"),
        ],
        env_changes: vec![BundleEnvChange {
            file: "secrets.env.patch".to_owned(),
            key: "MEOWAI_STRUCTURAL_TEST".to_owned(),
            action: "add".to_owned(),
        }],
    };
    let mut archive_files = files;
    archive_files.push((
        "bundle-manifest.json",
        0o600,
        serde_json::to_vec(&bundle_manifest).expect("encode bundle manifest"),
    ));
    let archive = archive(archive_files);
    let image_digest = required("MEOWAI_REAL_E2E_IMAGE_DIGEST");
    let release_id = required("MEOWAI_REAL_E2E_RELEASE_ID");
    let artifact = ManifestArtifact {
        name: "local-real-linux-e2e.tar.zst".to_owned(),
        url: required("MEOWAI_REAL_E2E_ARTIFACT_URL"),
        sha256: sha256(&archive),
        size: archive.len() as u64,
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
    };
    let manifest = ReleaseManifest {
        manifest_schema: 1,
        release_id: release_id.clone(),
        channel: "stable".to_owned(),
        newapi_version: "local-real-e2e".to_owned(),
        image_repository: "ghcr.io/moorcorpa/new-api-outgap".to_owned(),
        image_digest: image_digest.clone(),
        deployment_schema: 2,
        minimum_deployment_schema: 2,
        minimum_updater_schema: 2,
        minimum_cli_schema: 2,
        minimum_data_schema: 1,
        upgrade_kind: "deployment_and_image".to_owned(),
        required_capabilities: vec![
            "linux".to_owned(),
            "compose_v2".to_owned(),
            "systemd".to_owned(),
        ],
        artifacts: vec![
            artifact.clone(),
            ManifestArtifact {
                name: "local-real-linux-e2e-arm64.tar.zst".to_owned(),
                arch: "arm64".to_owned(),
                ..artifact.clone()
            },
        ],
        migration_plan: ManifestMigrationPlan {
            from: 1,
            to: 2,
            steps: vec!["deployment-1-to-2".to_owned()],
        },
        health_policy: ManifestHealthPolicy {
            newapi_timeout_seconds: 60,
            dependency_timeout_seconds: 60,
            updater_heartbeat_max_age_seconds: 900,
        },
        rollback: ManifestRollback {
            supported: true,
            retained_backup_count: 3,
            data_rollback_required: false,
        },
        created_at: required("MEOWAI_REAL_E2E_CREATED_AT")
            .parse()
            .expect("valid manifest created_at"),
        expires_at: required("MEOWAI_REAL_E2E_EXPIRES_AT")
            .parse()
            .expect("valid manifest expires_at"),
        signature: String::new(),
    };
    if std::env::var("MEOWAI_REAL_E2E_PREPARE_ONLY").as_deref() == Ok("1") {
        fs::write(required("MEOWAI_REAL_E2E_ARTIFACT_OUTPUT"), &archive)
            .expect("write prepared artifact");
        fs::write(
            required("MEOWAI_REAL_E2E_MANIFEST_OUTPUT"),
            serde_json::to_vec(&manifest).expect("encode prepared manifest"),
        )
        .expect("write prepared manifest");
        return;
    }
    let config = DeploymentConfig {
        directory: root.clone(),
        target: Target::Ssh {
            destination: ssh_destination,
        },
        container_name: "newapi-downstream".to_owned(),
        image: manifest.image_repository.clone(),
        image_ref: image_digest.clone(),
        newapi_port: 3005,
        kuma_port: 3006,
        ..DeploymentConfig::default()
    };
    let state: DeploymentState = serde_json::from_value(json!({
        "schema_version": 1,
        "deployment_id": "local-real-linux-e2e",
        "target_fingerprint": "ssh:local-real-linux-e2e",
        "container_name": "newapi-downstream",
        "directory": root,
        "newapi_port": 3005,
        "kuma_port": 3006,
        "image": manifest.image_repository,
        "image_ref": image_digest,
        "deployment_schema": "1",
        "updater_schema": "2",
        "cli_schema": "2",
        "data_schema": "1",
        "newapi_version": "1.7.4-local-old",
        "target_os": "linux",
        "target_arch": "arm64",
        "systemd_available": true,
        "compose_v2_available": true
    }))
    .expect("build live state");
    let registration = DeploymentRegistration {
        deployment_id: required("MEOWAI_REAL_E2E_DEPLOYMENT_ID"),
        installation_generation: required("MEOWAI_REAL_E2E_INSTALLATION_GENERATION")
            .parse()
            .expect("valid installation generation"),
        control_plane_url: required("MEOWAI_REAL_E2E_CONTROL_PLANE_URL"),
        report_credential: SecretString::from(required("MEOWAI_REAL_E2E_REPORT_CREDENTIAL")),
        pull_credential: SecretString::from(required("MEOWAI_REAL_E2E_PULL_CREDENTIAL")),
        heartbeat_interval_seconds: 60,
        snapshot_interval_seconds: 300,
        silent_updates_enabled: false,
        release_schema_version: "2".to_owned(),
        release_manifest_public_key: required("MEOWAI_REAL_E2E_MANIFEST_PUBLIC_KEY"),
        release_artifact_allowed_hosts: vec!["assets.example".to_owned()],
    };
    let plan = UpgradePlan {
        fingerprint: required("MEOWAI_REAL_E2E_PLAN_FINGERPRINT"),
        decision: match std::env::var("MEOWAI_REAL_E2E_DECISION").as_deref() {
            Ok("upgrade_required") => UpgradeDecision::UpgradeRequired,
            _ => UpgradeDecision::Blocked,
        },
        reason_code: "BOOTSTRAP_REQUIRED".to_owned(),
        reason: "local real Linux E2E bootstrap".to_owned(),
        current: BTreeMap::new(),
        target: BTreeMap::new(),
        release_id,
        version: "local-real-e2e".to_owned(),
        upgrade_kind: "deployment_and_image".to_owned(),
        data_rollback_required: false,
        image_digest: manifest.image_digest.clone(),
        manifest_url: "https://control.example/manifest".to_owned(),
        manifest_sha256: "unused-by-direct-apply".to_owned(),
        manifest_verified: true,
        selected_artifact: Some(artifact.clone()),
        required_action: "apply_upgrade_agent".to_owned(),
        execution_authorized: true,
        upgrade_authorization_id: required("MEOWAI_REAL_E2E_AUTHORIZATION_ID"),
        upgrade_operation_id: required("MEOWAI_REAL_E2E_OPERATION_ID"),
        upgrade_authorization_expires_at: i64::MAX,
    };

    let result = apply(
        &config,
        &state,
        &registration,
        &manifest,
        &artifact,
        &archive,
        &plan,
        true,
        true,
    )
    .await
    .expect("real Linux deployment upgrade");
    assert_eq!(result.operation_id, plan.upgrade_operation_id);
    assert_eq!(result.image_digest, manifest.image_digest);
}

fn plan() -> UpgradePlan {
    UpgradePlan {
        fingerprint: "plan-e2e".to_owned(),
        decision: UpgradeDecision::UpgradeRequired,
        reason_code: "UPGRADE_REQUIRED".to_owned(),
        reason: "e2e".to_owned(),
        current: BTreeMap::new(),
        target: BTreeMap::new(),
        release_id: "rel_e2e".to_owned(),
        version: "2.0.0".to_owned(),
        upgrade_kind: "deployment_and_image".to_owned(),
        data_rollback_required: false,
        image_digest: NEW_DIGEST.to_owned(),
        manifest_url: String::new(),
        manifest_sha256: String::new(),
        manifest_verified: true,
        selected_artifact: None,
        required_action: "upgrade".to_owned(),
        execution_authorized: false,
        upgrade_authorization_id: String::new(),
        upgrade_operation_id: String::new(),
        upgrade_authorization_expires_at: 0,
    }
}

fn bundle(data_migration: bool, failing: bool) -> (ReleaseManifest, ManifestArtifact, Vec<u8>) {
    let mut files = vec![
        ("docker-compose.yml", 0o644, staged_compose()),
        (
            "meowai-deploy-upgrade-agent",
            0o700,
            b"new-agent\n".to_vec(),
        ),
        ("secrets.env.patch", 0o600, b"FEATURE=enabled\n".to_vec()),
    ];
    if data_migration {
        let script = if failing {
            b"#!/bin/sh\nprintf migrated > data/postgres/business\nprintf mutated > data/redis/dump.rdb\nexit 23\n".to_vec()
        } else {
            b"#!/bin/sh\nprintf migrated > data/postgres/business\nprintf migrated > data/redis/dump.rdb\nexit 0\n".to_vec()
        };
        files.push(("migrations/data-1-to-2.sh", 0o700, script));
    }
    let steps = if data_migration {
        vec!["deployment-1-to-2".to_owned(), "data-1-to-2".to_owned()]
    } else {
        vec!["deployment-1-to-2".to_owned()]
    };
    let bundle_manifest = BundleManifest {
        bundle_schema: 1,
        release_id: "rel_e2e".to_owned(),
        deployment_schema: 2,
        files: files
            .iter()
            .map(|(path, mode, body)| BundleFile {
                path: (*path).to_owned(),
                sha256: sha256(body),
                mode: *mode,
            })
            .collect(),
        migration_steps: steps.clone(),
        compose_changes: vec![
            change("service", "new-api", "modify"),
            change("service", "worker", "add"),
        ],
        env_changes: vec![BundleEnvChange {
            file: "secrets.env.patch".to_owned(),
            key: "FEATURE".to_owned(),
            action: "add".to_owned(),
        }],
    };
    let manifest_bytes = serde_json::to_vec(&bundle_manifest).unwrap();
    files.push(("bundle-manifest.json", 0o600, manifest_bytes));
    let archive = archive(files);
    let manifest = ReleaseManifest {
        manifest_schema: 1,
        release_id: "rel_e2e".to_owned(),
        channel: "stable".to_owned(),
        newapi_version: "2.0.0".to_owned(),
        image_repository: "ghcr.io/example/newapi".to_owned(),
        image_digest: NEW_DIGEST.to_owned(),
        deployment_schema: 2,
        minimum_deployment_schema: 2,
        minimum_updater_schema: 2,
        minimum_cli_schema: 2,
        minimum_data_schema: if data_migration { 2 } else { 1 },
        upgrade_kind: "deployment_and_image".to_owned(),
        required_capabilities: vec![
            "linux".to_owned(),
            "compose_v2".to_owned(),
            "systemd".to_owned(),
        ],
        artifacts: Vec::new(),
        migration_plan: ManifestMigrationPlan {
            from: 1,
            to: 2,
            steps,
        },
        health_policy: ManifestHealthPolicy {
            newapi_timeout_seconds: 10,
            dependency_timeout_seconds: 10,
            updater_heartbeat_max_age_seconds: 900,
        },
        rollback: ManifestRollback {
            supported: true,
            retained_backup_count: 3,
            data_rollback_required: data_migration,
        },
        created_at: 1,
        expires_at: i64::MAX,
        signature: String::new(),
    };
    let artifact = ManifestArtifact {
        name: "e2e.tar.zst".to_owned(),
        url: "https://assets.example/e2e.tar.zst".to_owned(),
        sha256: sha256(&archive),
        size: archive.len() as u64,
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
    };
    (manifest, artifact, archive)
}

fn change(kind: &str, name: &str, action: &str) -> BundleComposeChange {
    BundleComposeChange {
        kind: kind.to_owned(),
        name: name.to_owned(),
        action: action.to_owned(),
    }
}
fn sha256(value: &[u8]) -> String {
    crate::security::sha256_hex(value)
}

fn archive(files: Vec<(&str, u32, Vec<u8>)>) -> Vec<u8> {
    let encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
    let mut builder = tar::Builder::new(encoder);
    for (path, mode, body) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(mode);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path(path).unwrap();
        header.set_cksum();
        builder.append(&header, Cursor::new(body)).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

fn current_compose() -> Vec<u8> {
    br#"{"services":{"new-api":{"image":"ghcr.io/example/newapi@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"postgres":{},"redis":{},"uptime-kuma":{}}}"#.to_vec()
}
fn staged_compose() -> Vec<u8> {
    br#"{"services":{"new-api":{"image":"${MEOWAI_IMAGE_REFERENCE}"},"postgres":{},"redis":{},"uptime-kuma":{},"worker":{"image":"worker:v2"}}}"#.to_vec()
}
fn credentials() -> &'static str {
    "MEOWAI_DEPLOYMENT_ID=dep_e2e\nMEOWAI_INSTALLATION_GENERATION=1\nMEOWAI_CONTROL_PLANE_URL=http://control.example\nMEOWAI_REPORT_CREDENTIAL=report\nMEOWAI_PULL_CREDENTIAL=pull\nMEOWAI_HEARTBEAT_INTERVAL_SECONDS=60\nMEOWAI_SNAPSHOT_INTERVAL_SECONDS=300\nMEOWAI_DEPLOYMENT_SCHEMA=1\nMEOWAI_UPDATER_SCHEMA=1\nMEOWAI_CLI_SCHEMA=1\nMEOWAI_DATA_SCHEMA=1\nMEOWAI_CURRENT_IMAGE_DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nMEOWAI_ALLOWED_IMAGE_REPOSITORY=ghcr.io/example/newapi\nMEOWAI_CONTAINER_NAME=e2e-newapi\nMEOWAI_NEWAPI_PORT=3100\nMEOWAI_KUMA_PORT=3101\nMEOWAI_RELEASE_SCHEMA_VERSION=2\nMEOWAI_RELEASE_MANIFEST_PUBLIC_KEY=public-key\nMEOWAI_RELEASE_ARTIFACT_ALLOWED_HOSTS=assets.example\nMEOWAI_UPDATER_SOCKET_PATH=/run/meowai/updater.sock\n"
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn docker_script() -> String {
    r#"#!/bin/sh
set -eu
root=${FAKE_ROOT:?}
if grep -q 'dddddddd' "$root/docker-compose.yml" 2>/dev/null; then digest=$FAKE_NEW_DIGEST; else digest=$FAKE_OLD_DIGEST; fi
case "${1:-}" in
  inspect)
    case "$*" in
      *'.Config.Image'*) printf '%s@%s\n' 'ghcr.io/example/newapi' "$digest" ;;
      *'.State.Health'*) printf 'healthy\n' ;;
      *) printf 'ghcr.io/example/newapi@%s|running|healthy\n' "$digest" ;;
    esac
    ;;
  compose)
    args="$*"
    case "$args" in
      *'config --format json'*)
        if printf '%s' "$args" | grep -q '.upgrade/'; then
          printf '%s\n' '{"services":{"new-api":{"image":"ghcr.io/example/newapi@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"postgres":{},"redis":{},"uptime-kuma":{},"worker":{"image":"worker:v2"}}}'
        else
          printf '%s\n' '{"services":{"new-api":{"image":"ghcr.io/example/newapi@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"postgres":{},"redis":{},"uptime-kuma":{}}}'
        fi
        ;;
      *'config --services'*) printf 'new-api\npostgres\nredis\nuptime-kuma\nworker\n' ;;
      *'ps --services'*) printf 'new-api\npostgres\nredis\nuptime-kuma\nworker\n' ;;
      *'exec'*'pg_dump'*)
        if [ "${FAKE_EMPTY_PG_DUMP:-0}" != 1 ]; then cat "$root/data/postgres/business"; fi
        ;;
      *'exec'*'pg_restore'*'--list'*) : > "$root/pg-restore-list-checked" ;;
      *'exec'*'pg_isready'*) exit 0 ;;
      *'exec'*'psql'*'select 1'*) printf '1\n' ;;
      *'exec'*'pg_restore'*) cat > "$root/data/postgres/business" ;;
      *'exec'*'redis-cli'*'SAVE'*) exit 0 ;;
      *'exec'*'redis-cli'*'ping'*) printf 'PONG\n' ;;
      *'up '*)
        if [ "${FAKE_SWITCH_FAIL:-0}" = 1 ] && printf '%s' "$args" | grep -q 'remove-orphans'; then exit 1; fi
        printf '%s' "$digest" > "$root/current-digest"
        ;;
      *) exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
"#.to_owned()
}

fn systemctl_script() -> String {
    r#"#!/bin/sh
set -eu
root=${FAKE_ROOT:?}
printf 'systemctl %s\n' "$*" >> "$root/events.log"
case "$*" in
  *'enable --now'*) [ "${FAKE_TIMER_FAIL:-0}" != 1 ] || exit 1; : > "$root/timer-active" ;;
  *'is-enabled'*) test -f "$root/timer-active" ;;
  *'is-active'*) test -f "$root/timer-active" ;;
  *) exit 0 ;;
esac
"#
    .to_owned()
}

fn curl_script() -> String {
    r#"#!/bin/sh
set -eu
root=${FAKE_ROOT:?}
printf 'curl %s\n' "$*" >> "$root/events.log"
case "$*" in
  *'/api/status'*) [ "${FAKE_HEALTH_FAIL:-0}" != 1 ] || exit 1 ;;
  *'/api/setup'*) [ "${FAKE_HEALTH_FAIL:-0}" != 1 ] || exit 1 ;;
  *'/api/entry-page'*) exit 0 ;;
esac
printf '{}\n'
"#
    .to_owned()
}
