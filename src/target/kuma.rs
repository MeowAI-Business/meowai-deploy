use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, Result},
    security::sha256_hex,
    source::StatusManifest,
    state::KumaMonitorState,
    target::TargetExecutor,
};

#[derive(Debug, Serialize)]
struct KumaInput<'a> {
    kuma_username: &'a str,
    kuma_password: &'a str,
    force: bool,
    website_name: &'a str,
    status_page_slug: &'a str,
    source_base_url: &'a str,
    status_key: &'a str,
    deployment_id: &'a str,
    manifest: &'a StatusManifest,
}

#[derive(Debug, Deserialize)]
struct KumaHelperResult {
    ok: bool,
    #[serde(default)]
    error: String,
    #[serde(default)]
    page_slug: String,
    #[serde(default)]
    monitors: Vec<KumaMonitorState>,
}

#[derive(Debug)]
pub struct KumaSyncResult {
    pub page_slug: String,
    pub manifest_sha256: String,
    pub monitors: BTreeMap<String, KumaMonitorState>,
}

pub struct KumaSyncOptions<'a> {
    pub executor: &'a TargetExecutor,
    pub container_name: &'a str,
    pub deployment_id: &'a str,
    pub website_name: &'a str,
    pub source_base_url: &'a str,
    pub status_key: &'a SecretString,
    pub kuma_username: &'a str,
    pub kuma_password: &'a SecretString,
    pub force: bool,
    pub manifest: &'a StatusManifest,
}

pub fn status_page_slug(deployment_id: &str) -> String {
    format!("meowai-{deployment_id}")
}

pub fn sync_status_page(options: KumaSyncOptions<'_>) -> Result<KumaSyncResult> {
    if !options.manifest.success {
        return Err(AppError::Target(
            "source public status manifest reported failure".to_owned(),
        ));
    }
    let page_slug = status_page_slug(options.deployment_id);
    let input = KumaInput {
        kuma_username: options.kuma_username,
        kuma_password: options.kuma_password.expose_secret(),
        force: options.force,
        website_name: options.website_name,
        status_page_slug: &page_slug,
        source_base_url: options.source_base_url,
        status_key: options.status_key.expose_secret(),
        deployment_id: options.deployment_id,
        manifest: options.manifest,
    };
    let input_json = serde_json::to_string(&input)
        .map_err(|error| AppError::Target(format!("serialize Kuma input: {error}")))?;
    let helper = include_str!("kuma_helper.js");
    let program = format!(
        "const input = {input};\n{helper}\nmain(input);",
        input = input_json,
        helper = helper,
    );
    let kuma_container = format!("{}-uptime-kuma", options.container_name);
    // The payload is sent over stdin to the container and is never written to the target disk
    // or passed as a docker process argument.
    let script = format!(
        "printf %s {program} | docker exec -i {container} node -",
        program = shell_escape::escape(program.into()),
        container = shell_escape::escape(kuma_container.into()),
    );
    let output = options.executor.run_script(&script)?;
    let raw = String::from_utf8_lossy(&output.stdout);
    let line = raw.lines().last().unwrap_or_default();
    let result: KumaHelperResult = serde_json::from_str(line)
        .map_err(|error| AppError::Target(format!("decode Kuma helper result: {error}")))?;
    if !result.ok {
        return Err(AppError::Target(format!(
            "Kuma sync failed: {}",
            result.error
        )));
    }
    let manifest_sha256 = sha256_hex(
        &serde_json::to_vec(options.manifest)
            .map_err(|error| AppError::Target(format!("hash Kuma manifest: {error}")))?,
    );
    let monitors = result
        .monitors
        .into_iter()
        .map(|monitor| (monitor.source_monitor_id.clone(), monitor))
        .collect();
    Ok(KumaSyncResult {
        page_slug: result.page_slug,
        manifest_sha256,
        monitors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_page_slug_is_stable_and_safe() {
        assert_eq!(status_page_slug("abcdef12"), "meowai-abcdef12");
    }
}
