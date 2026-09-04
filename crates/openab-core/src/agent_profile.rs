//! Validation and compatibility checks for opt-in existing agent profiles.
//!
//! A profile is immutable, reviewable input. It must never overlap the mutable
//! agent state directory because `pre_seed` may replace profile files at every
//! process start.

use crate::config::{AgentConfig, AgentProfileConfig};
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};
use tokio::process::Command;
use tracing::{info, warn};

const SUPPORTED_SCHEMA_VERSION: u32 = 1;
const MAX_SCANNED_FILE_BYTES: u64 = 1024 * 1024;
const MAX_SCANNED_FILES: usize = 10_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileManifest {
    schema_version: u32,
    name: String,
    version: String,
    runtime: String,
    runtime_version: String,
    #[serde(default)]
    required_paths: Vec<String>,
    #[serde(default)]
    managed_paths: Vec<String>,
}

/// Validate an optional profile after lifecycle hooks have prepared it and
/// before secrets are resolved or any agent subprocess is started.
pub async fn validate_and_report(agent: &AgentConfig, max_sessions: usize) -> Result<()> {
    let Some(profile) = agent.profile.as_ref() else {
        return Ok(());
    };

    let validated = validate_profile(profile, &agent.command)?;

    if max_sessions > 1 {
        warn!(
            max_sessions,
            state_dir = %validated.state_dir.display(),
            "existing agent profile uses a per-session process model; verify that the runtime's mutable state supports concurrent processes"
        );
    }

    info!(
        profile = %validated.manifest.name,
        profile_version = %validated.manifest.version,
        schema_version = validated.manifest.schema_version,
        runtime = %validated.manifest.runtime,
        expected_runtime_version = %validated.manifest.runtime_version,
        command = %agent.command,
        profile_root = %validated.root.display(),
        state_dir = %validated.state_dir.display(),
        process_model = "per-session-stdio-acp",
        "existing agent profile validated"
    );

    if let Some(ref doctor) = validated.doctor {
        run_doctor(
            doctor,
            profile.doctor_timeout_seconds,
            &validated,
            &agent.command,
        )
        .await?;
    }

    Ok(())
}

#[derive(Debug)]
struct ValidatedProfile {
    root: PathBuf,
    state_dir: PathBuf,
    manifest: ProfileManifest,
    doctor: Option<PathBuf>,
}

fn validate_profile(profile: &AgentProfileConfig, agent_command: &str) -> Result<ValidatedProfile> {
    let root = require_absolute_directory("agent.profile.root", &profile.root)?;
    let state_dir = require_absolute_directory("agent.profile.state_dir", &profile.state_dir)?;

    if paths_overlap(&root, &state_dir) {
        bail!(
            "agent.profile.root ({}) and agent.profile.state_dir ({}) must not overlap; profile refreshes must not overwrite mutable auth, session, memory, or workspace state",
            root.display(),
            state_dir.display()
        );
    }

    let manifest_path = resolve_profile_path(&root, "agent.profile.manifest", &profile.manifest)?;
    let manifest_text = std::fs::read_to_string(&manifest_path).with_context(|| {
        format!(
            "failed to read profile manifest {}",
            manifest_path.display()
        )
    })?;
    let manifest: ProfileManifest = toml::from_str(&manifest_text)
        .with_context(|| format!("invalid profile manifest {}", manifest_path.display()))?;

    validate_manifest_fields(&manifest, agent_command)?;

    for path in &manifest.required_paths {
        let resolved = resolve_profile_path(&root, "required_paths entry", path)?;
        if !resolved.exists() {
            bail!(
                "profile required path does not exist: {} ({})",
                path,
                resolved.display()
            );
        }
    }

    for path in &manifest.managed_paths {
        let resolved = resolve_profile_path(&root, "managed_paths entry", path)?;
        if !resolved.exists() {
            bail!(
                "profile managed path does not exist: {} ({})",
                path,
                resolved.display()
            );
        }
    }

    if profile.scan_credentials {
        scan_profile_root(&root)?;
    }

    let doctor = profile
        .doctor
        .as_deref()
        .map(|path| resolve_profile_path(&root, "agent.profile.doctor", path))
        .transpose()?;
    if let Some(path) = doctor.as_ref() {
        if !path.is_file() {
            bail!("agent.profile.doctor is not a file: {}", path.display());
        }
    }

    Ok(ValidatedProfile {
        root,
        state_dir,
        manifest,
        doctor,
    })
}

fn validate_manifest_fields(manifest: &ProfileManifest, agent_command: &str) -> Result<()> {
    if manifest.schema_version != SUPPORTED_SCHEMA_VERSION {
        bail!(
            "unsupported agent profile schema_version {}; supported version is {}",
            manifest.schema_version,
            SUPPORTED_SCHEMA_VERSION
        );
    }
    for (field, value) in [
        ("name", manifest.name.as_str()),
        ("version", manifest.version.as_str()),
        ("runtime", manifest.runtime.as_str()),
        ("runtime_version", manifest.runtime_version.as_str()),
    ] {
        if value.trim().is_empty() {
            bail!("agent profile manifest field '{field}' must not be empty");
        }
    }
    if !manifest.runtime.eq_ignore_ascii_case("hermes") {
        bail!(
            "agent profile runtime '{}' is unsupported; this contract currently supports only 'hermes'",
            manifest.runtime
        );
    }
    let command_name = Path::new(agent_command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(agent_command);
    if !command_name.to_ascii_lowercase().contains("hermes") {
        bail!(
            "Hermes profile cannot be used with agent command '{agent_command}'; configure hermes-acp or another Hermes ACP command"
        );
    }
    Ok(())
}

fn require_absolute_directory(field: &str, value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if !path.is_absolute() {
        bail!("{field} must be an absolute path, got: {value}");
    }
    let canonical = path
        .canonicalize()
        .with_context(|| format!("{field} does not exist or cannot be resolved: {value}"))?;
    if !canonical.is_dir() {
        bail!("{field} is not a directory: {}", canonical.display());
    }
    Ok(canonical)
}

fn resolve_profile_path(root: &Path, field: &str, value: &str) -> Result<PathBuf> {
    let relative = Path::new(value);
    if value.trim().is_empty() || relative.is_absolute() {
        bail!("{field} must be a non-empty path relative to agent.profile.root");
    }
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("{field} contains a disallowed path component: {value}");
    }
    let joined = root.join(relative);
    let canonical = joined
        .canonicalize()
        .with_context(|| format!("{field} does not exist or cannot be resolved: {value}"))?;
    if !canonical.starts_with(root) {
        bail!("{field} resolves outside agent.profile.root: {value}");
    }
    Ok(canonical)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn scan_profile_root(root: &Path) -> Result<()> {
    let mut scanned = 0;
    scan_path(root, &mut scanned)
}

fn scan_path(path: &Path, scanned: &mut usize) -> Result<()> {
    if *scanned >= MAX_SCANNED_FILES {
        bail!("profile credential scan exceeded {MAX_SCANNED_FILES} files");
    }
    if path.is_dir() {
        for entry in std::fs::read_dir(path)
            .with_context(|| format!("failed to scan profile directory {}", path.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                bail!(
                    "agent profile contains a symlink, which is not scanned safely: {}",
                    entry.path().display()
                );
            }
            scan_path(&entry.path(), scanned)?;
        }
        return Ok(());
    }
    if !path.is_file() {
        bail!(
            "agent profile path is not a regular file: {}",
            path.display()
        );
    }

    *scanned += 1;
    let metadata = path.metadata()?;
    if metadata.len() > MAX_SCANNED_FILE_BYTES {
        bail!(
            "agent profile file is too large to credential-scan safely: {} ({} bytes, max {})",
            path.display(),
            metadata.len(),
            MAX_SCANNED_FILE_BYTES
        );
    }
    let bytes = std::fs::read(path)?;
    if let Some(reason) = credential_indicator(path, &bytes) {
        bail!(
            "agent profile may contain credential material: {} ({reason}); move secrets to runtime secret injection or set scan_credentials=false only after a security review",
            path.display()
        );
    }
    Ok(())
}

fn credential_indicator(path: &Path, bytes: &[u8]) -> Option<&'static str> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if matches!(
        name.as_str(),
        ".env" | "credentials" | "credentials.json" | "auth.json" | "id_rsa" | "id_ed25519"
    ) || name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".p12")
        || name.ends_with(".pfx")
    {
        return Some("sensitive filename");
    }

    let text = std::str::from_utf8(bytes).ok()?;
    let indicators = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "xoxb-",
        "xapp-",
        "github_pat_",
        "ghp_",
        "AKIA",
    ];
    indicators
        .iter()
        .find(|indicator| text.contains(**indicator))
        .map(|_| "known credential pattern")
}

async fn run_doctor(
    doctor: &Path,
    timeout_seconds: u64,
    profile: &ValidatedProfile,
    agent_command: &str,
) -> Result<()> {
    info!(doctor = %doctor.display(), "running agent profile doctor");
    let mut command = Command::new(doctor);
    command.env_clear();
    for key in ["HOME", "PATH", "USER"] {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    command
        .current_dir(&profile.root)
        .env("OPENAB_PROFILE_ROOT", &profile.root)
        .env("OPENAB_PROFILE_NAME", &profile.manifest.name)
        .env("OPENAB_PROFILE_VERSION", &profile.manifest.version)
        .env("OPENAB_PROFILE_RUNTIME", &profile.manifest.runtime)
        .env(
            "OPENAB_PROFILE_RUNTIME_VERSION",
            &profile.manifest.runtime_version,
        )
        .env("OPENAB_STATE_DIR", &profile.state_dir)
        .env("OPENAB_AGENT_COMMAND", agent_command);

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start agent profile doctor {}", doctor.display()))?;
    let status = if timeout_seconds == 0 {
        child.wait().await?
    } else {
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_seconds),
            child.wait(),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.kill().await;
                return Err(anyhow!(
                    "agent profile doctor timed out after {timeout_seconds}s"
                ));
            }
        }
    };
    if !status.success() {
        bail!("agent profile doctor exited with {status}");
    }
    info!(doctor = %doctor.display(), "agent profile doctor completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_profile(root: &Path, managed_contents: &str) {
        fs::create_dir_all(root.join("config")).unwrap();
        fs::write(root.join("config/config.yaml"), managed_contents).unwrap();
        fs::write(
            root.join("manifest.toml"),
            r#"
schema_version = 1
name = "team-hermes"
version = "2026.09.04"
runtime = "hermes"
runtime_version = "2026.8.31"
required_paths = ["config/config.yaml"]
managed_paths = ["config"]
"#,
        )
        .unwrap();
    }

    fn config(root: &Path, state: &Path) -> AgentProfileConfig {
        AgentProfileConfig {
            root: root.display().to_string(),
            state_dir: state.display().to_string(),
            manifest: "manifest.toml".into(),
            doctor: None,
            doctor_timeout_seconds: 60,
            scan_credentials: true,
        }
    }

    #[test]
    fn validates_separate_hermes_profile() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profile");
        let state = temp.path().join("state");
        write_profile(&root, "model: claude\n");
        fs::create_dir_all(&state).unwrap();

        let validated = validate_profile(&config(&root, &state), "hermes-acp").unwrap();
        assert_eq!(validated.manifest.name, "team-hermes");
    }

    #[test]
    fn rejects_overlapping_profile_and_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("home/profile");
        let state = temp.path().join("home");
        write_profile(&root, "model: claude\n");
        fs::create_dir_all(&state).unwrap();

        let error = validate_profile(&config(&root, &state), "hermes-acp").unwrap_err();
        assert!(error.to_string().contains("must not overlap"));
    }

    #[test]
    fn rejects_non_hermes_command() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profile");
        let state = temp.path().join("state");
        write_profile(&root, "model: claude\n");
        fs::create_dir_all(&state).unwrap();

        let error = validate_profile(&config(&root, &state), "codex-acp").unwrap_err();
        assert!(error.to_string().contains("Hermes profile"));
    }

    #[test]
    fn rejects_credentials_in_managed_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profile");
        let state = temp.path().join("state");
        write_profile(&root, "token: xoxb-secret\n");
        fs::create_dir_all(&state).unwrap();

        let error = validate_profile(&config(&root, &state), "hermes-acp").unwrap_err();
        assert!(error.to_string().contains("credential material"));
    }

    #[test]
    fn rejects_credentials_even_when_file_is_not_declared_managed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profile");
        let state = temp.path().join("state");
        write_profile(&root, "model: claude\n");
        fs::write(root.join("auth.json"), "{}\n").unwrap();
        fs::create_dir_all(&state).unwrap();

        let error = validate_profile(&config(&root, &state), "hermes-acp").unwrap_err();
        assert!(error.to_string().contains("sensitive filename"));
    }

    #[test]
    fn rejects_required_path_escape() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profile");
        let state = temp.path().join("state");
        write_profile(&root, "model: claude\n");
        fs::write(
            root.join("manifest.toml"),
            r#"
schema_version = 1
name = "team-hermes"
version = "2026.09.04"
runtime = "hermes"
runtime_version = "2026.8.31"
required_paths = ["../outside"]
"#,
        )
        .unwrap();
        fs::create_dir_all(&state).unwrap();

        let error = validate_profile(&config(&root, &state), "hermes-acp").unwrap_err();
        assert!(error.to_string().contains("disallowed path component"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn doctor_receives_only_profile_metadata() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profile");
        let state = temp.path().join("state");
        write_profile(&root, "model: claude\n");
        fs::create_dir_all(root.join("checks")).unwrap();
        fs::create_dir_all(&state).unwrap();
        let doctor = root.join("checks/doctor.sh");
        fs::write(
            &doctor,
            "#!/bin/sh\nset -eu\ntest \"$OPENAB_PROFILE_NAME\" = team-hermes\ntest \"$OPENAB_STATE_DIR\" != \"\"\ntest \"${SLACK_BOT_TOKEN-unset}\" = unset\n",
        )
        .unwrap();
        fs::set_permissions(&doctor, fs::Permissions::from_mode(0o700)).unwrap();

        let mut profile_config = config(&root, &state);
        profile_config.doctor = Some("checks/doctor.sh".into());
        let validated = validate_profile(&profile_config, "hermes-acp").unwrap();
        std::env::set_var("SLACK_BOT_TOKEN", "must-not-leak");
        run_doctor(&doctor, 5, &validated, "hermes-acp")
            .await
            .unwrap();
        std::env::remove_var("SLACK_BOT_TOKEN");
    }
}
