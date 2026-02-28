use response::{CommandExecution, CommandOutcome};

use super::command_utils::{mdm_action_allowed, run_command};
use super::payloads::AppPayload;

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use super::sanitize::{sanitize_apt_package_name, sanitize_apt_package_version};
#[cfg(target_os = "macos")]
use super::sanitize::{sanitize_macos_package_name, sanitize_macos_package_version};
#[cfg(target_os = "windows")]
use super::sanitize::{sanitize_windows_package_name, sanitize_windows_package_version};

pub(super) fn apply_app_command(action: &str, payload_json: &str, exec: &mut CommandExecution) {
    if !mdm_action_allowed("app") {
        exec.outcome = CommandOutcome::Ignored;
        exec.status = "failed";
        exec.detail = "app management blocked by policy".to_string();
        return;
    }

    let payload: AppPayload = match serde_json::from_str(payload_json) {
        Ok(payload) => payload,
        Err(err) => {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("invalid app payload: {}", err);
            return;
        }
    };

    #[cfg(target_os = "windows")]
    {
        let package_name = match sanitize_windows_package_name(&payload.package_name) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid package_name: {}", err);
                return;
            }
        };

        let version = match sanitize_windows_package_version(&payload.version) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid version: {}", err);
                return;
            }
        };

        let mut args = match action {
            "install" => vec![
                "install".to_string(),
                "--id".to_string(),
                package_name.clone(),
                "--exact".to_string(),
                "--accept-package-agreements".to_string(),
                "--accept-source-agreements".to_string(),
            ],
            "remove" => vec![
                "uninstall".to_string(),
                "--id".to_string(),
                package_name.clone(),
                "--exact".to_string(),
            ],
            "update" => vec![
                "upgrade".to_string(),
                "--id".to_string(),
                package_name.clone(),
                "--exact".to_string(),
            ],
            _ => vec![
                "install".to_string(),
                "--id".to_string(),
                package_name.clone(),
                "--exact".to_string(),
                "--accept-package-agreements".to_string(),
                "--accept-source-agreements".to_string(),
            ],
        };

        if action == "install" && !version.is_empty() {
            args.push("--version".to_string());
            args.push(version);
        }

        if let Err(err) = run_command("winget", &args) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("app {} failed: {}", action, err);
        } else {
            exec.detail = format!("app {} executed for {}", action, package_name);
        }

        return;
    }

    #[cfg(target_os = "macos")]
    {
        let package_name = match sanitize_macos_package_name(&payload.package_name) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid package_name: {}", err);
                return;
            }
        };

        let version = match sanitize_macos_package_version(&payload.version) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid version: {}", err);
                return;
            }
        };

        let package = if version.is_empty() {
            package_name.clone()
        } else {
            format!("{}@{}", package_name, version)
        };

        let args = match action {
            "install" => vec!["install", package.as_str()],
            "remove" => vec!["uninstall", package_name.as_str()],
            "update" => vec!["upgrade", package_name.as_str()],
            _ => vec!["install", package.as_str()],
        };

        let cmd_args = args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        if let Err(err) = run_command("brew", &cmd_args) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("app {} failed: {}", action, err);
        } else {
            exec.detail = format!("app {} executed for {}", action, package_name);
        }

        return;
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let package_name = match sanitize_apt_package_name(&payload.package_name) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid package_name: {}", err);
                return;
            }
        };

        let version = match sanitize_apt_package_version(&payload.version) {
            Ok(value) => value,
            Err(err) => {
                exec.outcome = CommandOutcome::Ignored;
                exec.status = "failed";
                exec.detail = format!("invalid version: {}", err);
                return;
            }
        };

        let package = if version.is_empty() {
            package_name.clone()
        } else {
            format!("{}={}", package_name, version)
        };

        let args = match action {
            "install" => vec!["install", "-y", package.as_str()],
            "remove" => vec!["remove", "-y", package_name.as_str()],
            "update" => vec!["install", "-y", package.as_str()],
            _ => vec!["install", "-y", package.as_str()],
        };

        let cmd_args = args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        if let Err(err) = run_command("apt-get", &cmd_args) {
            exec.outcome = CommandOutcome::Ignored;
            exec.status = "failed";
            exec.detail = format!("app {} failed: {}", action, err);
        } else {
            exec.detail = format!("app {} executed for {}", action, package_name);
        }
    }
}
