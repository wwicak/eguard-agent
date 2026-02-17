use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

use grpc_client::ThreatIntelVersionEnvelope;

use super::bundle_guard::verify_bundle_sha256_if_present;
use super::super::bundle_path::{is_remote_bundle_reference, staging_bundle_archive_path};
use super::super::{is_signed_bundle_archive, AgentRuntime};

impl AgentRuntime {
    pub(super) async fn prepare_bundle_for_reload(
        &self,
        intel: &ThreatIntelVersionEnvelope,
    ) -> Result<String> {
        let version = intel.version.trim();
        let bundle_path = intel.bundle_path.trim();
        if bundle_path.is_empty() {
            return Ok(String::new());
        }

        if !is_remote_bundle_reference(bundle_path) {
            verify_bundle_sha256_if_present(Path::new(bundle_path), &intel.bundle_sha256)?;
            return Ok(bundle_path.to_string());
        }

        let local_bundle = self
            .download_remote_bundle_archive(version, bundle_path)
            .await?;
        verify_bundle_sha256_if_present(&local_bundle, &intel.bundle_sha256)?;
        self.download_remote_bundle_signature_if_needed(
            bundle_path,
            &intel.bundle_signature_path,
            &local_bundle,
        )
        .await?;

        Ok(local_bundle.to_string_lossy().into_owned())
    }

    async fn download_remote_bundle_archive(
        &self,
        version: &str,
        bundle_url: &str,
    ) -> Result<PathBuf> {
        let local_bundle = staging_bundle_archive_path(version, bundle_url)?;
        self.client
            .download_bundle(bundle_url, &local_bundle)
            .await
            .map_err(|err| anyhow!("download threat-intel bundle '{}': {}", bundle_url, err))?;
        Ok(local_bundle)
    }

    async fn download_remote_bundle_signature_if_needed(
        &self,
        bundle_url: &str,
        bundle_signature_ref: &str,
        local_bundle: &Path,
    ) -> Result<()> {
        if !is_signed_bundle_archive(local_bundle) {
            return Ok(());
        }

        let signature_url = resolve_signature_reference(bundle_url, bundle_signature_ref);
        let signature_dst = PathBuf::from(format!("{}.sig", local_bundle.to_string_lossy()));
        self.client
            .download_bundle(&signature_url, &signature_dst)
            .await
            .map_err(|err| {
                anyhow!(
                    "download threat-intel bundle signature '{}': {}",
                    signature_url,
                    err
                )
            })?;
        Ok(())
    }
}

pub(super) fn resolve_signature_reference(bundle_ref: &str, signature_ref: &str) -> String {
    let explicit_ref = signature_ref.trim();

    if !explicit_ref.is_empty() {
        return explicit_ref.to_string();
    }

    format!("{}.sig", bundle_ref.trim())
}
