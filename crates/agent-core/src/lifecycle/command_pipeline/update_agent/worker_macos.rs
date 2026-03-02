use std::path::Path;

use super::request::NormalizedUpdateRequest;

pub(super) fn spawn_update_worker(
    _request: &NormalizedUpdateRequest,
    _update_dir: &Path,
) -> Result<String, String> {
    Err("macOS update worker is not implemented yet".to_string())
}
