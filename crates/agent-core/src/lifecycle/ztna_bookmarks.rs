use anyhow::Result;
use ztna::{
    default_bookmark_state_path, discover_launchers, write_bookmark_state, BookmarkRecord,
    BookmarkState,
};

use super::AgentRuntime;

impl AgentRuntime {
    pub(super) fn sync_ztna_bookmarks(&self) -> Result<()> {
        let Some(latest) = self.client.latest_ztna_bookmarks() else {
            return Ok(());
        };
        let launchers = discover_launchers();
        let state = BookmarkState {
            version: latest.version,
            bookmarks: latest
                .bookmarks
                .into_iter()
                .map(|bookmark| {
                    let app_type = bookmark.app_type.trim().to_ascii_lowercase();
                    let launcher_supported = match app_type.as_str() {
                        "ssh" => launchers.ssh.is_some(),
                        "rdp" => launchers.rdp.is_some(),
                        "vnc" => launchers.vnc.is_some(),
                        "web" | "http" | "https" => launchers.web.is_some(),
                        _ => false,
                    };
                    BookmarkRecord {
                        app_id: bookmark.app_id.clone(),
                        name: bookmark.name.clone(),
                        icon: bookmark.icon.clone(),
                        app_type: bookmark.app_type.clone(),
                        description: bookmark.description.clone(),
                        health_status: bookmark.health_status.clone(),
                        launch_uri: build_bookmark_launch_uri(
                            &bookmark.app_id,
                            &bookmark.name,
                            &bookmark.app_type,
                        ),
                        launcher_supported,
                    }
                })
                .collect(),
        };
        write_bookmark_state(&default_bookmark_state_path(), &state)
    }
}

fn build_bookmark_launch_uri(app_id: &str, name: &str, app_type: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("app_id", app_id);
    serializer.append_pair("name", name);
    serializer.append_pair("type", app_type);
    format!("eguard-ztna://launch?{}", serializer.finish())
}

#[cfg(test)]
mod tests {
    use super::build_bookmark_launch_uri;

    #[test]
    fn bookmark_launch_uri_contains_required_fields() {
        let uri = build_bookmark_launch_uri("app-1", "SSH Admin", "ssh");
        assert!(uri.contains("app_id=app-1"));
        assert!(uri.contains("type=ssh"));
    }
}
