mod bookmarks;
mod commands;
mod discovery;
mod launcher;
mod protocol;
mod sessions;
mod types;
mod uri;

pub use bookmarks::{
    bookmark_by_app_id, default_bookmark_state_path, read_bookmark_state, write_bookmark_state,
};
pub use commands::{default_command_queue_dir, drain_commands, enqueue_command};
pub use discovery::{discover_launchers, DiscoveredLaunchers};
pub use launcher::{launch_request, launch_uri, LaunchOutcome};
pub use protocol::register_protocol_handler_for_current_exe;
pub use sessions::{
    clear_sessions, default_session_state_path, empty_session_state, next_session_id,
    read_session_state, remove_session, session_by_id, set_transport_disabled, upsert_session,
    write_session_state,
};
pub use types::{
    ActiveSessionRecord, SessionState, TrayCommand, TrayCommandKind, TrayCommandResult,
};
pub use types::{BookmarkRecord, BookmarkState, LaunchRequest, LaunchTargetKind};
pub use uri::parse_launch_uri;
