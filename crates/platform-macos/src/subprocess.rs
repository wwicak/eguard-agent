use std::io;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tracing::warn;

/// Run a short-lived macOS helper command with a hard wall-clock timeout.
///
/// Several Apple CLIs used for inventory/compliance (`system_profiler`,
/// `softwareupdate`, `profiles`) can block for tens of seconds in VMs. The
/// agent tick path calls these collectors synchronously today, so every call
/// must be bounded until those collectors are fully moved to background workers.
pub(crate) fn output_with_timeout(
    command: &mut Command,
    timeout_duration: Duration,
) -> io::Result<Option<Output>> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let program = command.get_program().to_string_lossy().into_owned();
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout_duration;

    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map(Some);
        }

        if Instant::now() >= deadline {
            warn!(
                program = %program,
                args = ?args,
                timeout_ms = timeout_duration.as_millis(),
                "macOS helper command timed out; killing subprocess"
            );
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}
