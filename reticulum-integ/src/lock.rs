//! Process-wide advisory lock for `reticulum-integ` tests.
//!
//! Two `cargo test -p reticulum-integ` invocations on the same box will fight
//! over Docker container names and USB serial handles (both identified by
//! fixed-name conventions). The most recent incident: a systemd-scheduled
//! Tier 3 nightly fired at 02:00 while a manual benchmark was running, and
//! the nightly's Docker integ tests killed the benchmark's `sender`/
//! `receiver` containers mid-run.
//!
//! `acquire_integ_lock()` is called as the very first statement of
//! `TestRunner::new()`. First caller acquires an exclusive `flock` on
//! `~/.local/state/leviculum-ci/test.lock` and writes identity metadata
//! (pid, started, pkg, binary, cwd, optional filter). Subsequent callers in
//! the same process are no-ops (the `OnceLock` already holds the `File`).
//! Callers from *other* processes find the lock held, drop a marker file at
//! `~/.local/state/leviculum-ci/lock-contention`, print a multi-line
//! `[leviculum]` error to stderr naming the current holder, and exit with
//! code 2. The marker file decouples the "this was a SKIPPED-not-RED" signal
//! from the exact prose of the error message — the Tier 2/3 runner scripts
//! look for the marker, not a grep on the log.
//!
//! OS-managed release: when the holding process exits (clean, panic,
//! SIGINT, SIGKILL — all of them), the kernel closes the fd and releases
//! the flock. Stale lock files on disk after a reboot are self-healing —
//! flock state is kernel-held, not file-content-held.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Process-wide holder for the integ lock. Kept here (not inside
/// `TestRunner`) so the fd outlives every `TestRunner` instance in the
/// process and is only released by OS close-on-exit. Must stay
/// `OnceLock<File>` — switching to `OnceLock<RwLock<_>>` or similar would
/// break the release-on-panic invariant. See the `#[should_panic]` test in
/// `executor.rs` that guards this.
static LOCK_GUARD: OnceLock<File> = OnceLock::new();

/// Acquire the process-wide integ-test lock. First call in this process
/// holds the flock for the process lifetime. Subsequent calls are no-ops.
/// On contention: drop a marker file, print an error, `exit(2)`.
pub fn acquire_integ_lock() {
    LOCK_GUARD.get_or_init(open_and_lock);
}

fn state_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set for acquire_integ_lock");
    PathBuf::from(home).join(".local/state/leviculum-ci")
}

fn lock_path() -> PathBuf {
    state_dir().join("test.lock")
}

fn marker_path() -> PathBuf {
    state_dir().join("lock-contention")
}

fn open_and_lock() -> File {
    let dir = state_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = lock_path();

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .unwrap_or_else(|e| panic!("cannot open integ test lock {}: {e}", path.display()));

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        fail_on_contention(&path);
    }

    let _ = file.set_len(0);
    let _ = write!(&mut file, "{}", identity_block());
    let _ = file.sync_all();
    file
}

fn fail_on_contention(path: &std::path::Path) -> ! {
    let existing = std::fs::read_to_string(path).unwrap_or_default();

    // Drop the marker before the error print so the runner script can
    // detect SKIPPED even if stderr is clipped or redirected.
    let marker = marker_path();
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::File::create(&marker);

    eprintln!();
    eprintln!("[leviculum] Another integration test is already running.");
    if !existing.trim().is_empty() {
        eprintln!("[leviculum] Current holder:");
        for line in existing.lines() {
            eprintln!("[leviculum]   {line}");
        }
    } else {
        eprintln!("[leviculum] (holder metadata not yet written — race with writer)");
    }
    eprintln!("[leviculum] Wait for it to finish or stop that process, then retry.");
    eprintln!();

    std::process::exit(2);
}

fn identity_block() -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(256);
    let _ = writeln!(out, "pid={}", std::process::id());
    let _ = writeln!(out, "started={}", format_local_iso8601());
    let _ = writeln!(out, "pkg={}", env!("CARGO_PKG_NAME"));
    let _ = writeln!(out, "binary={}", argv0_basename());
    if let Ok(cwd) = std::env::current_dir() {
        let _ = writeln!(out, "cwd={}", cwd.display());
    }
    if let Some(filter) = test_filter_hint() {
        let _ = writeln!(out, "filter={filter}");
    }
    out
}

fn argv0_basename() -> String {
    std::env::args()
        .next()
        .and_then(|p| {
            std::path::Path::new(&p)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "<unknown>".into())
}

/// Best-effort sniff of the test-name filter the user passed. Covers the
/// common `--exact NAME`, `-- NAME`, and `cargo test -- NAME` shapes.
/// Returns None if no likely filter is present; false positives are fine —
/// this is just a debugging aid in the lock file, not load-bearing.
fn test_filter_hint() -> Option<String> {
    let mut args = std::env::args().skip(1);
    let mut saw_double_dash = false;
    while let Some(a) = args.next() {
        if a == "--" {
            saw_double_dash = true;
            continue;
        }
        if a == "--exact" {
            return args.next();
        }
        if saw_double_dash && !a.starts_with('-') {
            return Some(a);
        }
    }
    None
}

/// `YYYY-MM-DDTHH:MM:SS` in local time. No tz suffix; single-dev-box
/// context makes that acceptable and avoids pulling `chrono`/`time` just
/// for formatting. Uses `libc::localtime_r` on a `SystemTime` → epoch
/// seconds conversion.
fn format_local_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // SAFETY: `tm` is zero-initialised plain data; `localtime_r` writes
    // into it. We pass a valid pointer to a valid `time_t`.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t: libc::time_t = secs as libc::time_t;
    let rc = unsafe { libc::localtime_r(&t, &mut tm) };
    if rc.is_null() {
        // Fall back to a recognisable sentinel instead of panicking.
        return format!("epoch+{secs}");
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_format_shape() {
        let s = format_local_iso8601();
        // Expected shape: YYYY-MM-DDTHH:MM:SS == 19 chars
        assert_eq!(s.len(), 19, "got {s:?}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
    }

    #[test]
    fn identity_block_has_required_keys() {
        let block = identity_block();
        assert!(block.contains("pid="));
        assert!(block.contains("started="));
        assert!(block.contains("pkg=reticulum-integ"));
        assert!(block.contains("binary="));
    }
}
