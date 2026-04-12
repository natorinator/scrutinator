//! Userspace event types
//!
//! Higher-level event types that wrap the raw BPF events with
//! ergonomic string fields and timestamps.

use chrono::{DateTime, Utc};
use scrutinator_common::bytes_to_string;
use serde::Serialize;

/// A scrutinator observation event
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScrutEvent {
    // --- Process events ---

    /// A process called execve()
    ProcessExec {
        pid: u32,
        ppid: u32,
        comm: String,
        filename: String,
        timestamp: DateTime<Utc>,
    },

    /// A process forked
    ProcessFork {
        parent_pid: u32,
        child_pid: u32,
        parent_comm: String,
        timestamp: DateTime<Utc>,
    },

    /// A process exited
    ProcessExit {
        pid: u32,
        exit_code: i32,
        comm: String,
        timestamp: DateTime<Utc>,
    },

    // --- File events ---

    /// A file was opened
    FileOpen {
        pid: u32,
        comm: String,
        path: String,
        flags: u32,
        writable: bool,
        created: bool,
        timestamp: DateTime<Utc>,
    },

    /// A file was deleted (unlinkat)
    FileDelete {
        pid: u32,
        comm: String,
        path: String,
        timestamp: DateTime<Utc>,
    },

    /// A file was renamed
    FileRename {
        pid: u32,
        comm: String,
        old_path: String,
        new_path: String,
        timestamp: DateTime<Utc>,
    },
}

impl ScrutEvent {
    /// Get the primary PID associated with this event
    pub fn pid(&self) -> u32 {
        match self {
            ScrutEvent::ProcessExec { pid, .. }
            | ScrutEvent::ProcessExit { pid, .. }
            | ScrutEvent::FileOpen { pid, .. }
            | ScrutEvent::FileDelete { pid, .. }
            | ScrutEvent::FileRename { pid, .. } => *pid,
            ScrutEvent::ProcessFork { parent_pid, .. } => *parent_pid,
        }
    }

    /// Get the event timestamp
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            ScrutEvent::ProcessExec { timestamp, .. }
            | ScrutEvent::ProcessFork { timestamp, .. }
            | ScrutEvent::ProcessExit { timestamp, .. }
            | ScrutEvent::FileOpen { timestamp, .. }
            | ScrutEvent::FileDelete { timestamp, .. }
            | ScrutEvent::FileRename { timestamp, .. } => *timestamp,
        }
    }

    /// Is this a file event?
    pub fn is_file_event(&self) -> bool {
        matches!(
            self,
            ScrutEvent::FileOpen { .. }
                | ScrutEvent::FileDelete { .. }
                | ScrutEvent::FileRename { .. }
        )
    }
}

/// Convert a raw BPF exec event to a ScrutEvent
pub(crate) fn from_exec(raw: &scrutinator_common::ProcessExecEvent) -> ScrutEvent {
    ScrutEvent::ProcessExec {
        pid: raw.pid,
        ppid: raw.ppid,
        comm: bytes_to_string(&raw.comm),
        filename: bytes_to_string(&raw.filename),
        timestamp: ktime_to_utc(raw.timestamp_ns),
    }
}

/// Convert a raw BPF fork event to a ScrutEvent
pub(crate) fn from_fork(raw: &scrutinator_common::ProcessForkEvent) -> ScrutEvent {
    ScrutEvent::ProcessFork {
        parent_pid: raw.parent_pid,
        child_pid: raw.child_pid,
        parent_comm: bytes_to_string(&raw.parent_comm),
        timestamp: ktime_to_utc(raw.timestamp_ns),
    }
}

/// Convert a raw BPF exit event to a ScrutEvent
pub(crate) fn from_exit(raw: &scrutinator_common::ProcessExitEvent) -> ScrutEvent {
    ScrutEvent::ProcessExit {
        pid: raw.pid,
        exit_code: raw.exit_code,
        comm: bytes_to_string(&raw.comm),
        timestamp: ktime_to_utc(raw.timestamp_ns),
    }
}

/// Convert a raw BPF file open event to a ScrutEvent
pub(crate) fn from_file_open(raw: &scrutinator_common::FileOpenEvent) -> ScrutEvent {
    use scrutinator_common::open_flags;
    let access_mode = raw.flags & open_flags::O_ACCESS_MODE_MASK;
    let writable = access_mode == open_flags::O_WRONLY || access_mode == open_flags::O_RDWR;
    let created = raw.flags & open_flags::O_CREAT != 0;

    ScrutEvent::FileOpen {
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        path: bytes_to_string(&raw.path),
        flags: raw.flags,
        writable,
        created,
        timestamp: ktime_to_utc(raw.timestamp_ns),
    }
}

/// Convert a raw BPF file delete event to a ScrutEvent
pub(crate) fn from_file_delete(raw: &scrutinator_common::FileDeleteEvent) -> ScrutEvent {
    ScrutEvent::FileDelete {
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        path: bytes_to_string(&raw.path),
        timestamp: ktime_to_utc(raw.timestamp_ns),
    }
}

/// Convert a raw BPF file rename event to a ScrutEvent
pub(crate) fn from_file_rename(raw: &scrutinator_common::FileRenameEvent) -> ScrutEvent {
    ScrutEvent::FileRename {
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        old_path: bytes_to_string(&raw.old_path),
        new_path: bytes_to_string(&raw.new_path),
        timestamp: ktime_to_utc(raw.timestamp_ns),
    }
}

/// Convert kernel monotonic nanoseconds to wall-clock UTC
///
/// This is approximate — we use the current time as a reference point
/// since bpf_ktime_get_ns() is monotonic, not wall-clock.
fn ktime_to_utc(ktime_ns: u64) -> DateTime<Utc> {
    // Best-effort: use boot time offset
    // For now, just use current time as the event time since
    // events are processed near-real-time
    let _ = ktime_ns;
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrut_event_pid() {
        let event = ScrutEvent::ProcessExec {
            pid: 1234,
            ppid: 1,
            comm: "test".to_string(),
            filename: "/usr/bin/test".to_string(),
            timestamp: Utc::now(),
        };
        assert_eq!(event.pid(), 1234);
    }

    #[test]
    fn file_event_pid() {
        let event = ScrutEvent::FileOpen {
            pid: 999,
            comm: "vim".to_string(),
            path: "/etc/passwd".to_string(),
            flags: 0,
            writable: false,
            created: false,
            timestamp: Utc::now(),
        };
        assert_eq!(event.pid(), 999);
        assert!(event.is_file_event());
    }

    #[test]
    fn file_open_writable_flag() {
        use scrutinator_common::open_flags;

        let raw = scrutinator_common::FileOpenEvent {
            tag: scrutinator_common::EventTag::FileOpen,
            pid: 1,
            flags: open_flags::O_WRONLY | open_flags::O_CREAT,
            mode: 0o644,
            path: [0; 256],
            comm: [0; 16],
            timestamp_ns: 0,
        };
        let event = from_file_open(&raw);
        match event {
            ScrutEvent::FileOpen { writable, created, .. } => {
                assert!(writable);
                assert!(created);
            }
            _ => panic!("Expected FileOpen"),
        }
    }

    #[test]
    fn file_open_readonly() {
        use scrutinator_common::open_flags;

        let raw = scrutinator_common::FileOpenEvent {
            tag: scrutinator_common::EventTag::FileOpen,
            pid: 1,
            flags: open_flags::O_RDONLY,
            mode: 0,
            path: [0; 256],
            comm: [0; 16],
            timestamp_ns: 0,
        };
        let event = from_file_open(&raw);
        match event {
            ScrutEvent::FileOpen { writable, created, .. } => {
                assert!(!writable);
                assert!(!created);
            }
            _ => panic!("Expected FileOpen"),
        }
    }

    #[test]
    fn file_event_serializes() {
        let event = ScrutEvent::FileOpen {
            pid: 42,
            comm: "cat".to_string(),
            path: "/etc/passwd".to_string(),
            flags: 0,
            writable: false,
            created: false,
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"file_open\""));
        assert!(json.contains("/etc/passwd"));
    }

    #[test]
    fn process_event_is_not_file_event() {
        let event = ScrutEvent::ProcessExec {
            pid: 1,
            ppid: 0,
            comm: "init".to_string(),
            filename: "/sbin/init".to_string(),
            timestamp: Utc::now(),
        };
        assert!(!event.is_file_event());
    }

    #[test]
    fn scrut_event_serializes() {
        let event = ScrutEvent::ProcessExec {
            pid: 42,
            ppid: 1,
            comm: "bash".to_string(),
            filename: "/usr/bin/bash".to_string(),
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"process_exec\""));
        assert!(json.contains("\"pid\":42"));
    }
}
