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
}

impl ScrutEvent {
    /// Get the primary PID associated with this event
    pub fn pid(&self) -> u32 {
        match self {
            ScrutEvent::ProcessExec { pid, .. } => *pid,
            ScrutEvent::ProcessFork { parent_pid, .. } => *parent_pid,
            ScrutEvent::ProcessExit { pid, .. } => *pid,
        }
    }

    /// Get the event timestamp
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            ScrutEvent::ProcessExec { timestamp, .. } => *timestamp,
            ScrutEvent::ProcessFork { timestamp, .. } => *timestamp,
            ScrutEvent::ProcessExit { timestamp, .. } => *timestamp,
        }
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
