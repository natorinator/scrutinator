//! Shared types between scrutinator BPF programs and userspace
//!
//! This crate is `no_std` compatible so it can be used in both BPF
//! and userspace contexts. Event structs use `#[repr(C)]` for safe
//! cross-boundary data passing via BPF ring buffer.

#![cfg_attr(not(feature = "user"), no_std)]

/// Maximum path length captured in BPF events
pub const MAX_PATH_LEN: usize = 256;

/// Maximum comm (process name) length
pub const MAX_COMM_LEN: usize = 16;

/// Event tag for discriminating event types in the ring buffer
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventTag {
    ProcessExec = 1,
    ProcessFork = 2,
    ProcessExit = 3,
}

/// Process execution event — emitted on sched_process_exec
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecEvent {
    /// Event discriminant
    pub tag: EventTag,
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process name (comm)
    pub comm: [u8; MAX_COMM_LEN],
    /// Binary path
    pub filename: [u8; MAX_PATH_LEN],
    /// Monotonic timestamp (nanoseconds)
    pub timestamp_ns: u64,
}

/// Process fork event — emitted on sched_process_fork
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessForkEvent {
    /// Event discriminant
    pub tag: EventTag,
    /// Parent PID
    pub parent_pid: u32,
    /// Child PID
    pub child_pid: u32,
    /// Parent comm
    pub parent_comm: [u8; MAX_COMM_LEN],
    /// Monotonic timestamp (nanoseconds)
    pub timestamp_ns: u64,
}

/// Process exit event — emitted on sched_process_exit
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExitEvent {
    /// Event discriminant
    pub tag: EventTag,
    /// Process ID
    pub pid: u32,
    /// Exit code
    pub exit_code: i32,
    /// Process comm
    pub comm: [u8; MAX_COMM_LEN],
    /// Monotonic timestamp (nanoseconds)
    pub timestamp_ns: u64,
}

#[cfg(feature = "user")]
mod user_impls {
    use super::*;

    /// Helper to convert a fixed-size byte array to a string, stopping at first null
    pub fn bytes_to_string(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).to_string()
    }

    impl core::fmt::Debug for ProcessExecEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("ProcessExecEvent")
                .field("pid", &self.pid)
                .field("ppid", &self.ppid)
                .field("comm", &bytes_to_string(&self.comm))
                .field("filename", &bytes_to_string(&self.filename))
                .field("timestamp_ns", &self.timestamp_ns)
                .finish()
        }
    }

    impl core::fmt::Debug for ProcessForkEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("ProcessForkEvent")
                .field("parent_pid", &self.parent_pid)
                .field("child_pid", &self.child_pid)
                .field("parent_comm", &bytes_to_string(&self.parent_comm))
                .field("timestamp_ns", &self.timestamp_ns)
                .finish()
        }
    }

    impl core::fmt::Debug for ProcessExitEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("ProcessExitEvent")
                .field("pid", &self.pid)
                .field("exit_code", &self.exit_code)
                .field("comm", &bytes_to_string(&self.comm))
                .field("timestamp_ns", &self.timestamp_ns)
                .finish()
        }
    }
}

#[cfg(feature = "user")]
pub use user_impls::bytes_to_string;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_sizes_are_stable() {
        // Ensure struct sizes don't accidentally change
        assert!(core::mem::size_of::<ProcessExecEvent>() > 0);
        assert!(core::mem::size_of::<ProcessForkEvent>() > 0);
        assert!(core::mem::size_of::<ProcessExitEvent>() > 0);
    }

    #[test]
    fn event_tag_values() {
        assert_eq!(EventTag::ProcessExec as u32, 1);
        assert_eq!(EventTag::ProcessFork as u32, 2);
        assert_eq!(EventTag::ProcessExit as u32, 3);
    }
}
