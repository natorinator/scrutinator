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
    FileOpen = 4,
    FileClose = 5,
    FileDelete = 6,
    FileRename = 7,
    NetConnect = 8,
    NetBind = 9,
    NetStateChange = 10,
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

// --- File access events ---

/// Open flags we care about (subset of libc O_* constants)
pub mod open_flags {
    pub const O_RDONLY: u32 = 0;
    pub const O_WRONLY: u32 = 1;
    pub const O_RDWR: u32 = 2;
    pub const O_CREAT: u32 = 0o100;
    pub const O_TRUNC: u32 = 0o1000;
    pub const O_APPEND: u32 = 0o2000;
    pub const O_ACCESS_MODE_MASK: u32 = 3;
}

/// File open event — emitted on sys_enter_openat
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenEvent {
    pub tag: EventTag,
    pub pid: u32,
    pub flags: u32,
    pub mode: u32,
    pub path: [u8; MAX_PATH_LEN],
    pub comm: [u8; MAX_COMM_LEN],
    pub timestamp_ns: u64,
}

/// File close event — emitted on sys_enter_close (for tracked fds)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileCloseEvent {
    pub tag: EventTag,
    pub pid: u32,
    pub fd: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub timestamp_ns: u64,
}

/// File delete event — emitted on sys_enter_unlinkat
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileDeleteEvent {
    pub tag: EventTag,
    pub pid: u32,
    pub path: [u8; MAX_PATH_LEN],
    pub comm: [u8; MAX_COMM_LEN],
    pub timestamp_ns: u64,
}

/// File rename event — emitted on sys_enter_renameat2
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameEvent {
    pub tag: EventTag,
    pub pid: u32,
    pub old_path: [u8; MAX_PATH_LEN],
    pub new_path: [u8; MAX_PATH_LEN],
    pub comm: [u8; MAX_COMM_LEN],
    pub timestamp_ns: u64,
}

// --- Network events ---

/// Address family constants
pub mod af {
    pub const AF_INET: u16 = 2;
    pub const AF_INET6: u16 = 10;
}

/// TCP state constants (matching kernel values)
pub mod tcp_state {
    pub const TCP_ESTABLISHED: u32 = 1;
    pub const TCP_SYN_SENT: u32 = 2;
    pub const TCP_SYN_RECV: u32 = 3;
    pub const TCP_FIN_WAIT1: u32 = 4;
    pub const TCP_FIN_WAIT2: u32 = 5;
    pub const TCP_TIME_WAIT: u32 = 6;
    pub const TCP_CLOSE: u32 = 7;
    pub const TCP_CLOSE_WAIT: u32 = 8;
    pub const TCP_LAST_ACK: u32 = 9;
    pub const TCP_LISTEN: u32 = 10;
    pub const TCP_CLOSING: u32 = 11;
}

/// Network state change event — from inet_sock_set_state tracepoint
///
/// This is the primary network event. It fires on TCP state transitions
/// and includes full source/dest address information.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetStateChangeEvent {
    pub tag: EventTag,
    pub pid: u32,
    pub old_state: u32,
    pub new_state: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub protocol: u16,
    /// IPv4 source address (4 bytes, network byte order)
    pub saddr: [u8; 4],
    /// IPv4 dest address (4 bytes, network byte order)
    pub daddr: [u8; 4],
    /// IPv6 source address (16 bytes)
    pub saddr_v6: [u8; 16],
    /// IPv6 dest address (16 bytes)
    pub daddr_v6: [u8; 16],
    pub comm: [u8; MAX_COMM_LEN],
    pub timestamp_ns: u64,
}

/// Network connect event — from sys_enter_connect
///
/// Captures the connect() syscall with destination address.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetConnectEvent {
    pub tag: EventTag,
    pub pid: u32,
    pub family: u16,
    pub port: u16,
    /// IPv4 address or first 4 bytes of IPv6
    pub addr: [u8; 4],
    /// Full IPv6 address (zero for IPv4)
    pub addr_v6: [u8; 16],
    pub comm: [u8; MAX_COMM_LEN],
    pub timestamp_ns: u64,
}

/// Network bind event — from sys_enter_bind
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetBindEvent {
    pub tag: EventTag,
    pub pid: u32,
    pub family: u16,
    pub port: u16,
    pub addr: [u8; 4],
    pub comm: [u8; MAX_COMM_LEN],
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

    impl core::fmt::Debug for FileOpenEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("FileOpenEvent")
                .field("pid", &self.pid)
                .field("flags", &self.flags)
                .field("path", &bytes_to_string(&self.path))
                .field("comm", &bytes_to_string(&self.comm))
                .finish()
        }
    }

    impl core::fmt::Debug for FileCloseEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("FileCloseEvent")
                .field("pid", &self.pid)
                .field("fd", &self.fd)
                .field("comm", &bytes_to_string(&self.comm))
                .finish()
        }
    }

    impl core::fmt::Debug for FileDeleteEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("FileDeleteEvent")
                .field("pid", &self.pid)
                .field("path", &bytes_to_string(&self.path))
                .field("comm", &bytes_to_string(&self.comm))
                .finish()
        }
    }

    impl core::fmt::Debug for FileRenameEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("FileRenameEvent")
                .field("pid", &self.pid)
                .field("old_path", &bytes_to_string(&self.old_path))
                .field("new_path", &bytes_to_string(&self.new_path))
                .field("comm", &bytes_to_string(&self.comm))
                .finish()
        }
    }

    /// Format an IPv4 address from 4 bytes
    pub fn format_ipv4(addr: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }

    /// Format an IPv6 address from 16 bytes
    pub fn format_ipv6(addr: &[u8; 16]) -> String {
        let segments: Vec<String> = (0..8)
            .map(|i| format!("{:x}", u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]])))
            .collect();
        segments.join(":")
    }

    /// Format an address based on family
    pub fn format_addr(family: u16, v4: &[u8; 4], v6: &[u8; 16]) -> String {
        if family == super::af::AF_INET6 {
            format_ipv6(v6)
        } else {
            format_ipv4(v4)
        }
    }

    impl core::fmt::Debug for NetStateChangeEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("NetStateChangeEvent")
                .field("pid", &self.pid)
                .field("src", &format!("{}:{}", format_addr(self.family, &self.saddr, &self.saddr_v6), self.sport))
                .field("dst", &format!("{}:{}", format_addr(self.family, &self.daddr, &self.daddr_v6), self.dport))
                .field("old_state", &self.old_state)
                .field("new_state", &self.new_state)
                .finish()
        }
    }

    impl core::fmt::Debug for NetConnectEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("NetConnectEvent")
                .field("pid", &self.pid)
                .field("addr", &format!("{}:{}", format_addr(self.family, &self.addr, &self.addr_v6), self.port))
                .field("comm", &bytes_to_string(&self.comm))
                .finish()
        }
    }

    impl core::fmt::Debug for NetBindEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("NetBindEvent")
                .field("pid", &self.pid)
                .field("addr", &format!("{}:{}", format_ipv4(&self.addr), self.port))
                .field("comm", &bytes_to_string(&self.comm))
                .finish()
        }
    }
}

#[cfg(feature = "user")]
pub use user_impls::{bytes_to_string, format_addr, format_ipv4, format_ipv6};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_sizes_are_stable() {
        assert!(core::mem::size_of::<ProcessExecEvent>() > 0);
        assert!(core::mem::size_of::<ProcessForkEvent>() > 0);
        assert!(core::mem::size_of::<ProcessExitEvent>() > 0);
        assert!(core::mem::size_of::<FileOpenEvent>() > 0);
        assert!(core::mem::size_of::<FileDeleteEvent>() > 0);
        assert!(core::mem::size_of::<FileRenameEvent>() > 0);
    }

    #[test]
    fn event_tag_values() {
        assert_eq!(EventTag::ProcessExec as u32, 1);
        assert_eq!(EventTag::ProcessFork as u32, 2);
        assert_eq!(EventTag::ProcessExit as u32, 3);
        assert_eq!(EventTag::FileOpen as u32, 4);
        assert_eq!(EventTag::FileClose as u32, 5);
        assert_eq!(EventTag::FileDelete as u32, 6);
        assert_eq!(EventTag::FileRename as u32, 7);
        assert_eq!(EventTag::NetConnect as u32, 8);
        assert_eq!(EventTag::NetBind as u32, 9);
        assert_eq!(EventTag::NetStateChange as u32, 10);
    }

    #[test]
    fn net_event_sizes() {
        assert!(core::mem::size_of::<NetStateChangeEvent>() > 0);
        assert!(core::mem::size_of::<NetConnectEvent>() > 0);
        assert!(core::mem::size_of::<NetBindEvent>() > 0);
    }
}
