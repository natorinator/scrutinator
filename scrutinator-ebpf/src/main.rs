//! Scrutinator BPF programs
//!
//! Process tracing via tracepoints. Events are written to a ring buffer
//! and consumed by the userspace scrutinator library.
//!
//! NOTE: BPF stack is limited to 512 bytes. Large structs (with path buffers)
//! must be written directly to ring buffer reservations, not constructed on stack.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use scrutinator_common::{
    EventTag, FileDeleteEvent, FileOpenEvent, FileRenameEvent, NetBindEvent, NetConnectEvent,
    NetStateChangeEvent, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent, MAX_PATH_LEN,
};

/// Ring buffer for delivering events to userspace
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint: sched/sched_process_exec
///
/// Fired when a process calls execve(). Captures PID, PPID, and comm.
/// Filename is read in userspace from /proc/pid/exe to avoid stack overflow.
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_process_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_process_exec(_ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Write directly to ring buffer to avoid stack overflow
    if let Some(mut buf) = EVENTS.reserve::<ProcessExecEvent>(0) {
        let ptr = buf.as_mut_ptr() as *mut ProcessExecEvent;
        unsafe {
            (*ptr).tag = EventTag::ProcessExec;
            (*ptr).pid = pid;
            (*ptr).ppid = 0; // Enriched in userspace from /proc
            (*ptr).comm = comm;
            // Zero the filename — userspace reads /proc/pid/exe instead
            (*ptr).filename = [0u8; scrutinator_common::MAX_PATH_LEN];
            (*ptr).timestamp_ns = timestamp_ns;
        }
        buf.submit(0);
    }

    Ok(())
}

/// Tracepoint: sched/sched_process_fork
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_process_fork(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_process_fork(_ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let parent_pid = (pid_tgid >> 32) as u32;
    let parent_comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    if let Some(mut buf) = EVENTS.reserve::<ProcessForkEvent>(0) {
        let ptr = buf.as_mut_ptr() as *mut ProcessForkEvent;
        unsafe {
            (*ptr).tag = EventTag::ProcessFork;
            (*ptr).parent_pid = parent_pid;
            (*ptr).child_pid = 0; // Not easily available in fork tracepoint from current context
            (*ptr).parent_comm = parent_comm;
            (*ptr).timestamp_ns = timestamp_ns;
        }
        buf.submit(0);
    }

    Ok(())
}

/// Tracepoint: sched/sched_process_exit
#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    match try_process_exit() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_process_exit() -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    if let Some(mut buf) = EVENTS.reserve::<ProcessExitEvent>(0) {
        let ptr = buf.as_mut_ptr() as *mut ProcessExitEvent;
        unsafe {
            (*ptr).tag = EventTag::ProcessExit;
            (*ptr).pid = pid;
            (*ptr).exit_code = 0; // Not directly available in this tracepoint
            (*ptr).comm = comm;
            (*ptr).timestamp_ns = timestamp_ns;
        }
        buf.submit(0);
    }

    Ok(())
}

// --- File access tracing ---

/// Tracepoint: syscalls/sys_enter_openat
///
/// Captures file open operations with path and flags.
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_file_open(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_file_open(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Read args from tracepoint context
    // sys_enter_openat format: __syscall_nr(8), dfd(16), filename(24), flags(32), mode(40)
    let filename_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let flags: u32 = unsafe { ctx.read_at::<u64>(32).unwrap_or(0) as u32 };
    let mode: u32 = unsafe { ctx.read_at::<u64>(40).unwrap_or(0) as u32 };

    if filename_ptr == 0 {
        return Ok(());
    }

    // Write directly to ringbuf to avoid stack overflow from path buffer
    if let Some(mut buf) = EVENTS.reserve::<FileOpenEvent>(0) {
        let ptr = buf.as_mut_ptr() as *mut FileOpenEvent;
        unsafe {
            (*ptr).tag = EventTag::FileOpen;
            (*ptr).pid = pid;
            (*ptr).flags = flags;
            (*ptr).mode = mode;
            (*ptr).comm = comm;
            (*ptr).timestamp_ns = timestamp_ns;
            // Read path from userspace
            (*ptr).path = [0u8; MAX_PATH_LEN];
            let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
                filename_ptr as *const u8,
                &mut (*ptr).path,
            );
        }
        buf.submit(0);
    }

    Ok(())
}

/// Tracepoint: syscalls/sys_enter_unlinkat
///
/// Captures file deletion.
#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    match try_file_delete(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_file_delete(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // sys_enter_unlinkat: __syscall_nr(8), dfd(16), pathname(24), flag(32)
    let pathname_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };

    if pathname_ptr == 0 {
        return Ok(());
    }

    if let Some(mut buf) = EVENTS.reserve::<FileDeleteEvent>(0) {
        let ptr = buf.as_mut_ptr() as *mut FileDeleteEvent;
        unsafe {
            (*ptr).tag = EventTag::FileDelete;
            (*ptr).pid = pid;
            (*ptr).comm = comm;
            (*ptr).timestamp_ns = timestamp_ns;
            (*ptr).path = [0u8; MAX_PATH_LEN];
            let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
                pathname_ptr as *const u8,
                &mut (*ptr).path,
            );
        }
        buf.submit(0);
    }

    Ok(())
}

/// Tracepoint: syscalls/sys_enter_renameat2
///
/// Captures file renames (old path and new path).
#[tracepoint]
pub fn sys_enter_renameat2(ctx: TracePointContext) -> u32 {
    match try_file_rename(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_file_rename(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // sys_enter_renameat2: __syscall_nr(8), olddfd(16), oldname(24), newdfd(32), newname(40), flags(48)
    let oldname_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let newname_ptr: u64 = unsafe { ctx.read_at(40).unwrap_or(0) };

    if oldname_ptr == 0 || newname_ptr == 0 {
        return Ok(());
    }

    if let Some(mut buf) = EVENTS.reserve::<FileRenameEvent>(0) {
        let ptr = buf.as_mut_ptr() as *mut FileRenameEvent;
        unsafe {
            (*ptr).tag = EventTag::FileRename;
            (*ptr).pid = pid;
            (*ptr).comm = comm;
            (*ptr).timestamp_ns = timestamp_ns;
            (*ptr).old_path = [0u8; MAX_PATH_LEN];
            (*ptr).new_path = [0u8; MAX_PATH_LEN];
            let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
                oldname_ptr as *const u8,
                &mut (*ptr).old_path,
            );
            let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
                newname_ptr as *const u8,
                &mut (*ptr).new_path,
            );
        }
        buf.submit(0);
    }

    Ok(())
}

// --- Network tracing ---

/// Tracepoint: sock/inet_sock_set_state
///
/// Fires on TCP state transitions. Provides full source/dest address info
/// directly in the tracepoint args (no userspace pointer reading needed).
#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_net_state_change(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_net_state_change(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // inet_sock_set_state format:
    // skaddr(8), oldstate(16), newstate(20), sport(24), dport(26),
    // family(28), protocol(30), saddr(32), daddr(36), saddr_v6(40), daddr_v6(56)
    let old_state: u32 = unsafe { ctx.read_at(16).unwrap_or(0) };
    let new_state: u32 = unsafe { ctx.read_at(20).unwrap_or(0) };
    let sport: u16 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let dport: u16 = unsafe { ctx.read_at(26).unwrap_or(0) };
    let family: u16 = unsafe { ctx.read_at(28).unwrap_or(0) };
    let protocol: u16 = unsafe { ctx.read_at(30).unwrap_or(0) };

    if let Some(mut buf) = EVENTS.reserve::<NetStateChangeEvent>(0) {
        let ptr = buf.as_mut_ptr() as *mut NetStateChangeEvent;
        unsafe {
            (*ptr).tag = EventTag::NetStateChange;
            (*ptr).pid = pid;
            (*ptr).old_state = old_state;
            (*ptr).new_state = new_state;
            (*ptr).sport = sport;
            (*ptr).dport = dport;
            (*ptr).family = family;
            (*ptr).protocol = protocol;
            (*ptr).comm = comm;
            (*ptr).timestamp_ns = timestamp_ns;

            // Read addresses from tracepoint context
            (*ptr).saddr = [0u8; 4];
            (*ptr).daddr = [0u8; 4];
            (*ptr).saddr_v6 = [0u8; 16];
            (*ptr).daddr_v6 = [0u8; 16];

            // IPv4 addresses at offset 32 and 36
            if let Ok(saddr) = ctx.read_at::<[u8; 4]>(32) {
                (*ptr).saddr = saddr;
            }
            if let Ok(daddr) = ctx.read_at::<[u8; 4]>(36) {
                (*ptr).daddr = daddr;
            }
            // IPv6 addresses at offset 40 and 56
            if family == 10 {
                // AF_INET6
                if let Ok(saddr_v6) = ctx.read_at::<[u8; 16]>(40) {
                    (*ptr).saddr_v6 = saddr_v6;
                }
                if let Ok(daddr_v6) = ctx.read_at::<[u8; 16]>(56) {
                    (*ptr).daddr_v6 = daddr_v6;
                }
            }
        }
        buf.submit(0);
    }

    Ok(())
}

/// Tracepoint: syscalls/sys_enter_bind
///
/// Captures bind() calls to detect port binding / listening.
#[tracepoint]
pub fn sys_enter_bind(ctx: TracePointContext) -> u32 {
    match try_net_bind(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_net_bind(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // sys_enter_bind: __syscall_nr(8), fd(16), umyaddr(24), addrlen(32)
    let addr_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };

    if addr_ptr == 0 {
        return Ok(());
    }

    // Read sockaddr_in from userspace: family(2 bytes), port(2 bytes), addr(4 bytes)
    let mut sa_buf = [0u8; 8];
    unsafe {
        let _ = aya_ebpf::helpers::bpf_probe_read_user_buf(addr_ptr as *const u8, &mut sa_buf);
    }

    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);
    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = [sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]];

    if let Some(mut buf) = EVENTS.reserve::<NetBindEvent>(0) {
        let ptr = buf.as_mut_ptr() as *mut NetBindEvent;
        unsafe {
            (*ptr).tag = EventTag::NetBind;
            (*ptr).pid = pid;
            (*ptr).family = family;
            (*ptr).port = port;
            (*ptr).addr = addr;
            (*ptr).comm = comm;
            (*ptr).timestamp_ns = timestamp_ns;
        }
        buf.submit(0);
    }

    Ok(())
}

/// Tracepoint: syscalls/sys_enter_connect
///
/// Captures connect() calls with destination address.
#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_net_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_net_connect(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // sys_enter_connect: __syscall_nr(8), fd(16), uservaddr(24), addrlen(32)
    let addr_ptr: u64 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let addrlen: u64 = unsafe { ctx.read_at(32).unwrap_or(0) };

    if addr_ptr == 0 {
        return Ok(());
    }

    // Read sockaddr from userspace
    // sockaddr_in: family(2), port(2), addr(4)
    // sockaddr_in6: family(2), port(2), flowinfo(4), addr(16)
    let mut sa_buf = [0u8; 28]; // enough for sockaddr_in6
    let read_len = if addrlen > 28 { 28 } else { addrlen as usize };
    unsafe {
        let _ = aya_ebpf::helpers::bpf_probe_read_user_buf(
            addr_ptr as *const u8,
            &mut sa_buf[..read_len],
        );
    }

    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);
    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = [sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]];

    // Read IPv6 address if AF_INET6
    let mut addr_v6 = [0u8; 16];
    if family == 10 && read_len >= 24 {
        // sockaddr_in6: addr starts at offset 8 (after family + port + flowinfo)
        addr_v6.copy_from_slice(&sa_buf[8..24]);
    }

    // Skip AF_UNIX and other non-IP families
    if family != 2 && family != 10 {
        return Ok(());
    }

    if let Some(mut buf) = EVENTS.reserve::<NetConnectEvent>(0) {
        let ptr = buf.as_mut_ptr() as *mut NetConnectEvent;
        unsafe {
            (*ptr).tag = EventTag::NetConnect;
            (*ptr).pid = pid;
            (*ptr).family = family;
            (*ptr).port = port;
            (*ptr).addr = addr;
            (*ptr).addr_v6 = addr_v6;
            (*ptr).comm = comm;
            (*ptr).timestamp_ns = timestamp_ns;
        }
        buf.submit(0);
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
