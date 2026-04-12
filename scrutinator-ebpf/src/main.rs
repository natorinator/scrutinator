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
    EventTag, FileDeleteEvent, FileOpenEvent, FileRenameEvent, ProcessExecEvent, ProcessExitEvent,
    ProcessForkEvent, MAX_PATH_LEN,
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
