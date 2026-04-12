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
    EventTag, ProcessExecEvent, ProcessExitEvent, ProcessForkEvent,
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
