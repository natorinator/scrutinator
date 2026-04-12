//! BPF program loader and event observer
//!
//! Loads eBPF programs, attaches to tracepoints, and reads events
//! from the ring buffer.

use crate::events::{self, ScrutEvent};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use log::{debug, info, warn};
use std::time::Duration;
use tokio::sync::mpsc;

/// eBPF bytecode — embedded at compile time from the BPF build
const SCRUTINATOR_BPF: &[u8] = aya::include_bytes_aligned!(concat!(
    env!("OUT_DIR"),
    "/scrutinator-ebpf/bpfel-unknown-none/release/scrutinator"
));

/// The main observation controller
pub struct Observer {
    bpf: Ebpf,
}

impl Observer {
    /// Create a new observer by loading the eBPF programs
    ///
    /// Requires CAP_BPF + CAP_PERFMON or root.
    pub fn new() -> anyhow::Result<Self> {
        // Bump memlock limit for BPF maps
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
        }

        let mut bpf = Ebpf::load(SCRUTINATOR_BPF)?;

        // Initialize aya-log for BPF-side logging
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            warn!("Failed to init BPF logger: {}", e);
        }

        Ok(Self { bpf })
    }

    /// Attach process tracing programs (exec, fork, exit)
    pub fn attach_process_tracing(&mut self) -> anyhow::Result<()> {
        // sched_process_exec
        let exec_prog: &mut TracePoint = self
            .bpf
            .program_mut("sched_process_exec")
            .ok_or_else(|| anyhow::anyhow!("BPF program 'sched_process_exec' not found"))?
            .try_into()?;
        exec_prog.load()?;
        exec_prog.attach("sched", "sched_process_exec")?;
        info!("Attached sched_process_exec tracepoint");

        // sched_process_fork
        let fork_prog: &mut TracePoint = self
            .bpf
            .program_mut("sched_process_fork")
            .ok_or_else(|| anyhow::anyhow!("BPF program 'sched_process_fork' not found"))?
            .try_into()?;
        fork_prog.load()?;
        fork_prog.attach("sched", "sched_process_fork")?;
        info!("Attached sched_process_fork tracepoint");

        // sched_process_exit
        let exit_prog: &mut TracePoint = self
            .bpf
            .program_mut("sched_process_exit")
            .ok_or_else(|| anyhow::anyhow!("BPF program 'sched_process_exit' not found"))?
            .try_into()?;
        exit_prog.load()?;
        exit_prog.attach("sched", "sched_process_exit")?;
        info!("Attached sched_process_exit tracepoint");

        Ok(())
    }

    /// Attach file access tracing programs (open, delete, rename)
    pub fn attach_file_tracing(&mut self) -> anyhow::Result<()> {
        // sys_enter_openat
        let open_prog: &mut TracePoint = self
            .bpf
            .program_mut("sys_enter_openat")
            .ok_or_else(|| anyhow::anyhow!("BPF program 'sys_enter_openat' not found"))?
            .try_into()?;
        open_prog.load()?;
        open_prog.attach("syscalls", "sys_enter_openat")?;
        info!("Attached sys_enter_openat tracepoint");

        // sys_enter_unlinkat
        let unlink_prog: &mut TracePoint = self
            .bpf
            .program_mut("sys_enter_unlinkat")
            .ok_or_else(|| anyhow::anyhow!("BPF program 'sys_enter_unlinkat' not found"))?
            .try_into()?;
        unlink_prog.load()?;
        unlink_prog.attach("syscalls", "sys_enter_unlinkat")?;
        info!("Attached sys_enter_unlinkat tracepoint");

        // sys_enter_renameat2
        let rename_prog: &mut TracePoint = self
            .bpf
            .program_mut("sys_enter_renameat2")
            .ok_or_else(|| anyhow::anyhow!("BPF program 'sys_enter_renameat2' not found"))?
            .try_into()?;
        rename_prog.load()?;
        rename_prog.attach("syscalls", "sys_enter_renameat2")?;
        info!("Attached sys_enter_renameat2 tracepoint");

        Ok(())
    }

    /// Run the observer, sending events to a channel
    pub async fn run(&mut self, tx: mpsc::Sender<ScrutEvent>) -> anyhow::Result<()> {
        let ring_buf = RingBuf::try_from(self.bpf.map_mut("EVENTS").unwrap())?;
        let mut poll = tokio::io::unix::AsyncFd::new(ring_buf)?;

        info!("Scrutinator observer running, waiting for events...");

        loop {
            let mut guard = poll.readable_mut().await?;

            while let Some(item) = guard.get_inner_mut().next() {
                let data = item.as_ref();
                if data.len() < 4 {
                    continue;
                }

                // Read event tag from first 4 bytes
                let tag_val = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

                let event = match tag_val {
                    1 => {
                        // ProcessExec
                        if data.len() >= core::mem::size_of::<scrutinator_common::ProcessExecEvent>() {
                            let raw = unsafe {
                                &*(data.as_ptr()
                                    as *const scrutinator_common::ProcessExecEvent)
                            };
                            Some(events::from_exec(raw))
                        } else {
                            None
                        }
                    }
                    2 => {
                        // ProcessFork
                        if data.len() >= core::mem::size_of::<scrutinator_common::ProcessForkEvent>() {
                            let raw = unsafe {
                                &*(data.as_ptr()
                                    as *const scrutinator_common::ProcessForkEvent)
                            };
                            Some(events::from_fork(raw))
                        } else {
                            None
                        }
                    }
                    3 => {
                        // ProcessExit
                        if data.len() >= core::mem::size_of::<scrutinator_common::ProcessExitEvent>() {
                            let raw = unsafe {
                                &*(data.as_ptr()
                                    as *const scrutinator_common::ProcessExitEvent)
                            };
                            Some(events::from_exit(raw))
                        } else {
                            None
                        }
                    }
                    4 => {
                        // FileOpen
                        if data.len() >= core::mem::size_of::<scrutinator_common::FileOpenEvent>() {
                            let raw = unsafe {
                                &*(data.as_ptr() as *const scrutinator_common::FileOpenEvent)
                            };
                            Some(events::from_file_open(raw))
                        } else {
                            None
                        }
                    }
                    6 => {
                        // FileDelete
                        if data.len() >= core::mem::size_of::<scrutinator_common::FileDeleteEvent>()
                        {
                            let raw = unsafe {
                                &*(data.as_ptr() as *const scrutinator_common::FileDeleteEvent)
                            };
                            Some(events::from_file_delete(raw))
                        } else {
                            None
                        }
                    }
                    7 => {
                        // FileRename
                        if data.len() >= core::mem::size_of::<scrutinator_common::FileRenameEvent>()
                        {
                            let raw = unsafe {
                                &*(data.as_ptr() as *const scrutinator_common::FileRenameEvent)
                            };
                            Some(events::from_file_rename(raw))
                        } else {
                            None
                        }
                    }
                    _ => {
                        debug!("Unknown event tag: {}", tag_val);
                        None
                    }
                };

                if let Some(event) = event {
                    if tx.send(event).await.is_err() {
                        return Ok(()); // Channel closed, exit gracefully
                    }
                }
            }

            guard.clear_ready();
        }
    }

    /// Run the observer for a limited duration, collecting all events
    pub async fn run_for(&mut self, duration: Duration) -> anyhow::Result<Vec<ScrutEvent>> {
        let (tx, mut rx) = mpsc::channel(4096);
        let mut collected = Vec::new();

        tokio::select! {
            result = self.run(tx) => {
                result?;
            }
            _ = tokio::time::sleep(duration) => {
                info!("Observation period complete");
            }
        }

        // Drain remaining events from channel
        rx.close();
        while let Some(event) = rx.recv().await {
            collected.push(event);
        }

        Ok(collected)
    }
}
