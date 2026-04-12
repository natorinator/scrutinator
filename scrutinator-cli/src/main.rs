//! Scrutinator CLI — eBPF system observation tool
//!
//! Watch process execution, file access, and network connections
//! in real-time using kernel-level eBPF tracing.

use clap::{Parser, Subcommand};
use scrutinator::ScrutEvent;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(name = "scrutinator")]
#[command(about = "eBPF system observation — watch what processes actually do")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Watch process events in real-time
    ///
    /// Traces process execution (execve), forking, and exit events
    /// using kernel eBPF tracepoints. Requires root or CAP_BPF.
    Watch {
        /// Only show events for this PID and its descendants
        #[arg(long)]
        pid: Option<u32>,

        /// Stop after this many seconds
        #[arg(long)]
        duration: Option<u64>,

        /// Output as JSON (one event per line)
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Watch { pid, duration, json } => {
            run_watch(pid, duration, json).await
        }
    }
}

async fn run_watch(
    filter_pid: Option<u32>,
    duration_secs: Option<u64>,
    json_output: bool,
) -> anyhow::Result<()> {
    eprintln!("Loading eBPF programs...");

    let mut observer = scrutinator::Observer::new()?;
    observer.attach_process_tracing()?;

    eprintln!("Watching process events (Ctrl-C to stop)...");
    if let Some(pid) = filter_pid {
        eprintln!("Filtering to PID {} and descendants", pid);
    }
    eprintln!();

    let (tx, mut rx) = mpsc::channel::<ScrutEvent>(4096);

    // Spawn observer in background
    let observer_handle = tokio::spawn(async move {
        if let Err(e) = observer.run(tx).await {
            eprintln!("Observer error: {}", e);
        }
    });

    // Set up duration timeout
    let deadline = duration_secs.map(|s| tokio::time::Instant::now() + Duration::from_secs(s));

    // Track PIDs that are descendants of the filter PID
    let mut tracked_pids = std::collections::HashSet::new();
    if let Some(pid) = filter_pid {
        tracked_pids.insert(pid);
    }

    loop {
        let event = if let Some(deadline) = deadline {
            tokio::select! {
                event = rx.recv() => event,
                _ = tokio::time::sleep_until(deadline) => {
                    eprintln!("\nDuration expired.");
                    break;
                }
            }
        } else {
            rx.recv().await
        };

        let Some(event) = event else { break };

        // PID filtering
        if filter_pid.is_some() {
            let dominated = match &event {
                ScrutEvent::ProcessExec { pid, ppid, .. } => {
                    if tracked_pids.contains(ppid) {
                        tracked_pids.insert(*pid);
                        true
                    } else {
                        tracked_pids.contains(pid)
                    }
                }
                ScrutEvent::ProcessFork { parent_pid, child_pid, .. } => {
                    if tracked_pids.contains(parent_pid) {
                        tracked_pids.insert(*child_pid);
                        true
                    } else {
                        false
                    }
                }
                ScrutEvent::ProcessExit { pid, .. } => tracked_pids.contains(pid),
            };

            if !dominated {
                continue;
            }
        }

        if json_output {
            if let Ok(json) = serde_json::to_string(&event) {
                println!("{}", json);
            }
        } else {
            print_event(&event);
        }
    }

    observer_handle.abort();
    Ok(())
}

fn print_event(event: &ScrutEvent) {
    match event {
        ScrutEvent::ProcessExec {
            pid,
            ppid,
            comm,
            filename,
            timestamp,
        } => {
            let time = timestamp.format("%H:%M:%S%.3f");
            println!(
                "\x1b[32m{}\x1b[0m  \x1b[1mEXEC\x1b[0m  pid={} ppid={} comm={} file={}",
                time, pid, ppid, comm, filename
            );
        }
        ScrutEvent::ProcessFork {
            parent_pid,
            child_pid,
            parent_comm,
            timestamp,
        } => {
            let time = timestamp.format("%H:%M:%S%.3f");
            println!(
                "\x1b[32m{}\x1b[0m  \x1b[36mFORK\x1b[0m  parent={} child={} comm={}",
                time, parent_pid, child_pid, parent_comm
            );
        }
        ScrutEvent::ProcessExit {
            pid,
            exit_code,
            comm,
            timestamp,
        } => {
            let time = timestamp.format("%H:%M:%S%.3f");
            let color = if *exit_code == 0 { "37" } else { "91" };
            println!(
                "\x1b[32m{}\x1b[0m  \x1b[{}mEXIT\x1b[0m  pid={} code={} comm={}",
                time, color, pid, exit_code, comm
            );
        }
    }
}
