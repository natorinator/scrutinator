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
    /// Profile a process — observe and produce a behavior summary
    ///
    /// Watches a PID (and its children) for a duration, then outputs
    /// a structured behavior profile showing all files accessed,
    /// network connections made, and child processes spawned.
    Profile {
        /// PID to profile
        #[arg(long)]
        pid: u32,

        /// Observation duration in seconds (default: 30)
        #[arg(long, default_value_t = 30)]
        duration: u64,

        /// Output format: json (default) or text
        #[arg(long, default_value = "json")]
        format: String,
    },

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

        /// Also trace file access (open, delete, rename)
        #[arg(long)]
        files: bool,

        /// Also trace network activity (connect, bind, TCP state)
        #[arg(long)]
        network: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Profile { pid, duration, format } => {
            run_profile(pid, duration, &format).await
        }
        Commands::Watch { pid, duration, json, files, network } => {
            run_watch(pid, duration, json, files, network).await
        }
    }
}

async fn run_watch(
    filter_pid: Option<u32>,
    duration_secs: Option<u64>,
    json_output: bool,
    trace_files: bool,
    trace_network: bool,
) -> anyhow::Result<()> {
    eprintln!("Loading eBPF programs...");

    let mut observer = scrutinator::Observer::new()?;
    observer.attach_process_tracing()?;

    if trace_files {
        observer.attach_file_tracing()?;
        eprintln!("File tracing enabled (open, delete, rename)");
    }

    if trace_network {
        observer.attach_network_tracing()?;
        eprintln!("Network tracing enabled (connect, bind, TCP state)");
    }

    eprintln!("Watching events (Ctrl-C to stop)...");
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
                ScrutEvent::FileOpen { pid, .. }
                | ScrutEvent::FileDelete { pid, .. }
                | ScrutEvent::FileRename { pid, .. }
                | ScrutEvent::NetStateChange { pid, .. }
                | ScrutEvent::NetConnect { pid, .. }
                | ScrutEvent::NetBind { pid, .. } => tracked_pids.contains(pid),
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

async fn run_profile(pid: u32, duration_secs: u64, format: &str) -> anyhow::Result<()> {
    eprintln!("Loading eBPF programs...");

    let mut observer = scrutinator::Observer::new()?;
    observer.attach_process_tracing()?;
    observer.attach_file_tracing()?;
    observer.attach_network_tracing()?;

    eprintln!(
        "Profiling PID {} for {} seconds (all tracers active)...",
        pid, duration_secs
    );

    let (tx, mut rx) = mpsc::channel::<ScrutEvent>(8192);
    let mut profile_builder = scrutinator::ProfileBuilder::new(pid);

    // Spawn observer
    let observer_handle = tokio::spawn(async move {
        if let Err(e) = observer.run(tx).await {
            eprintln!("Observer error: {}", e);
        }
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(duration_secs);

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(e) => profile_builder.add_event(&e),
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                eprintln!("Observation complete.");
                break;
            }
        }
    }

    observer_handle.abort();

    let profile = profile_builder.build();

    match format {
        "text" => print_profile_text(&profile),
        _ => {
            println!("{}", serde_json::to_string_pretty(&profile)?);
        }
    }

    Ok(())
}

fn print_profile_text(profile: &scrutinator::BehaviorProfile) {
    println!("\n\x1b[1mBehavior Profile\x1b[0m");
    println!("═══════════════════════════════════════");
    println!("  PID:      {}", profile.pid);
    println!("  Binary:   {}", profile.binary.as_deref().unwrap_or("(unknown)"));
    println!("  Comm:     {}", profile.comm);
    println!("  Duration: {:.1}s", profile.duration_secs);
    println!("  Events:   {}", profile.total_events);

    if !profile.files_read.is_empty() {
        println!("\n\x1b[1mFiles Read\x1b[0m ({})", profile.files_read.len());
        for f in &profile.files_read {
            println!("  {}", f);
        }
    }

    if !profile.files_written.is_empty() {
        println!("\n\x1b[1mFiles Written\x1b[0m ({})", profile.files_written.len());
        for f in &profile.files_written {
            println!("  \x1b[33m{}\x1b[0m", f);
        }
    }

    if !profile.files_created.is_empty() {
        println!("\n\x1b[1mFiles Created\x1b[0m ({})", profile.files_created.len());
        for f in &profile.files_created {
            println!("  \x1b[32m{}\x1b[0m", f);
        }
    }

    if !profile.files_deleted.is_empty() {
        println!("\n\x1b[1mFiles Deleted\x1b[0m ({})", profile.files_deleted.len());
        for f in &profile.files_deleted {
            println!("  \x1b[91m{}\x1b[0m", f);
        }
    }

    if !profile.sensitive_access.is_empty() {
        println!("\n\x1b[91;1mSensitive Access\x1b[0m ({})", profile.sensitive_access.len());
        for s in &profile.sensitive_access {
            println!("  \x1b[91m{}\x1b[0m ({}) by {} [pid={}]", s.path, s.access_type, s.comm, s.pid);
        }
    }

    if !profile.network_connections.is_empty() {
        println!("\n\x1b[1mNetwork Connections\x1b[0m ({})", profile.network_connections.len());
        for c in &profile.network_connections {
            println!("  {}:{} ({}) by {}", c.addr, c.port, c.family, c.comm);
        }
    }

    if !profile.ports_bound.is_empty() {
        println!("\n\x1b[1mPorts Bound\x1b[0m ({})", profile.ports_bound.len());
        for b in &profile.ports_bound {
            println!("  {}:{} by {}", b.addr, b.port, b.comm);
        }
    }

    if !profile.child_processes.is_empty() {
        println!("\n\x1b[1mChild Processes\x1b[0m ({})", profile.child_processes.len());
        for c in &profile.child_processes {
            println!("  pid={} {} ({})", c.pid, c.binary, c.comm);
        }
    }

    println!();
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
        ScrutEvent::FileOpen {
            pid,
            comm,
            path,
            writable,
            created,
            timestamp,
            ..
        } => {
            let time = timestamp.format("%H:%M:%S%.3f");
            let mode = if *created {
                "CREATE"
            } else if *writable {
                "WRITE"
            } else {
                "READ"
            };
            let color = if *writable || *created { "33" } else { "37" };
            println!(
                "\x1b[32m{}\x1b[0m  \x1b[{}mOPEN\x1b[0m   pid={} mode={} comm={} path={}",
                time, color, pid, mode, comm, path
            );
        }
        ScrutEvent::FileDelete {
            pid,
            comm,
            path,
            timestamp,
        } => {
            let time = timestamp.format("%H:%M:%S%.3f");
            println!(
                "\x1b[32m{}\x1b[0m  \x1b[91mDEL\x1b[0m    pid={} comm={} path={}",
                time, pid, comm, path
            );
        }
        ScrutEvent::FileRename {
            pid,
            comm,
            old_path,
            new_path,
            timestamp,
        } => {
            let time = timestamp.format("%H:%M:%S%.3f");
            println!(
                "\x1b[32m{}\x1b[0m  \x1b[33mRENAME\x1b[0m pid={} comm={} {} -> {}",
                time, pid, comm, old_path, new_path
            );
        }
        ScrutEvent::NetStateChange {
            pid,
            comm,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            old_state,
            new_state,
            family,
            timestamp,
        } => {
            let time = timestamp.format("%H:%M:%S%.3f");
            let color = match new_state.as_str() {
                "ESTABLISHED" => "32",
                "CLOSE" | "TIME_WAIT" => "37",
                "SYN_SENT" => "33",
                _ => "36",
            };
            println!(
                "\x1b[32m{}\x1b[0m  \x1b[{}mTCP\x1b[0m    pid={} comm={} {}:{} -> {}:{} {} [{}->{}]",
                time, color, pid, comm, src_addr, src_port, dst_addr, dst_port,
                family, old_state, new_state
            );
        }
        ScrutEvent::NetConnect {
            pid,
            comm,
            addr,
            port,
            family,
            timestamp,
        } => {
            let time = timestamp.format("%H:%M:%S%.3f");
            println!(
                "\x1b[32m{}\x1b[0m  \x1b[35mCONN\x1b[0m   pid={} comm={} -> {}:{} ({})",
                time, pid, comm, addr, port, family
            );
        }
        ScrutEvent::NetBind {
            pid,
            comm,
            addr,
            port,
            timestamp,
        } => {
            let time = timestamp.format("%H:%M:%S%.3f");
            println!(
                "\x1b[32m{}\x1b[0m  \x1b[34mBIND\x1b[0m   pid={} comm={} {}:{}",
                time, pid, comm, addr, port
            );
        }
    }
}
