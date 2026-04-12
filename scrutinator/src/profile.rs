//! Behavior profile generation
//!
//! Aggregates raw ScrutEvents into a structured BehaviorProfile that
//! summarizes what a process (and its children) did during an observation
//! window. The profile can be serialized to JSON for consumption by
//! Gaol (policy generation) and Protectinator (anomaly detection).

use crate::events::ScrutEvent;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// Known sensitive file paths that warrant special attention
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/.ssh/",
    "/.gnupg/",
    "/.aws/",
    "/.config/gcloud/",
    "/.kube/config",
    "/.docker/config.json",
    "/etc/ssl/private/",
    "/.env",
    "/.netrc",
    "/.npmrc",
    "/.pypirc",
];

/// A structured summary of observed process behavior
#[derive(Debug, Clone, Serialize)]
pub struct BehaviorProfile {
    /// The primary PID observed
    pub pid: u32,

    /// Binary path (if captured from exec event)
    pub binary: Option<String>,

    /// Process name
    pub comm: String,

    /// Observation start time
    pub started_at: DateTime<Utc>,

    /// Observation end time
    pub ended_at: DateTime<Utc>,

    /// How long the observation lasted
    pub duration_secs: f64,

    /// Total events observed
    pub total_events: usize,

    /// Files read (deduplicated paths)
    pub files_read: Vec<String>,

    /// Files written (deduplicated paths)
    pub files_written: Vec<String>,

    /// Files created
    pub files_created: Vec<String>,

    /// Files deleted
    pub files_deleted: Vec<String>,

    /// Files renamed (old -> new)
    pub files_renamed: Vec<RenameEntry>,

    /// Sensitive files accessed (subset of reads/writes matching known sensitive paths)
    pub sensitive_access: Vec<SensitiveAccess>,

    /// Network connections made
    pub network_connections: Vec<ConnectionEntry>,

    /// Ports bound (listening)
    pub ports_bound: Vec<BindEntry>,

    /// Child processes spawned
    pub child_processes: Vec<ChildProcess>,

    /// Process tree: PID -> list of child PIDs
    pub process_tree: HashMap<u32, Vec<u32>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameEntry {
    pub old_path: String,
    pub new_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SensitiveAccess {
    pub path: String,
    pub access_type: String, // "read", "write", "create", "delete"
    pub comm: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionEntry {
    pub addr: String,
    pub port: u16,
    pub family: String,
    pub comm: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BindEntry {
    pub addr: String,
    pub port: u16,
    pub comm: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChildProcess {
    pub pid: u32,
    pub binary: String,
    pub comm: String,
}

/// Builds a BehaviorProfile from a stream of events
pub struct ProfileBuilder {
    pid: u32,
    comm: String,
    binary: Option<String>,
    started_at: Option<DateTime<Utc>>,
    ended_at: Option<DateTime<Utc>>,
    total_events: usize,

    // Tracked PIDs (the target PID and all descendants)
    tracked_pids: HashSet<u32>,

    // Deduplicated collections
    files_read: HashSet<String>,
    files_written: HashSet<String>,
    files_created: HashSet<String>,
    files_deleted: Vec<String>,
    files_renamed: Vec<RenameEntry>,
    sensitive_access: Vec<SensitiveAccess>,
    connections: Vec<ConnectionEntry>,
    // Deduplicate connections by (addr, port)
    seen_connections: HashSet<(String, u16)>,
    ports_bound: Vec<BindEntry>,
    seen_binds: HashSet<u16>,
    child_processes: Vec<ChildProcess>,
    process_tree: HashMap<u32, Vec<u32>>,
}

impl ProfileBuilder {
    /// Create a new profile builder for the given PID
    pub fn new(pid: u32) -> Self {
        let mut tracked = HashSet::new();
        tracked.insert(pid);

        Self {
            pid,
            comm: String::new(),
            binary: None,
            started_at: None,
            ended_at: None,
            total_events: 0,
            tracked_pids: tracked,
            files_read: HashSet::new(),
            files_written: HashSet::new(),
            files_created: HashSet::new(),
            files_deleted: Vec::new(),
            files_renamed: Vec::new(),
            sensitive_access: Vec::new(),
            connections: Vec::new(),
            seen_connections: HashSet::new(),
            ports_bound: Vec::new(),
            seen_binds: HashSet::new(),
            child_processes: Vec::new(),
            process_tree: HashMap::new(),
        }
    }

    /// Process a single event
    pub fn add_event(&mut self, event: &ScrutEvent) {
        let event_pid = event.pid();

        // Only track events from our PID or descendants
        if !self.tracked_pids.contains(&event_pid) {
            // Check if this is a fork from a tracked PID
            if let ScrutEvent::ProcessFork { parent_pid, child_pid, .. } = event {
                if self.tracked_pids.contains(parent_pid) {
                    self.tracked_pids.insert(*child_pid);
                } else {
                    return;
                }
            } else {
                return;
            }
        }

        // Update timestamps
        let ts = event.timestamp();
        if self.started_at.is_none() || ts < self.started_at.unwrap() {
            self.started_at = Some(ts);
        }
        if self.ended_at.is_none() || ts > self.ended_at.unwrap() {
            self.ended_at = Some(ts);
        }

        self.total_events += 1;

        match event {
            ScrutEvent::ProcessExec { pid, comm, filename, .. } => {
                if *pid == self.pid && self.comm.is_empty() {
                    self.comm = comm.clone();
                    if !filename.is_empty() {
                        self.binary = Some(filename.clone());
                    }
                } else if *pid != self.pid {
                    self.child_processes.push(ChildProcess {
                        pid: *pid,
                        binary: filename.clone(),
                        comm: comm.clone(),
                    });
                }
            }
            ScrutEvent::ProcessFork { parent_pid, child_pid, .. } => {
                self.tracked_pids.insert(*child_pid);
                self.process_tree
                    .entry(*parent_pid)
                    .or_default()
                    .push(*child_pid);
            }
            ScrutEvent::ProcessExit { .. } => {}
            ScrutEvent::FileOpen { pid, comm, path, writable, created, .. } => {
                if path.is_empty() {
                    return;
                }
                if *created {
                    self.files_created.insert(path.clone());
                    self.check_sensitive(path, "create", comm, *pid);
                } else if *writable {
                    self.files_written.insert(path.clone());
                    self.check_sensitive(path, "write", comm, *pid);
                } else {
                    self.files_read.insert(path.clone());
                    self.check_sensitive(path, "read", comm, *pid);
                }
            }
            ScrutEvent::FileDelete { pid, comm, path, .. } => {
                self.files_deleted.push(path.clone());
                self.check_sensitive(path, "delete", comm, *pid);
            }
            ScrutEvent::FileRename { old_path, new_path, .. } => {
                self.files_renamed.push(RenameEntry {
                    old_path: old_path.clone(),
                    new_path: new_path.clone(),
                });
            }
            ScrutEvent::NetConnect { addr, port, family, comm, .. } => {
                let key = (addr.clone(), *port);
                if !self.seen_connections.contains(&key) {
                    self.seen_connections.insert(key);
                    self.connections.push(ConnectionEntry {
                        addr: addr.clone(),
                        port: *port,
                        family: family.clone(),
                        comm: comm.clone(),
                    });
                }
            }
            ScrutEvent::NetStateChange { dst_addr, dst_port, new_state, family, comm, .. } => {
                // Only track new ESTABLISHED connections
                if new_state == "ESTABLISHED" {
                    let key = (dst_addr.clone(), *dst_port);
                    if !self.seen_connections.contains(&key) {
                        self.seen_connections.insert(key);
                        self.connections.push(ConnectionEntry {
                            addr: dst_addr.clone(),
                            port: *dst_port,
                            family: family.clone(),
                            comm: comm.clone(),
                        });
                    }
                }
            }
            ScrutEvent::NetBind { addr, port, comm, .. } => {
                if !self.seen_binds.contains(port) {
                    self.seen_binds.insert(*port);
                    self.ports_bound.push(BindEntry {
                        addr: addr.clone(),
                        port: *port,
                        comm: comm.clone(),
                    });
                }
            }
        }
    }

    /// Process multiple events
    pub fn add_events(&mut self, events: &[ScrutEvent]) {
        for event in events {
            self.add_event(event);
        }
    }

    /// Check if a path matches a known sensitive location
    fn check_sensitive(&mut self, path: &str, access_type: &str, comm: &str, pid: u32) {
        for sensitive in SENSITIVE_PATHS {
            if path.contains(sensitive) {
                self.sensitive_access.push(SensitiveAccess {
                    path: path.to_string(),
                    access_type: access_type.to_string(),
                    comm: comm.to_string(),
                    pid,
                });
                break;
            }
        }
    }

    /// Build the final profile
    pub fn build(self) -> BehaviorProfile {
        let now = Utc::now();
        let started = self.started_at.unwrap_or(now);
        let ended = self.ended_at.unwrap_or(now);
        let duration = (ended - started).num_milliseconds() as f64 / 1000.0;

        let mut files_read: Vec<String> = self.files_read.into_iter().collect();
        files_read.sort();
        let mut files_written: Vec<String> = self.files_written.into_iter().collect();
        files_written.sort();
        let mut files_created: Vec<String> = self.files_created.into_iter().collect();
        files_created.sort();

        BehaviorProfile {
            pid: self.pid,
            binary: self.binary,
            comm: self.comm,
            started_at: started,
            ended_at: ended,
            duration_secs: duration,
            total_events: self.total_events,
            files_read,
            files_written,
            files_created,
            files_deleted: self.files_deleted,
            files_renamed: self.files_renamed,
            sensitive_access: self.sensitive_access,
            network_connections: self.connections,
            ports_bound: self.ports_bound,
            child_processes: self.child_processes,
            process_tree: self.process_tree,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exec(pid: u32, comm: &str, filename: &str) -> ScrutEvent {
        ScrutEvent::ProcessExec {
            pid,
            ppid: 1,
            comm: comm.to_string(),
            filename: filename.to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_fork(parent: u32, child: u32) -> ScrutEvent {
        ScrutEvent::ProcessFork {
            parent_pid: parent,
            child_pid: child,
            parent_comm: "parent".to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_file_open(pid: u32, path: &str, writable: bool, created: bool) -> ScrutEvent {
        ScrutEvent::FileOpen {
            pid,
            comm: "test".to_string(),
            path: path.to_string(),
            flags: 0,
            writable,
            created,
            timestamp: Utc::now(),
        }
    }

    fn make_connect(pid: u32, addr: &str, port: u16) -> ScrutEvent {
        ScrutEvent::NetConnect {
            pid,
            comm: "test".to_string(),
            addr: addr.to_string(),
            port,
            family: "IPv4".to_string(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn basic_profile() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "curl", "/usr/bin/curl"));
        builder.add_event(&make_file_open(100, "/etc/hosts", false, false));
        builder.add_event(&make_connect(100, "93.184.216.34", 443));

        let profile = builder.build();
        assert_eq!(profile.pid, 100);
        assert_eq!(profile.comm, "curl");
        assert_eq!(profile.binary, Some("/usr/bin/curl".to_string()));
        assert_eq!(profile.files_read.len(), 1);
        assert_eq!(profile.network_connections.len(), 1);
        assert_eq!(profile.total_events, 3);
    }

    #[test]
    fn deduplicates_files() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "test", ""));
        builder.add_event(&make_file_open(100, "/etc/hosts", false, false));
        builder.add_event(&make_file_open(100, "/etc/hosts", false, false));
        builder.add_event(&make_file_open(100, "/etc/hosts", false, false));

        let profile = builder.build();
        assert_eq!(profile.files_read.len(), 1);
    }

    #[test]
    fn deduplicates_connections() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "test", ""));
        builder.add_event(&make_connect(100, "1.2.3.4", 80));
        builder.add_event(&make_connect(100, "1.2.3.4", 80));
        builder.add_event(&make_connect(100, "1.2.3.4", 443));

        let profile = builder.build();
        assert_eq!(profile.network_connections.len(), 2);
    }

    #[test]
    fn tracks_child_processes() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "bash", "/bin/bash"));
        builder.add_event(&make_fork(100, 101));
        builder.add_event(&make_exec(101, "ls", "/usr/bin/ls"));
        builder.add_event(&make_fork(100, 102));
        builder.add_event(&make_exec(102, "cat", "/usr/bin/cat"));

        let profile = builder.build();
        assert_eq!(profile.child_processes.len(), 2);
        assert_eq!(profile.process_tree.get(&100).unwrap().len(), 2);
    }

    #[test]
    fn filters_unrelated_pids() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "test", ""));
        builder.add_event(&make_file_open(100, "/etc/hosts", false, false));
        // Unrelated PID
        builder.add_event(&make_file_open(999, "/etc/shadow", false, false));

        let profile = builder.build();
        assert_eq!(profile.files_read.len(), 1);
        assert_eq!(profile.total_events, 2);
    }

    #[test]
    fn tracks_descendants() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "bash", ""));
        builder.add_event(&make_fork(100, 200));
        // Child's file access should be tracked
        builder.add_event(&make_file_open(200, "/tmp/child.txt", true, false));
        // Grandchild
        builder.add_event(&make_fork(200, 300));
        builder.add_event(&make_file_open(300, "/tmp/grandchild.txt", true, false));

        let profile = builder.build();
        assert_eq!(profile.files_written.len(), 2);
    }

    #[test]
    fn detects_sensitive_access() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "evil", ""));
        builder.add_event(&make_file_open(100, "/home/user/.ssh/id_rsa", false, false));
        builder.add_event(&make_file_open(100, "/etc/shadow", false, false));
        builder.add_event(&make_file_open(100, "/tmp/harmless.txt", false, false));

        let profile = builder.build();
        assert_eq!(profile.sensitive_access.len(), 2);
        assert_eq!(profile.files_read.len(), 3);
    }

    #[test]
    fn separates_read_write_create() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "test", ""));
        builder.add_event(&make_file_open(100, "/tmp/read.txt", false, false));
        builder.add_event(&make_file_open(100, "/tmp/write.txt", true, false));
        builder.add_event(&make_file_open(100, "/tmp/new.txt", true, true));

        let profile = builder.build();
        assert_eq!(profile.files_read.len(), 1);
        assert_eq!(profile.files_written.len(), 1);
        assert_eq!(profile.files_created.len(), 1);
    }

    #[test]
    fn profile_serializes_to_json() {
        let mut builder = ProfileBuilder::new(42);
        builder.add_event(&make_exec(42, "npm", "/usr/bin/npm"));
        builder.add_event(&make_file_open(42, "/home/user/.npmrc", false, false));
        builder.add_event(&make_connect(42, "104.16.0.1", 443));

        let profile = builder.build();
        let json = serde_json::to_string_pretty(&profile).unwrap();
        assert!(json.contains("\"pid\": 42"), "json was: {}", json);
        assert!(json.contains(".npmrc"));
        assert!(json.contains("104.16.0.1"));
    }

    #[test]
    fn bind_deduplication() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "nginx", ""));
        builder.add_event(&ScrutEvent::NetBind {
            pid: 100,
            comm: "nginx".to_string(),
            addr: "0.0.0.0".to_string(),
            port: 80,
            timestamp: Utc::now(),
        });
        builder.add_event(&ScrutEvent::NetBind {
            pid: 100,
            comm: "nginx".to_string(),
            addr: "0.0.0.0".to_string(),
            port: 80,
            timestamp: Utc::now(),
        });

        let profile = builder.build();
        assert_eq!(profile.ports_bound.len(), 1);
    }

    #[test]
    fn delete_and_rename_tracked() {
        let mut builder = ProfileBuilder::new(100);
        builder.add_event(&make_exec(100, "test", ""));
        builder.add_event(&ScrutEvent::FileDelete {
            pid: 100,
            comm: "test".to_string(),
            path: "/tmp/old.txt".to_string(),
            timestamp: Utc::now(),
        });
        builder.add_event(&ScrutEvent::FileRename {
            pid: 100,
            comm: "test".to_string(),
            old_path: "/tmp/a.txt".to_string(),
            new_path: "/tmp/b.txt".to_string(),
            timestamp: Utc::now(),
        });

        let profile = builder.build();
        assert_eq!(profile.files_deleted.len(), 1);
        assert_eq!(profile.files_renamed.len(), 1);
    }
}
