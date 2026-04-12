//! Scrutinator — eBPF System Observation Library
//!
//! Provides kernel-level visibility into process behavior using eBPF:
//! - Process execution, forking, and exit tracing
//! - File access monitoring (open, read, write, delete)
//! - Network connection tracking (TCP, UDP, DNS)
//!
//! # Example
//!
//! ```no_run
//! use scrutinator::Observer;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let mut observer = Observer::new()?;
//!     observer.attach_process_tracing()?;
//!
//!     // Process events for 10 seconds
//!     observer.run_for(std::time::Duration::from_secs(10)).await?;
//!     Ok(())
//! }
//! ```

pub mod events;
pub mod observer;

pub use events::ScrutEvent;
pub use observer::Observer;
