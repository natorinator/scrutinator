# Scrutinator

eBPF-based system observation library and CLI for Linux. Scrutinator attaches
to kernel tracepoints to give you real-time visibility into what processes are
doing — without modifying the target programs.

## What it traces

- **Process lifecycle** — exec, fork, and exit events
- **File access** — open, delete, and rename operations (with writable/created flags)
- **Network activity** — TCP state changes, connect, and bind calls

Events are emitted as structured data (`ScrutEvent`) that you can consume
programmatically or stream as JSON from the CLI.

## Crates

| Crate | Description |
|---|---|
| `scrutinator` | Core library — loads eBPF programs, attaches probes, reads events |
| `scrutinator-common` | Shared types between userspace and eBPF programs |
| `scrutinator-cli` | CLI binary for interactive use |

## Quick start

```bash
cargo install scrutinator-cli

# Requires root or CAP_BPF + CAP_PERFMON
sudo scrutinator --trace process,file,network
```

### As a library

```rust
use scrutinator::Observer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut observer = Observer::new()?;
    observer.attach_process_tracing()?;
    observer.attach_file_tracing()?;
    observer.attach_network_tracing()?;

    observer.run_for(std::time::Duration::from_secs(10)).await?;
    Ok(())
}
```

## Building from source

Scrutinator uses [Aya](https://aya-rs.dev/) for eBPF. You need:

- Rust nightly (for the eBPF target)
- `bpf-linker`
- Linux kernel headers

```bash
cargo install bpf-linker
cargo build --release
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) for details.
