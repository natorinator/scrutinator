use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_dir = manifest_dir.parent().unwrap().join("scrutinator-ebpf");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed={}", ebpf_dir.display());

    // Build eBPF programs using nightly toolchain
    let target_dir = out_dir.join("scrutinator-ebpf");

    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--manifest-path",
            &ebpf_dir.join("Cargo.toml").to_string_lossy(),
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--release",
            "--target-dir",
            &target_dir.to_string_lossy(),
        ])
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            "--cfg=bpf_target_arch=\"x86_64\"\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf",
        )
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=eBPF programs built successfully");
        }
        Ok(s) => {
            panic!(
                "Failed to build eBPF programs (exit code: {:?}). \
                 Make sure you have: nightly Rust, bpf-linker, rust-src component",
                s.code()
            );
        }
        Err(e) => {
            panic!("Failed to run rustup: {}", e);
        }
    }
}
