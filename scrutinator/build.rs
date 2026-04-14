use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ebpf_dir = manifest_dir.parent().unwrap().join("scrutinator-ebpf");

    // This is the path that observer.rs expects via include_bytes_aligned!
    let expected_binary = out_dir.join("scrutinator-ebpf/bpfel-unknown-none/release/scrutinator");

    // If the eBPF source tree exists (workspace development), build from source
    if ebpf_dir.join("Cargo.toml").exists() {
        println!("cargo:rerun-if-changed={}", ebpf_dir.display());
        build_ebpf_from_source(&ebpf_dir, &out_dir);
    } else {
        // crates.io install — use the pre-compiled binary
        let bundled = manifest_dir.join("bpf/scrutinator.bin");
        if !bundled.exists() {
            panic!(
                "No eBPF source tree and no pre-compiled binary found at {}",
                bundled.display()
            );
        }

        std::fs::create_dir_all(expected_binary.parent().unwrap()).unwrap();
        std::fs::copy(&bundled, &expected_binary).unwrap();
        println!("cargo:warning=Using pre-compiled eBPF binary from bpf/scrutinator.bin");
    }
}

fn build_ebpf_from_source(ebpf_dir: &PathBuf, out_dir: &PathBuf) {
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
