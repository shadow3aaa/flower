use std::{env, fs, path::Path, process::Command};

use anyhow::{Ok, Result};

fn main() -> Result<()> {
    install_ebpf_linker()?;
    build_ebpf()?;
    Ok(())
}

fn add_path<S: AsRef<str>>(add: S) -> Result<String> {
    let path = env::var("PATH")?;
    Ok(format!("{path}:{}", add.as_ref()))
}

fn install_ebpf_linker() -> Result<()> {
    let out_dir = env::var("OUT_DIR")?;
    let out_dir = Path::new(&out_dir);
    let target_dir = out_dir.join("temp_target");
    let target_dir_str = target_dir.to_str().unwrap();

    Command::new("cargo")
        .args([
            "install",
            "bpf-linker",
            "--force",
            "--root",
            target_dir_str,
            "--target-dir",
            target_dir_str,
        ])
        .status()?;

    Ok(())
}

fn build_ebpf() -> Result<()> {
    let current_dir = env::current_dir()?;
    let project_path = current_dir.parent().unwrap().join("flower-ebpf");
    let out_dir = env::var("OUT_DIR")?;
    let out_dir = Path::new(&out_dir);
    let target_dir = out_dir.join("ebpf_target");
    let target_dir_str = target_dir.to_str().unwrap();
    let bin = out_dir.join("temp_target").join("bin");
    let bin = bin.to_str().unwrap();

    if !target_dir.exists() {
        fs::create_dir(&target_dir)?;
    }

    let mut ebpf_args = vec![
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--target-dir",
        target_dir_str,
    ];

    if project_path.exists() {
        println!("cargo:rerun-if-changed=../flower-ebpf");

        #[cfg(not(debug_assertions))]
        ebpf_args.push("--release");

        Command::new("cargo")
            .arg("build")
            .args(ebpf_args)
            .env_remove("RUSTUP_TOOLCHAIN")
            .current_dir(&project_path)
            .env("PATH", add_path(bin)?)
            .status()?;
    } else {
        #[cfg(debug_assertions)]
        ebpf_args.push("--debug");

        let _ = fs::remove_dir_all(target_dir.join("bin")); // clean up
        Command::new("cargo")
            .args(["install", "flower-ebpf"])
            .args(ebpf_args)
            .args(["--root", target_dir_str])
            .env_remove("RUSTUP_TOOLCHAIN")
            .env("PATH", add_path(bin)?)
            .status()?;

        #[cfg(debug_assertions)]
        let prefix_dir = &target_dir.join("bpfel-unknown-none").join("debug");

        #[cfg(not(debug_assertions))]
        let prefix_dir = &target_dir.join("bpfel-unknown-none").join("release");

        let _ = fs::create_dir_all(prefix_dir);
        let to = &prefix_dir.join("flower-ebpf");
        fs::rename(target_dir.join("bin").join("flower-ebpf"), to)?;
    }

    Ok(())
}
