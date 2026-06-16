use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Show which parts of the workflow are supported on the current host.
    CheckHost,
    /// Build the eBPF program for bpfel-unknown-none.
    BuildEbpf {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
    },
    /// Build only the userspace crate for the current host.
    BuildUser {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
    },
    /// Build everything: eBPF first, then the userspace agent.
    Build {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
    },
    /// Build everything and run with sudo.
    Run {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
        /// Extra arguments passed to the binary.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::CheckHost => check_host(),
        Cli::BuildEbpf { release } => build_ebpf(release),
        Cli::BuildUser { release } => build_userspace(release),
        Cli::Build { release } => {
            build_ebpf(release)?;
            build_userspace(release)
        }
        Cli::Run { release, args } => {
            build_ebpf(release)?;
            build_userspace(release)?;
            run(release, &args)
        }
    }
}

fn check_host() -> anyhow::Result<()> {
    let host = std::env::consts::OS;
    if host == "linux" {
        println!("Host: linux");
        println!("Supported here: cargo test, cargo xtask build-user, cargo xtask build-ebpf, cargo xtask build, cargo xtask run");
    } else {
        println!("Host: {}", host);
        println!("Supported here: cargo test -p ayaflow-common, cargo test -p ayaflow, cargo xtask build-user");
        println!("Linux-only commands: cargo xtask build-ebpf, cargo xtask build, cargo xtask run");
    }
    Ok(())
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    ensure_linux("cargo xtask build-ebpf")?;
    let mut cmd = Command::new("cargo");
    cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../ayaflow-ebpf"));
    cmd.args([
        "+nightly",
        "build",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().context("failed to run cargo build for eBPF")?;
    anyhow::ensure!(status.success(), "eBPF build failed");
    Ok(())
}

fn build_userspace(release: bool) -> anyhow::Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "-p", "ayaflow"]);
    if release {
        cmd.arg("--release");
    }
    let status = cmd
        .status()
        .context("failed to run cargo build for workspace")?;
    anyhow::ensure!(status.success(), "workspace build failed");
    Ok(())
}

fn run(release: bool, extra_args: &[String]) -> anyhow::Result<()> {
    ensure_linux("cargo xtask run")?;
    let profile = if release { "release" } else { "debug" };
    let bin = format!("target/{profile}/ayaflow");

    let mut cmd = Command::new("sudo");
    cmd.arg(&bin);
    cmd.args(extra_args);
    let status = cmd.status().context("failed to run ayaflow")?;
    anyhow::ensure!(status.success(), "ayaflow exited with error");
    Ok(())
}

fn ensure_linux(command: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        std::env::consts::OS == "linux",
        "{command} is only supported on Linux. Run `cargo xtask check-host` for the supported host-safe workflow."
    );
    Ok(())
}
