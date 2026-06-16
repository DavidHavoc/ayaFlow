#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ayaflow::runtime_linux::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "ayaFlow's packet capture runtime only runs on Linux. Use `cargo test -p ayaflow`, \
`cargo test -p ayaflow-common`, or `cargo xtask check-host` on this host, and run `cargo xtask build` on Linux."
    );
    std::process::exit(1);
}
