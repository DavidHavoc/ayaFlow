# Stage 1: Build the eBPF kernel program (requires nightly + bpf-linker).
FROM --platform=$BUILDPLATFORM rust:1.85.1 AS ebpf-builder

RUN rustup install nightly && \
    rustup component add rust-src --toolchain nightly && \
    cargo +nightly install bpf-linker

WORKDIR /build
COPY . .
RUN cd ayaflow-ebpf && \
    cargo +nightly build \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

# Stage 2: Build the userspace agent.
FROM rust:1.85.1 AS builder

WORKDIR /build
COPY . .
COPY --from=ebpf-builder /build/ayaflow-ebpf/target/bpfel-unknown-none/release/ayaflow \
    /build/ayaflow-ebpf/target/bpfel-unknown-none/debug/ayaflow

RUN cargo build --release -p ayaflow

# Stage 3: Minimal runtime image.
FROM debian:bookworm-slim

# Apply available OS security updates and install only runtime deps, then
# drop the apt cache so no package metadata or installers remain in the image.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ayaflow /usr/local/bin/ayaflow

# NOTE: the container intentionally runs as root. Loading and attaching the
# eBPF TC classifier requires the BPF, NET_ADMIN, and PERFMON capabilities,
# which the host grants via `--privileged` or `--cap-add` at `docker run` time
# (see HOW_TO_USE_DOCKER.md). A non-root USER would not receive those caps in
# its effective set under the documented `--cap-add` run path, so switching
# users here would break the supported deployment model. Scanner findings for
# OS package CVEs are addressed by the `apt-get upgrade` above; capability
# scoping is handled at runtime, not by dropping the image user.

EXPOSE 3000

# Liveness probe against the built-in health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:3000/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/ayaflow"]
