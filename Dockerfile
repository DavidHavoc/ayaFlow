# Stage 1: Build the eBPF kernel program (requires nightly + bpf-linker).
FROM --platform=$BUILDPLATFORM rust:1.85.1 AS ebpf-builder

# bpf-linker >= 0.13 no longer builds via `cargo install` without a system
# LLVM, so install the upstream prebuilt static binary instead. The version and
# checksums are pinned; update all three together.
ARG BPF_LINKER_VERSION=v0.13.0
ARG BPF_LINKER_SHA256_X86_64=0e9b2b30f68898177f1cb6f0ecbfa909a82479473a49a0ef66529fd088e3e410
ARG BPF_LINKER_SHA256_AARCH64=248e25f5c6a7242b054bd8f705470abb7a5a79b2b7c07df347c5d7049b783452

RUN apt-get update && \
    apt-get install -y --no-install-recommends zstd && \
    rm -rf /var/lib/apt/lists/* && \
    arch="$(uname -m)" && \
    case "$arch" in \
      x86_64) sha="$BPF_LINKER_SHA256_X86_64" ;; \
      aarch64) sha="$BPF_LINKER_SHA256_AARCH64" ;; \
      *) echo "unsupported build arch: $arch" >&2; exit 1 ;; \
    esac && \
    tarball="bpf-linker-${arch}-unknown-linux-musl.tar.zst" && \
    curl -fsSLo "/tmp/$tarball" \
      "https://github.com/aya-rs/bpf-linker/releases/download/${BPF_LINKER_VERSION}/${tarball}" && \
    echo "$sha  /tmp/$tarball" | sha256sum -c - && \
    tar --zstd -xf "/tmp/$tarball" -C /usr/local/bin bpf-linker && \
    rm "/tmp/$tarball" && \
    bpf-linker --version

RUN rustup install nightly && \
    rustup component add rust-src --toolchain nightly

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

# Apply pending Debian security updates, install only runtime deps, and drop
# the apt lists so no package metadata remains in the image.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ayaflow /usr/local/bin/ayaflow

# The container runs as root on purpose. Attaching the eBPF TC classifier needs
# the BPF, NET_ADMIN, and PERFMON capabilities, granted at `docker run` time via
# `--privileged` or `--cap-add` (see HOW_TO_USE_DOCKER.md). A non-root USER
# would not get those capabilities in its effective set on the `--cap-add` path.

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/ayaflow"]
