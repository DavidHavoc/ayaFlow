# Stage 1: Build the eBPF kernel program (requires nightly + bpf-linker).
FROM rust:1.85 AS ebpf-builder

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
FROM rust:1.85 AS builder

WORKDIR /build
COPY . .
COPY --from=ebpf-builder /build/target/bpfel-unknown-none/release/ayaflow \
     /build/target/bpfel-unknown-none/debug/ayaflow

RUN cargo build --release -p ayaflow

# Stage 3: Minimal runtime image.
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ayaflow /usr/local/bin/ayaflow

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/ayaflow"]
