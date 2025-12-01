# Build stage
FROM rust:1.88.0-bookworm AS init

RUN apt-get -qq update && \
  apt-get install -y -q clang cmake

SHELL ["/bin/bash", "-c"]

ARG CACHE_DATE=2025-12-01  # update this date to force rebuild

ENV RISC0_SKIP_BUILD=1

FROM init AS builder

COPY Cargo.toml .
COPY Cargo.lock .
COPY rust-toolchain.toml .
COPY crates/ ./crates/
COPY cli/ ./cli/
COPY zkvm/ ./zkvm/

SHELL ["/bin/bash", "-c"]

RUN cargo build --release

FROM init AS runtime

COPY --from=builder /target/release/cli /app/cli

ENTRYPOINT ["/app/cli"]
