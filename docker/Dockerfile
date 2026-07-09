# --- STAGE 1: Der Builder ---
FROM rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY .sqlx/ ./.sqlx/
COPY migrations/ ./migrations/

ENV SQLX_OFFLINE=true
RUN cargo build --release -p vauxl-server

# --- STAGE 2: Das winzige Runtime-Image ---
FROM debian:bookworm-slim

# Installiere Zertifikate für HTTPS/Föderation und OpenSSL
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Hole NUR das fertige Binary aus Stage 1
COPY --from=builder /build/target/release/vauxl-server ./
COPY config/ ./config/

CMD ["./vauxl-server"]
