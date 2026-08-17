# =============================================================================
# Spryzen+ (IronWall WAF) — Production Benchmark Container
# Multi-stage automated Rust builder for 100% reproducible cross-platform benchmarking
# =============================================================================

# --- STAGE 1: Fast Musl Rust Compiler ---
FROM rust:1-alpine as builder

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY Cargo.toml ./
COPY src/ ./src/

# Compile with maximum release optimizations (LTO, fat, codegen-units=1)
RUN cargo build --release

# --- STAGE 2: Minimal Distroless / Alpine Runtime ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates libgcc tzdata

# Security: Run as non-root user
RUN addgroup -S spryzen && adduser -S spryzen -G spryzen

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder --chmod=755 /app/target/release/spryzen-engine /app/spryzen-engine

# Switch to unprivileged benchmark user
USER spryzen

EXPOSE 8081

ENV RUST_LOG=info
ENV BIND_ADDR=0.0.0.0:8081
ENV PORT=8081

ENTRYPOINT ["/app/spryzen-engine"]
