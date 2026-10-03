# =============================================================================
# Spryzen+ (IronWall WAF) — Production Edge & Reverse Proxy WAF Container
# Ultra-compact, sub-microsecond Rust Alpine multi-stage build (<20MB)
# =============================================================================

# --- STAGE 1: Fast Musl Rust Compiler ---
FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY Cargo.toml ./
COPY src/ ./src/

# Compile with maximum release optimizations (LTO, fat, codegen-units=1)
RUN cargo build --release

# --- STAGE 2: Minimal Alpine Runtime ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates libgcc tzdata curl

# Security: Run as non-root user
RUN addgroup -S spryzen && adduser -S spryzen -G spryzen

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder --chmod=755 /app/target/release/spryzen-engine /app/spryzen-engine

# Switch to unprivileged benchmark user
USER spryzen

EXPOSE 8080 8081

ENV RUST_LOG=info
ENV PORT=8080
ENV UPSTREAM_URL=""

HEALTHCHECK --interval=10s --timeout=3s --start-period=2s --retries=3 \
  CMD curl -f http://127.0.0.1:${PORT:-8080}/health || exit 1

ENTRYPOINT ["/app/spryzen-engine"]
