# =============================================================================
# Spryzen+ (IronWall WAF) — Production Benchmark Container
# Minimal Distroless / Alpine Runtime (Zero Source Code Exposed)
# =============================================================================

FROM alpine:3.20

# Install minimal runtime dependencies (ca-certificates, musl, libgcc)
RUN apk add --no-cache ca-certificates libgcc tzdata

# Security: Run as non-root user
RUN addgroup -S spryzen && adduser -S spryzen -G spryzen

WORKDIR /app

# Copy the pre-compiled, stripped release binary
COPY --chmod=755 Spryzen-engine /app/Spryzen-engine

# Switch to unprivileged benchmark user
USER spryzen

# Expose HTTP & HTTPS inspection ports
EXPOSE 8080 8081 443

# Environment configurations for high-throughput socket polling
ENV RUST_LOG=info
ENV BIND_ADDR=0.0.0.0:8081
ENV PORT=8081

ENTRYPOINT ["/app/Spryzen-engine"]
