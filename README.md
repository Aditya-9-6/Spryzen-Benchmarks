# ⚡ Spryzen Single-Core & Sovereign Edge Benchmarks

[![eBPF / XDP](https://img.shields.io/badge/eBPF%2FXDP-6.92M_PPS-orange?style=for-the-badge&logo=linux)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)
[![Sustained Throughput](https://img.shields.io/badge/Cluster_Throughput-4.83M_RPS-blue?style=for-the-badge&logo=rust)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)
[![Throughput](https://img.shields.io/badge/Single--Core_Throughput-240%2C000%2B_req%2Fsec-00f2ff?style=for-the-badge&logo=rust)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)
[![P50 Latency](https://img.shields.io/badge/p50_Latency-12%C2%B5s-3b82f6?style=for-the-badge)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)
[![P99 Latency](https://img.shields.io/badge/p99_Latency-95%C2%B5s-10b981?style=for-the-badge)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)
[![OWASP CRS](https://img.shields.io/badge/OWASP_CRS-100%25_Blocked-success?style=for-the-badge)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)
[![RAM](https://img.shields.io/badge/Memory_Footprint-18MB_RSS-a855f7?style=for-the-badge)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)

Official reproducible benchmark suite, penetration evaluation, and microsecond architectural implementation for the **Spryzen Bare-Metal WAF & Edge Security Engine**.

> ⚠️ **Reproducibility scope:** performance and latency are highly environment-dependent (CPU model, core count, OS/kernel, runner load, virtualization, and loopback/network path). Treat fixed throughput/latency numbers in this README as **historical examples** unless they are listed under the "Latest local/CI verification" section below.

> **Systems design target:** up to multi-million PPS/RPS under prior benchmark environments. Current-run reproducible outputs are documented in the verification section below.

---

## 📊 Summary of Benchmark Results

Historical benchmark snapshot from a previous dedicated environment (`c6i.large` / AMD EPYC 7R13, Ubuntu 22.04 LTS, keep-alive over loopback). This table is not a guarantee for all systems.

```
+---------------------------------------------------------------------------------------------------+
|                              SINGLE-CORE HEAD-TO-HEAD BENCHMARK                                   |
+--------------------------+-----------------------+-----------------------+------------------------+
| Engine                   | Throughput (Req/Sec)  | p99 Latency (Active)  | Resident RAM (RSS)     |
+--------------------------+-----------------------+-----------------------+------------------------+
| ⚡ Spryzen (WAF Active)   | 185,000+ req/s        | 95 µs (0.095 ms)      | 18 MB                  |
| ⚡ Spryzen (Clean Path)   | 240,000+ req/s        | 12 µs (0.012 ms)      | 18 MB                  |
| 🔹 Nginx + ModSecurity   | 14,200 req/s          | 7,120 µs (7.12 ms)    | 142 MB                 |
| 🔸 Node.js / Express WAF | 8,900 req/s           | 11,400 µs (11.40 ms)  | 195 MB                 |
| ☁️ Cloudflare Edge (CDN) | ~45,000 req/s (edge)  | 18,500 µs (18.50 ms)  | N/A (Cloud Managed)    |
+--------------------------+-----------------------+-----------------------+------------------------+
```

---

## 🐳 1-Line Drop-In Docker Deployment

Spryzen can be deployed directly in front of any existing backend (FastAPI, Node.js, Go, Rails, Spring Boot, Django) in **30 seconds**. Zero code changes required:

### Option A: Inline Reverse Proxy WAF (Shield Any Backend)
```bash
docker run -d \
  --name spryzen-waf \
  -p 8080:8080 \
  -e UPSTREAM_URL=http://host.docker.internal:3000 \
  ghcr.io/aditya-9-6/spryzen:latest
```
* **Traffic Flow:** `Client` ➔ `Spryzen (:8080)` *(12µs AVX2 SIMD inspection)* ➔ `Upstream Backend (:3000)`.
* **Sub-Microsecond Latency:** Zero-allocation stream parsing and in-place percent-decode normalization.
* **Instant Defense:** Rejects SQLi, XSS, RCE, Path Traversal, and SSRF attacks with `403 Forbidden` and verdict telemetry headers (`x-spryzen-verdict: BLOCKED`, `x-spryzen-threat`).

### Option B: Standalone Benchmark & Evaluation Mode
```bash
docker run -d -p 8081:8081 -e PORT=8081 ghcr.io/aditya-9-6/spryzen:latest
```

### Option C: Docker Compose
```yaml
version: '3.8'

services:
  spryzen:
    image: ghcr.io/aditya-9-6/spryzen:latest
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - UPSTREAM_URL=http://my-backend:3000
      - SPRYZEN_MODE=block # or "simulate" for zero-risk onboarding
    depends_on:
      - my-backend

  my-backend:
    image: my-app:latest
    expose:
      - "3000"
```

---

## 🏢 Enterprise-Grade Architecture & Capabilities

Spryzen is engineered as a cloud-native, zero-downtime API Security Gateway:

### 1. Zero-Risk Onboarding: `block` vs `simulate` Mode
* **`SPRYZEN_MODE=simulate` (Audit & Monitor Mode):** Runs full AVX2 SIMD deep-packet scanning, emits real-time SIEM audit logs and tags `x-spryzen-simulated-verdict: WOULD_BLOCK` headers, but **forwards traffic cleanly to the backend**. Enables enterprise teams to benchmark false-positive rates on production traffic with **0% risk of service disruption**.
* **`SPRYZEN_MODE=block` (Active Defense):** Autonomous line-rate mitigation with `403 Forbidden`.

### 2. In-Memory Token-Bucket Rate Limiter
* Tracks client IPs with lock-free atomic counters.
* Protects origins from brute-force spikes and L7 credential stuffing.
* Returns RFC 6585 compliant `429 Too Many Requests` with `Retry-After: 1` and `x-spryzen-verdict: RATE_LIMITED`.

### 3. Declarative Configuration (`spryzen.toml`)
```toml
[server]
listen = "0.0.0.0:8080"
upstream = "http://backend:3000"
mode = "block" # "block" | "simulate" | "bypass"
timeout_ms = 10000
max_body_bytes = 10485760 # 10 MB DoS protection

[rate_limit]
enabled = true
requests_per_second = 1000
burst = 2000

[allowlist]
paths = ["/health", "/metrics", "/api/v1/webhooks/*"]
ips = ["127.0.0.1", "10.0.0.0/8"]

[logging]
format = "json" # Structured NDJSON for Datadog / Splunk / Elastic
mask_headers = ["authorization", "cookie", "x-api-key"] # PCI-DSS / SOC 2 compliance
```

### 4. Structured SIEM JSON Audit Logging
Emits machine-readable NDJSON telemetry with sensitive header redaction:
```json
{"timestamp":1791054900,"client_ip":"198.51.100.24","method":"POST","path":"/api/login","status":403,"verdict":"BLOCKED","threat":"SQL Injection","mode":"block","latency_us":14}
```

### 5. Kubernetes Sidecar Pattern (`k8s/spryzen-sidecar.yaml`)
Drops transparently into any existing Kubernetes pod alongside your application container over `localhost`:
```bash
kubectl apply -f k8s/spryzen-sidecar.yaml
```

---

Spryzen is continuously validated across industry-standard penetration tools and attack vector suites (table below is project-level/historical context; see latest local verification for this run):

| Audit Suite / Tool | Test Description | Target Invariant | Result |
|---|---|---|:---:|
| **OWASP Core Rule Set (CRS)** | 100+ SQLi, XSS, RCE, LFI, SSTI, and SSRF attack payloads | 100% Block Rate (`403 Forbidden`) | **PASSED (100%)** |
| **Clean Request Suite** | Legitimate API endpoints, queries, and form POSTs | 0% False Positive Rate (`200 OK`) | **PASSED (0.00% FP)** |
| **`sqlmap` Penetration** | Automated SQL injection scanner with blind/union/stacked tests | All parameters uninjectable | **DEFENDED** |
| **`wafw00f` Fingerprint** | Automated firewall detection suite | Recognized as active protective WAF | **IDENTIFIED** |
| **`nikto` Scanner** | Web server vulnerability & configuration scanner | Zero server leakages, headers suppressed | **PASSED** |
| **Extreme HTTP Fuzzer** | 10,000+ mutated, truncated, null-byte & non-UTF8 packets | Zero crashes, zero memory leaks | **0 CRASHES** |

---

## 🔬 Historical Nanosecond & Microsecond Hardware Telemetry

### 1. Pure CPU Zero-Allocation Microbenchmark (1,000,000 Requests)
Executed via `cargo test --release -- test_microsecond_inspection_benchmark --nocapture`:

| Operation | CPU Execution Time | Throughput per CPU Core | Heap Allocations |
| :--- | :--- | :--- | :--- |
| **Clean Path (L1 Cache Hit)** | **14.01 ns** *(0.014 µs)* | **71.38 Million ops/sec** | **0 bytes** (Zero-Alloc) |
| **Clean Path (LUT + SIMD Scan)** | **185.00 ns** *(0.185 µs)* | **5.40 Million ops/sec** | **0 bytes** (Zero-Alloc) |
| **Attack Detection (Deep Scan)** | **8.05 ns** *(0.008 µs)* | **124.20 Million ops/sec** | **0 bytes** (Zero-Alloc) |

> **Note:** 1,000,000 real-world request inspections were evaluated in **0.02 seconds** with zero heap allocations.

### 2. High-Concurrency Network Load Benchmark (k6 Telemetry)
Executed with 500 concurrent Virtual Users over 30 seconds (**378,328 total requests**, 0.0000% error rate):

| Protocol Stage | Measured Latency | Technical Explanation & Exact Number |
| :--- | :--- | :--- |
| **TCP Connect Latency (P50)** | **0.00 µs** | **HTTP/1.1 Keep-Alive Connection Reuse**: Connections are opened once at test start. 99.87% of requests reuse the open TCP pipe with **0 ns** re-handshake overhead. *(Initial 3-way handshake takes **32.5 µs**).* |
| **HTTP Socket Sending (P50)** | **0.00 µs** | **Sub-Microsecond Kernel Buffering**: ~150-byte HTTP request headers are copied to the OS socket buffer in **~1.8 µs** (1,800 ns). |
| **Socket Read / Recv (P50)** | **0.00 µs** | Responses are read directly from kernel memory without intermediate socket stalls. |
| **End-to-End Success Rate** | **100.0000%** | **378,328 / 378,328 requests succeeded** with zero dropped packets and zero memory leaks (< 18 MB RSS). |

---

## 🛠️ Upstream Core Infrastructure Contributions (11+ Systems Fixes)

Spryzen's sub-microsecond networking and zero-allocation philosophy is directly upstreamed to foundational open-source runtimes and edge proxies:

* **[smoltcp (PR #1194 - Merged)](https://github.com/smoltcp-rs/smoltcp/pull/1194)**: Engineered single-pass zero-allocation `TcpOptionSummary` wire parser.
* **[Foundry (PR #16707 - Merged)](https://github.com/foundry-rs/foundry/pull/16707)**: Hardened Chisel session validator against NTFS alternate data stream path traversal.
* **[Cloudflare Pingora (PR #1039)](https://github.com/cloudflare/pingora/pull/1039)**: Fixed panic on non-UTF-8 response headers in HTTP/1 trace logging.
* **[Hyperium Hyper (PR #337)](https://github.com/hyperium/hyper-util/pull/337)**: Bounded automatic server protocol version detection with configurable read timeout.
* **[Bytecode Alliance Wasmtime (PR #14515)](https://github.com/bytecodealliance/wasmtime/pull/14515)**: Enhanced CLI component export validation error reporting.
* **[Tokio Async Runtime (PR #8575)](https://github.com/tokio-rs/tokio/pull/8575)**: Resolved arithmetic overflow guard on buffered relative file seeks.

---

## 🚀 How to Reproduce Locally

### 1. Prerequisites
```bash
rustc --version
cargo --version
python3 --version
k6 version              # optional (required only for benchmark.js)
wafw00f --version       # optional (used by eval_security.py when available)
sqlmap --version        # optional (used by eval_security.py when available)
nikto -Version          # optional (used by eval_security.py when available)
```

### 2. Clone and enter repository
```bash
git clone https://github.com/Aditya-9-6/Spryzen-Benchmarks.git
cd Spryzen-Benchmarks
```

### 3. Reproducible checks
```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test --release -- --nocapture
cargo build --release
```

### 4. Start server for runtime/security/perf checks
```bash
PORT=8081 RATE_LIMIT_ENABLED=false ./target/release/spryzen-engine
```

### 5. Verify server health (new terminal)
```bash
curl -i http://127.0.0.1:8081/health
```

### 6. Runtime checks against the running server (new terminal)
```bash
# k6 benchmark (optional; requires k6 binary)
k6 run benchmark.js

# Optional target override (backwards-compatible with existing default)
k6 run -e TARGET_URL=http://127.0.0.1:8081/products/104 benchmark.js

# Security evaluation (defaults to http://127.0.0.1:8081)
python3 scripts/eval_security.py

# Fuzz safety validation
python3 scripts/fuzz_test.py
```

---

## ✅ Latest local/CI verification (this task run)

Timestamp (UTC): `2026-10-06`

Environment-observed tool versions:

- `rustc 1.98.1 (48a229cea 2026-09-01)`
- `cargo 1.98.1 (797e8a9bc 2026-08-05)`
- `Python 3.12.3`
- `k6`: **not installed** in this environment

Local checks executed:

- `cargo fmt -- --check` ✅ pass (exit code 0)
- `cargo clippy --all-targets -- -D warnings` ✅ pass (exit code 0)
- `cargo test --release -- --nocapture` ✅ pass (`13 passed; 0 failed`)
- `cargo build --release` ✅ pass
- `PORT=8081 RATE_LIMIT_ENABLED=false ./target/release/spryzen-engine` ✅ started
- `curl -i http://127.0.0.1:8081/health` ✅ `HTTP/1.1 200 OK` with `server: Spryzen/2.2.0`
- `k6 run benchmark.js` ⚠️ skipped (`k6: command not found`)
- `python3 scripts/eval_security.py` ✅ pass:
  - OWASP vectors blocked: `39/39 (100.00%)`
  - False positives on clean traffic: `0/10 (0.00%)`
  - `wafw00f`, `sqlmap`, `nikto`: skipped (not installed)
- `python3 scripts/fuzz_test.py` ✅ pass:
  - `FUZZ_COUNT=10000`
  - `server_crashes=0`
  - final health check passed

Relevant CI observation during this task:

- Recent pull-request workflow runs were listed via GitHub Actions API and showed `conclusion: action_required` with `total_jobs: 0` for this in-progress Copilot branch run, so no failed-job logs were available for those runs.

## 📜 License
Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
