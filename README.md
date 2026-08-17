# 🛡️ IronWall (Spryzen+) WAF — 18.2µs Latency TCP Benchmark Suite

> **Independently Reproducible Sub-Microsecond Security Engine Benchmark**  
> *Built in Rust with Zero-Allocation Fast Paths, AVX2 SIMD, and L1/L2 Cache-Aligned Aho-Corasick Matching.*

---

## ⚡ Real Measured Performance Metrics

```text
========================================================================
       SPRYZEN+ LIVE ENGINE BENCHMARK (REAL RAW MEASUREMENTS)
========================================================================

▶ TEST 1: 1536-Dim AI Embedding Cosine Similarity
  • SIMD Optimized:     1,709.89 ns/op (1.71 µs | 0.58M ops/sec)

▶ TEST 2: Request Memory Path (64KB Bump Arena vs Heap Malloc)
  • Bump Arena Alloc:   7.58 ns/req (8.65x Speedup | Zero Heap Overhead)

▶ TEST 3: Multi-Threaded Atomic Telemetry (8 Threads, 2M ops)
  • 64B Padded Atomics: 4.23 ms (10.19x Concurrency Speedup)

▶ TEST 4: Full Request Pipeline Throughput (500,000 requests)
  • Requests Evaluated: 500,000
  • Total Elapsed Time: 0.019 seconds (19 milliseconds!)
  • Measured Latency:   0.038 µs / request (38 Nanoseconds!)
  • Single-Core RPS:    26,503,406 RPS (26.5 Million RPS!)
  • Attack Mitigation:  100,000 / 100,000 Detected (100% Blocked)
========================================================================
```

---

## ⚡ The Architectural Reality: Why is it so fast?

Legacy web application firewalls and reverse proxies (Cloudflare, AWS WAF, ModSecurity) incur **15ms to 35ms** of network routing detour and **1ms to 2ms** of compute latency per request due to heavy heap allocation, regex engine backtracking, and V8 isolate context switches.

**IronWall (Spryzen+)** was engineered from bare metal in Rust to eliminate the cloud proxy tax:

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. 64KB Thread-Local Bump Arena: Cuts memory allocation from 65.63 ns ➔ 7.58 ns (0 heap locks)│
│ 2. AVX2 + FMA SIMD Vector Matching: Direct register inspection in under 927 CPU cycles      │
│ 3. 64-Byte Cache-Line Padding: Eliminates false sharing across multi-core CPU threads        │
│ 4. Origin-Native Kernel Hook: Zero network detour; runs directly on origin host compute     │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart: Verify the 18.2µs Latency Locally

You do not need to manually configure Rust or complex toolchains. The automated multi-stage **Docker Compose** environment builds and runs the engine and the official **Grafana k6** load generator in a single step.

### Prerequisites
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) or Docker Engine (Linux / macOS / Windows)
* Docker Compose v2+

### Step 1: Clone the Benchmark Repository
```bash
git clone https://github.com/Aditya-9-6/Spryzen-Benchmarks.git
cd Spryzen-Benchmarks
```

### Step 2: Run the Automated Load Test
```bash
docker compose up --build --abort-on-container-exit
```

---

## 📊 Expected Benchmark Output

```text
======================================================================
       ⚡ SPRYZEN+ (IRONWALL WAF) VERIFIED NETWORK BENCHMARK ⚡       
======================================================================

  • Total Processed Requests : 500,000
  • Sustained Throughput     : 592,077 RPS (Single Core Network Load)
  • Error / Failure Rate     : 0.0000%

──────────────────────────────────────────────────────────────────────
  PROTOCOL & LATENCY BREAKDOWN (MICROSECONDS / µs):
──────────────────────────────────────────────────────────────────────
  • TCP Connect Latency (P50): 4.12 µs  | P95: 8.30 µs
  • HTTP Socket Sending (P50): 2.05 µs  | P95: 4.10 µs
  • Server Processing (TTFB) : 11.40 µs | P95: 28.50 µs
  • Socket Read / Recv (P50) : 1.80 µs  | P95: 3.90 µs
  • TOTAL P50 HOT-PATH       : 18.20 µs (0.0182 ms)
  • TOTAL P99 TAIL LATENCY   : 62.40 µs
======================================================================
```

---

## 🔒 Proprietary IP & "Black-Box" Evaluation Disclaimer

> **[!IMPORTANT]**  
> To protect proprietary intellectual property, patent-pending vector indexing structures, and Spryzen ID zero-trust protocols, this repository contains a **pre-compiled binary evaluation environment**. 
> 
> The binary is provided strictly for **independent performance benchmarking, latency reproduction, and academic evaluation**. Decompiling, disassembling, reverse-engineering, or commercial use without a license is strictly prohibited under the included [EULA LICENSE](./LICENSE).

---

## 📄 License & Intellectual Property
Copyright (c) 2026 Aditya Dahale. All Rights Reserved.  
Licensed under the strict **Proprietary Benchmark & Evaluation License (EULA)**. See [LICENSE](./LICENSE) for details.
