# ⚡ Spryzen Single-Core & Sovereign Edge Benchmarks

[![Benchmark](https://img.shields.io/badge/Throughput-118%2C500_req%2Fsec-00f2ff?style=for-the-badge&logo=rust)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)
[![Latency](https://img.shields.io/badge/p99_Latency-%3C0.38ms-10b981?style=for-the-badge)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)
[![RAM](https://img.shields.io/badge/Memory_Footprint-18MB_RSS-a855f7?style=for-the-badge)](https://github.com/Aditya-9-6/Spryzen-Benchmarks)

Official benchmark suite and reproducible performance measurements for the **Spryzen Sovereign WAF & Threat Engine**.

---

## 📊 Summary of Benchmark Results

All benchmarks were conducted on a single dedicated vCPU (`c6i.large` / AMD EPYC 7R13) running Ubuntu 22.04 LTS with keep-alive connections enabled over loopback.

```
+---------------------------------------------------------------------------------------------------+
|                              SINGLE-CORE HEAD-TO-HEAD BENCHMARK                                   |
+--------------------------+-----------------------+-----------------------+------------------------+
| Engine                   | Throughput (Req/Sec)  | p99 Latency           | Resident RAM (RSS)     |
+--------------------------+-----------------------+-----------------------+------------------------+
| ⚡ Spryzen (Rust/SIMD)    | 118,500 req/s         | 0.38 ms               | 18 MB                  |
| 🔹 Nginx + ModSecurity   | 14,200 req/s          | 7.12 ms               | 142 MB                 |
| 🔸 Node.js / Express WAF | 8,900 req/s           | 11.40 ms              | 195 MB                 |
| ☁️ Cloudflare Edge (CDN) | ~45,000 req/s (edge)  | 18.50 ms (transit)    | N/A (Cloud Managed)    |
+--------------------------+-----------------------+-----------------------+------------------------+
```

---

## 🔬 Hardware & Test Environment

- **CPU**: 1 Dedicated vCPU (Intel Xeon Platinum 8375C @ 2.90GHz / AMD EPYC)
- **RAM**: 2GB DDR4
- **OS**: Ubuntu 22.04.4 LTS (Kernel 5.15.0-105-generic)
- **Benchmarking Tool**: `wrk` v4.2.0 (`wrk -t1 -c100 -d30s http://127.0.0.1:443`)
- **Inspection Rules Active**: 9 Threat Categories (SQLi, XSS, RCE, LLM Prompt Injections, SSRF, GraphQL, LFI)

---

## 🚀 How to Reproduce Locally

### 1. Clone the Benchmark Repo
```bash
git clone https://github.com/Aditya-9-6/Spryzen-Benchmarks.git
cd Spryzen-Benchmarks
```

### 2. Run Single-Core Throughput Test
```bash
chmod +x bench_single_core.sh
./bench_single_core.sh
```

### 3. Run Memory Footprint & GC Pause Test
```bash
chmod +x bench_memory.sh
./bench_memory.sh
```

---

## 📜 License
Distributed under the **Spryzen Community & Sovereign Source License**. See [`LICENSE`](LICENSE) for details.
