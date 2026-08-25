#!/usr/bin/env bash
# Spryzen Single-Core Throughput & Latency Replication Script

set -e

TARGET_URL=${1:-"http://127.0.0.1:443"}
THREADS=1
CONNECTIONS=100
DURATION="30s"

echo "================================================================="
echo "⚡ Running Spryzen Single-Core Benchmark (wrk)"
echo "Target: ${TARGET_URL} | Threads: ${THREADS} | Connections: ${CONNECTIONS} | Duration: ${DURATION}"
echo "================================================================="

if ! command -v wrk >/dev/null 2>&1; then
  echo "⚠️ 'wrk' not found. Installing via apt..."
  sudo apt-get update && sudo apt-get install -y wrk
fi

wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} --latency "${TARGET_URL}"
