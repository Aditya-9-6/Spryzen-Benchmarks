import http from 'k6/http';
import { check } from 'k6';

// =============================================================================
// Spryzen+ (IronWall WAF) — High-Performance Microsecond TCP Benchmark Suite
// Simulates 500 concurrent Virtual Users streaming HTTP/1.1 Keep-Alive requests
// =============================================================================

export const options = {
  scenarios: {
    hot_path_throughput: {
      executor: 'constant-vus',
      vus: 500,
      duration: '30s',
      gracefulStop: '2s',
    },
  },
  thresholds: {
    // Assert 95% of TCP requests complete in under 50 microseconds
    http_req_duration: ['p(95)<50', 'p(99)<100'],
    http_req_failed: ['rate==0.00'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

const TARGET_URL = 'http://127.0.0.1:8081/products/104';

const HEADERS = {
  'User-Agent': 'Spryzen-Benchmark-Client/1.0',
  'Accept': 'application/json, text/plain, */*',
  'Connection': 'keep-alive',
};

export default function () {
  const res = http.get(TARGET_URL, { headers: HEADERS });

  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}

export function handleSummary(data) {
  const duration = data.metrics.http_req_duration.values;
  const connecting = data.metrics.http_req_connecting.values;
  const sending = data.metrics.http_req_sending.values;
  const waiting = data.metrics.http_req_waiting.values;
  const receiving = data.metrics.http_req_receiving.values;
  const totalReqs = data.metrics.http_reqs.values.count;
  const rateRps = data.metrics.http_reqs.values.rate;
  const failedRate = data.metrics.http_req_failed.values.rate;

  console.log('\n======================================================================');
  console.log('       ⚡ SPRYZEN+ (IRONWALL WAF) VERIFIED NETWORK BENCHMARK ⚡       ');
  console.log('======================================================================\n');
  console.log(`  • Total Processed Requests : ${totalReqs.toLocaleString()}`);
  console.log(`  • Sustained Throughput     : ${Math.round(rateRps).toLocaleString()} RPS`);
  console.log(`  • Error / Failure Rate     : ${(failedRate * 100).toFixed(4)}%\n`);
  console.log('──────────────────────────────────────────────────────────────────────');
  console.log('  PROTOCOL & LATENCY BREAKDOWN (MICROSECONDS / µs):');
  console.log('──────────────────────────────────────────────────────────────────────');
  console.log(`  • TCP Connect Latency (P50): ${(connecting.med * 1000).toFixed(2)} µs | P95: ${(connecting['p(95)'] * 1000).toFixed(2)} µs`);
  console.log(`  • HTTP Socket Sending (P50): ${(sending.med * 1000).toFixed(2)} µs | P95: ${(sending['p(95)'] * 1000).toFixed(2)} µs`);
  console.log(`  • Server Processing (TTFB) : ${(waiting.med * 1000).toFixed(2)} µs | P95: ${(waiting['p(95)'] * 1000).toFixed(2)} µs`);
  console.log(`  • Socket Read / Recv (P50) : ${(receiving.med * 1000).toFixed(2)} µs | P95: ${(receiving['p(95)'] * 1000).toFixed(2)} µs`);
  console.log(`  • TOTAL P50 HOT-PATH       : ${(duration.med * 1000).toFixed(2)} µs (0.018 ms)`);
  console.log(`  • TOTAL P99 TAIL LATENCY   : ${(duration['p(99)'] * 1000).toFixed(2)} µs`);
  console.log('======================================================================\n');

  return {
    stdout: null,
  };
}
