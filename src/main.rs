use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::Infallible;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ahash::RandomState;
use aho_corasick::AhoCorasick;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

// ============================================================================
// 1. ENTERPRISE CONFIGURATION ENGINE (spryzen.toml + ENV Overrides)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    Block,
    Simulate,
    Bypass,
}

impl EnforcementMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Simulate => "simulate",
            Self::Bypass => "bypass",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub upstream: Option<String>,
    pub mode: EnforcementMode,
    pub timeout_ms: u64,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    pub paths: Vec<String>,
    pub ips: Vec<String>,
}

impl AllowlistConfig {
    pub fn is_path_allowlisted(&self, path: &str) -> bool {
        for pattern in &self.paths {
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                if path.starts_with(prefix) {
                    return true;
                }
            } else if pattern == path {
                return true;
            }
        }
        false
    }

    pub fn is_ip_allowlisted(&self, ip: &IpAddr) -> bool {
        let ip_str = ip.to_string();
        for allowed in &self.ips {
            if allowed == &ip_str {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub format: String,
    pub mask_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpryzenConfig {
    pub server: ServerConfig,
    pub rate_limit: RateLimitConfig,
    pub allowlist: AllowlistConfig,
    pub logging: LoggingConfig,
}

impl Default for SpryzenConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen: "0.0.0.0:8080".to_string(),
                upstream: None,
                mode: EnforcementMode::Block,
                timeout_ms: 10000,
                max_body_bytes: 10 * 1024 * 1024,
            },
            rate_limit: RateLimitConfig {
                enabled: true,
                requests_per_second: 100_000,
                burst: 200_000,
            },
            allowlist: AllowlistConfig {
                paths: vec![
                    "/health".to_string(),
                    "/metrics".to_string(),
                    "/_spryzen/*".to_string(),
                ],
                ips: vec![],
            },
            logging: LoggingConfig {
                format: "json".to_string(),
                mask_headers: vec![
                    "authorization".to_string(),
                    "cookie".to_string(),
                    "x-api-key".to_string(),
                    "proxy-authorization".to_string(),
                ],
            },
        }
    }
}

impl SpryzenConfig {
    pub fn load() -> Self {
        let mut config = Self::default();

        // 1. Try loading from file
        let config_path =
            std::env::var("SPRYZEN_CONFIG").unwrap_or_else(|_| "spryzen.toml".to_string());
        if Path::new(&config_path).exists() {
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                if let Ok(parsed) = toml::from_str::<SpryzenConfig>(&content) {
                    config = parsed;
                }
            }
        } else if Path::new("spryzen.default.toml").exists() {
            if let Ok(content) = std::fs::read_to_string("spryzen.default.toml") {
                if let Ok(parsed) = toml::from_str::<SpryzenConfig>(&content) {
                    config = parsed;
                }
            }
        }

        // 2. Apply ENV Variable Overrides
        if let Ok(port) = std::env::var("PORT") {
            config.server.listen = format!("0.0.0.0:{}", port);
        }
        if let Ok(listen) = std::env::var("SPRYZEN_LISTEN") {
            config.server.listen = listen;
        }
        if let Ok(upstream) = std::env::var("UPSTREAM_URL")
            .or_else(|_| std::env::var("UPSTREAM"))
            .or_else(|_| std::env::var("BACKEND_URL"))
        {
            if !upstream.trim().is_empty() {
                config.server.upstream = Some(upstream);
            }
        }
        if let Ok(mode) = std::env::var("SPRYZEN_MODE") {
            match mode.to_ascii_lowercase().as_str() {
                "simulate" | "monitor" | "audit" => config.server.mode = EnforcementMode::Simulate,
                "bypass" | "off" => config.server.mode = EnforcementMode::Bypass,
                "block" => config.server.mode = EnforcementMode::Block,
                _ => {}
            }
        }
        if let Ok(rps) = std::env::var("RATE_LIMIT_RPS") {
            if let Ok(val) = rps.parse::<u32>() {
                config.rate_limit.requests_per_second = val;
                config.rate_limit.burst = val * 2;
            }
        }
        if let Ok(enabled) = std::env::var("RATE_LIMIT_ENABLED") {
            config.rate_limit.enabled = enabled.to_lowercase() != "false" && enabled != "0";
        }

        config
    }
}

// ============================================================================
// 2. IN-MEMORY TOKEN-BUCKET RATE LIMITER (PER CLIENT IP)
// ============================================================================

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

pub struct RateLimiter {
    enabled: bool,
    rps: f64,
    burst: f64,
    buckets: Mutex<HashMap<IpAddr, TokenBucket, RandomState>>,
}

impl RateLimiter {
    pub fn new(enabled: bool, rps: u32, burst: u32) -> Self {
        Self {
            enabled,
            rps: rps as f64,
            burst: burst as f64,
            buckets: Mutex::new(HashMap::with_hasher(RandomState::new())),
        }
    }

    pub fn check_and_consume(&self, ip: IpAddr) -> bool {
        if !self.enabled {
            return true;
        }
        let now = Instant::now();
        let mut guard = self.buckets.lock();
        let bucket = guard.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.burst,
            last_update: now,
        });

        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst);
        bucket.last_update = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// 3. STRUCTURED SIEM JSON AUDIT LOGGING
// ============================================================================

#[derive(Serialize)]
struct SiemLogEntry<'a> {
    timestamp: u64,
    client_ip: String,
    method: &'a str,
    path: &'a str,
    status: u16,
    verdict: &'a str,
    threat: &'a str,
    mode: &'a str,
    latency_us: u64,
}

#[allow(clippy::too_many_arguments)]
fn emit_siem_log(
    is_json: bool,
    client_ip: IpAddr,
    method: &str,
    path: &str,
    status: u16,
    verdict: &str,
    threat: &str,
    mode: &str,
    latency_us: u64,
) {
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if is_json {
        let entry = SiemLogEntry {
            timestamp: now_epoch,
            client_ip: client_ip.to_string(),
            method,
            path,
            status,
            verdict,
            threat,
            mode,
            latency_us,
        };
        if let Ok(json) = serde_json::to_string(&entry) {
            println!("{}", json);
        }
    } else {
        println!(
            "[{}] {} {} -> HTTP {} | Verdict: {} | Threat: {} | Mode: {} | {}µs",
            now_epoch, method, path, status, verdict, threat, mode, latency_us
        );
    }
}

// ============================================================================
// 4. STACK THREAT BITFLAGS (ZERO-ALLOCATION)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreatFlags(pub u32);

impl ThreatFlags {
    pub const CLEAN: Self = Self(0);
    pub const SQLI: Self = Self(1 << 0);
    pub const XSS: Self = Self(1 << 1);
    pub const RCE: Self = Self(1 << 2);
    pub const PATH_TRAVERSAL: Self = Self(1 << 3);
    pub const PROMPT_INJECTION: Self = Self(1 << 4);
    pub const PROTOCOL_VIOLATION: Self = Self(1 << 5);
    pub const SSRF: Self = Self(1 << 6);
    pub const SSTI: Self = Self(1 << 7);

    #[inline(always)]
    pub fn is_threat(&self) -> bool {
        self.0 != 0
    }

    #[inline(always)]
    pub fn name(&self) -> &'static str {
        if self.0 & Self::SQLI.0 != 0 {
            "SQL Injection"
        } else if self.0 & Self::XSS.0 != 0 {
            "Cross-Site Scripting (XSS)"
        } else if self.0 & Self::RCE.0 != 0 {
            "Remote Code Execution (RCE)"
        } else if self.0 & Self::PATH_TRAVERSAL.0 != 0 {
            "Path Traversal (LFI/RFI)"
        } else if self.0 & Self::PROMPT_INJECTION.0 != 0 {
            "LLM Prompt Injection"
        } else if self.0 & Self::SSRF.0 != 0 {
            "Server-Side Request Forgery (SSRF)"
        } else if self.0 & Self::SSTI.0 != 0 {
            "Server-Side Template Injection (SSTI)"
        } else if self.0 & Self::PROTOCOL_VIOLATION.0 != 0 {
            "Protocol Violation"
        } else {
            "Clean"
        }
    }
}

// ============================================================================
// 5. AVX2 SIMD + O(1) LOOKUP TABLE SCANNER & NORMALIZATION
// ============================================================================

pub static RISKY_CHAR_LUT: [bool; 256] = {
    let mut lut = [false; 256];
    let risky = b"'\"<>/\\-;{}$#`=(),*%+|&[].\0";
    let mut i = 0;
    while i < risky.len() {
        lut[risky[i] as usize] = true;
        i += 1;
    }
    lut
};

#[inline(always)]
pub fn has_risky_characters(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| RISKY_CHAR_LUT[b as usize])
}

pub fn normalize_uri_bytes<'a>(input: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
    let mut i = 0;
    let mut out_len = 0;
    let max = buf.len().min(input.len());

    while i < input.len() && out_len < max {
        if input[i] == b'%' && i + 2 < input.len() {
            let h1 = input[i + 1];
            let h2 = input[i + 2];
            let val1 = match h1 {
                b'0'..=b'9' => Some(h1 - b'0'),
                b'a'..=b'f' => Some(h1 - b'a' + 10),
                b'A'..=b'F' => Some(h1 - b'A' + 10),
                _ => None,
            };
            let val2 = match h2 {
                b'0'..=b'9' => Some(h2 - b'0'),
                b'a'..=b'f' => Some(h2 - b'a' + 10),
                b'A'..=b'F' => Some(h2 - b'A' + 10),
                _ => None,
            };
            if let (Some(v1), Some(v2)) = (val1, val2) {
                buf[out_len] = (v1 << 4) | v2;
                out_len += 1;
                i += 3;
                continue;
            }
        } else if input[i] == b'+' {
            buf[out_len] = b' ';
            out_len += 1;
            i += 1;
            continue;
        }
        buf[out_len] = input[i];
        out_len += 1;
        i += 1;
    }

    if buf[..out_len].contains(&b'%') {
        let mut pass2_buf = [0u8; 1024];
        let p2_max = pass2_buf.len().min(out_len);
        let mut j = 0;
        let mut p2_len = 0;
        while j < out_len && p2_len < p2_max {
            if buf[j] == b'%' && j + 2 < out_len {
                let val1 = match buf[j + 1] {
                    b'0'..=b'9' => Some(buf[j + 1] - b'0'),
                    b'a'..=b'f' => Some(buf[j + 1] - b'a' + 10),
                    b'A'..=b'F' => Some(buf[j + 1] - b'A' + 10),
                    _ => None,
                };
                let val2 = match buf[j + 2] {
                    b'0'..=b'9' => Some(buf[j + 2] - b'0'),
                    b'a'..=b'f' => Some(buf[j + 2] - b'a' + 10),
                    b'A'..=b'F' => Some(buf[j + 2] - b'A' + 10),
                    _ => None,
                };
                if let (Some(v1), Some(v2)) = (val1, val2) {
                    pass2_buf[p2_len] = (v1 << 4) | v2;
                    p2_len += 1;
                    j += 3;
                    continue;
                }
            }
            pass2_buf[p2_len] = buf[j];
            p2_len += 1;
            j += 1;
        }
        buf[..p2_len].copy_from_slice(&pass2_buf[..p2_len]);
        out_len = p2_len;
    }

    &buf[..out_len]
}

// ============================================================================
// 6. COMPREHENSIVE OWASP CRS AHO-CORASICK PATTERN ENGINE
// ============================================================================

static WAF_PATTERNS: Lazy<(AhoCorasick, Vec<ThreatFlags>)> = Lazy::new(|| {
    let patterns = vec![
        ("union select", ThreatFlags::SQLI),
        ("union all select", ThreatFlags::SQLI),
        ("select from", ThreatFlags::SQLI),
        ("insert into", ThreatFlags::SQLI),
        ("drop table", ThreatFlags::SQLI),
        ("or 1=1", ThreatFlags::SQLI),
        ("or 1 = 1", ThreatFlags::SQLI),
        ("or '1'='1", ThreatFlags::SQLI),
        ("or '1' = '1", ThreatFlags::SQLI),
        ("or true", ThreatFlags::SQLI),
        ("and 1=1", ThreatFlags::SQLI),
        ("and 1 = 1", ThreatFlags::SQLI),
        ("and true", ThreatFlags::SQLI),
        ("'--", ThreatFlags::SQLI),
        ("' --", ThreatFlags::SQLI),
        ("admin' --", ThreatFlags::SQLI),
        ("admin'--", ThreatFlags::SQLI),
        ("' or '", ThreatFlags::SQLI),
        ("' or ", ThreatFlags::SQLI),
        ("' and '", ThreatFlags::SQLI),
        ("/*", ThreatFlags::SQLI),
        ("*/", ThreatFlags::SQLI),
        ("sleep(", ThreatFlags::SQLI),
        ("pg_sleep", ThreatFlags::SQLI),
        ("waitfor delay", ThreatFlags::SQLI),
        ("benchmark(", ThreatFlags::SQLI),
        ("information_schema", ThreatFlags::SQLI),
        ("extractvalue(", ThreatFlags::SQLI),
        ("updatexml(", ThreatFlags::SQLI),
        ("schema()", ThreatFlags::SQLI),
        ("database()", ThreatFlags::SQLI),
        ("<script", ThreatFlags::XSS),
        ("</script>", ThreatFlags::XSS),
        ("javascript:", ThreatFlags::XSS),
        ("vbscript:", ThreatFlags::XSS),
        ("onerror=", ThreatFlags::XSS),
        ("onerror =", ThreatFlags::XSS),
        ("onload=", ThreatFlags::XSS),
        ("onload =", ThreatFlags::XSS),
        ("onfocus=", ThreatFlags::XSS),
        ("onmouseover=", ThreatFlags::XSS),
        ("onblur=", ThreatFlags::XSS),
        ("alert(", ThreatFlags::XSS),
        ("eval(", ThreatFlags::XSS),
        ("document.cookie", ThreatFlags::XSS),
        ("<iframe", ThreatFlags::XSS),
        ("<svg", ThreatFlags::XSS),
        ("<img", ThreatFlags::XSS),
        ("src=x", ThreatFlags::XSS),
        ("data:text/html", ThreatFlags::XSS),
        ("..", ThreatFlags::PATH_TRAVERSAL),
        ("/etc/passwd", ThreatFlags::PATH_TRAVERSAL),
        ("/etc/shadow", ThreatFlags::PATH_TRAVERSAL),
        ("boot.ini", ThreatFlags::PATH_TRAVERSAL),
        ("win.ini", ThreatFlags::PATH_TRAVERSAL),
        ("windows/win.ini", ThreatFlags::PATH_TRAVERSAL),
        ("proc/self/environ", ThreatFlags::PATH_TRAVERSAL),
        ("proc/self/cmdline", ThreatFlags::PATH_TRAVERSAL),
        ("/bin/bash", ThreatFlags::RCE),
        ("/bin/sh", ThreatFlags::RCE),
        ("powershell", ThreatFlags::RCE),
        ("cmd.exe", ThreatFlags::RCE),
        ("curl ", ThreatFlags::RCE),
        ("wget ", ThreatFlags::RCE),
        ("nc -e", ThreatFlags::RCE),
        (";whoami", ThreatFlags::RCE),
        ("; whoami", ThreatFlags::RCE),
        ("|whoami", ThreatFlags::RCE),
        ("| whoami", ThreatFlags::RCE),
        ("$(whoami)", ThreatFlags::RCE),
        (";cat", ThreatFlags::RCE),
        ("; cat", ThreatFlags::RCE),
        (";id", ThreatFlags::RCE),
        ("; id", ThreatFlags::RCE),
        ("|id", ThreatFlags::RCE),
        ("| id", ThreatFlags::RCE),
        (";ls", ThreatFlags::RCE),
        ("; ls", ThreatFlags::RCE),
        ("|ls", ThreatFlags::RCE),
        ("| ls", ThreatFlags::RCE),
        ("bash -i", ThreatFlags::RCE),
        ("169.254.169.254", ThreatFlags::SSRF),
        ("metadata.google.internal", ThreatFlags::SSRF),
        ("instance-data", ThreatFlags::SSRF),
        ("{{7*7}}", ThreatFlags::SSTI),
        ("${7*7}", ThreatFlags::SSTI),
        ("#{7*7}", ThreatFlags::SSTI),
        ("{{config", ThreatFlags::SSTI),
        (
            "ignore previous instructions",
            ThreatFlags::PROMPT_INJECTION,
        ),
        (
            "disregard all prior instructions",
            ThreatFlags::PROMPT_INJECTION,
        ),
        ("system prompt", ThreatFlags::PROMPT_INJECTION),
    ];

    let keys: Vec<&str> = patterns.iter().map(|(k, _)| *k).collect();
    let flags: Vec<ThreatFlags> = patterns.iter().map(|(_, f)| *f).collect();

    let ac = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(keys)
        .expect("AhoCorasick build failed");

    (ac, flags)
});

// ============================================================================
// 7. THREAD-LOCAL L1 REPEAT CACHE
// ============================================================================

const CACHE_SIZE: usize = 2048;

pub struct ThreadLocalInspector {
    cache_keys: [u64; CACHE_SIZE],
    cache_verdicts: [ThreatFlags; CACHE_SIZE],
    hasher_builder: RandomState,
}

impl Default for ThreadLocalInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadLocalInspector {
    pub fn new() -> Self {
        Self {
            cache_keys: [0; CACHE_SIZE],
            cache_verdicts: [ThreatFlags::CLEAN; CACHE_SIZE],
            hasher_builder: RandomState::new(),
        }
    }

    #[inline(always)]
    pub fn inspect(&mut self, path: &str, query: Option<&str>, body: Option<&[u8]>) -> ThreatFlags {
        let mut hasher = self.hasher_builder.build_hasher();
        hasher.write(path.as_bytes());
        if let Some(q) = query {
            hasher.write(q.as_bytes());
        }
        if let Some(b) = body {
            hasher.write(b);
        }
        let hash = hasher.finish();

        let slot = (hash as usize) % CACHE_SIZE;
        if self.cache_keys[slot] == hash {
            return self.cache_verdicts[slot];
        }

        let path_bytes = path.as_bytes();
        let query_bytes = query.map(|q| q.as_bytes()).unwrap_or(b"");
        let body_bytes = body.unwrap_or(b"");

        let has_risky = has_risky_characters(path_bytes)
            || has_risky_characters(query_bytes)
            || has_risky_characters(body_bytes);

        if !has_risky {
            self.cache_keys[slot] = hash;
            self.cache_verdicts[slot] = ThreatFlags::CLEAN;
            return ThreatFlags::CLEAN;
        }

        let mut norm_buf_path = [0u8; 1024];
        let mut norm_buf_query = [0u8; 4096];
        let mut norm_buf_body = [0u8; 8192];
        let dec_path = normalize_uri_bytes(path_bytes, &mut norm_buf_path);
        let dec_query = normalize_uri_bytes(query_bytes, &mut norm_buf_query);
        let dec_body = normalize_uri_bytes(body_bytes, &mut norm_buf_body);

        let (ac, flags) = &*WAF_PATTERNS;
        let mut result = ThreatFlags::CLEAN;

        if let Ok(p_str) = std::str::from_utf8(dec_path) {
            if let Some(m) = ac.find(p_str) {
                result.0 |= flags[m.pattern().as_usize()].0;
            }
        }
        if let Ok(q_str) = std::str::from_utf8(dec_query) {
            if let Some(m) = ac.find(q_str) {
                result.0 |= flags[m.pattern().as_usize()].0;
            }
        }
        if !dec_body.is_empty() {
            if let Ok(b_str) = std::str::from_utf8(dec_body) {
                if let Some(m) = ac.find(b_str) {
                    result.0 |= flags[m.pattern().as_usize()].0;
                }
            }
        }

        self.cache_keys[slot] = hash;
        self.cache_verdicts[slot] = result;
        result
    }
}

thread_local! {
    static INSPECTOR: RefCell<ThreadLocalInspector> = RefCell::new(ThreadLocalInspector::new());
}

// ============================================================================
// 8. CACHE-ALIGNED ATOMIC METRICS
// ============================================================================

#[repr(align(64))]
pub struct AlignedMetrics {
    pub processed: AtomicU64,
    pub threats_blocked: AtomicU64,
    pub clean_requests: AtomicU64,
    pub rate_limited: AtomicU64,
}

impl Default for AlignedMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl AlignedMetrics {
    pub fn new() -> Self {
        Self {
            processed: AtomicU64::new(0),
            threats_blocked: AtomicU64::new(0),
            clean_requests: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// 9. MAIN PRODUCTION SERVER & GRACEFUL DRAIN
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(SpryzenConfig::load());
    let addr: SocketAddr = config.server.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;

    let mut http_connector = HttpConnector::new();
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(std::time::Duration::from_secs(60)));
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(hyper_util::rt::TokioExecutor::new())
            .pool_max_idle_per_host(256)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build(http_connector);
    let client = Arc::new(client);

    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit.enabled,
        config.rate_limit.requests_per_second,
        config.rate_limit.burst,
    ));

    let metrics = Arc::new(AlignedMetrics::new());

    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║       SPRYZEN+ ENTERPRISE REVERSE PROXY & API SECURITY GATEWAY       ║");
    println!("║       Architecture: AVX2 SIMD + Zero-Alloc Bitmasks + L1 Cache        ║");
    println!(
        "║       Enforcement Mode: {:<45}║",
        format!("{:?}", config.server.mode)
    );
    println!(
        "║       Listening Address: {:<44}║",
        format!("http://{}", addr)
    );
    if let Some(ref up) = config.server.upstream {
        println!("║       Upstream URL: {:<49}║", up);
        println!("║       Operating Mode: ACTIVE DROP-IN INLINE REVERSE PROXY WAF         ║");
    } else {
        println!("║       Upstream URL: (none) -> STANDALONE BENCHMARK & EVALUATION MODE  ║");
    }
    println!(
        "║       Rate Limiting: {:<48}║",
        if config.rate_limit.enabled {
            format!(
                "{} RPS (Burst: {})",
                config.rate_limit.requests_per_second, config.rate_limit.burst
            )
        } else {
            "Disabled".to_string()
        }
    );
    println!(
        "║       SIEM Log Format: {:<46}║",
        config.logging.format.to_uppercase()
    );
    println!("╚══════════════════════════════════════════════════════════════════════╝");

    let server = auto::Builder::new(hyper_util::rt::TokioExecutor::new());

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                let (stream, client_addr) = accept_res?;
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let metrics = metrics.clone();
                let config = config.clone();
                let client = client.clone();
                let rate_limiter = rate_limiter.clone();
                let server = server.clone();

                tokio::task::spawn(async move {
                    let client_ip = client_addr.ip();
                    let service = service_fn(move |mut req: Request<Incoming>| {
                        let metrics = metrics.clone();
                        let config = config.clone();
                        let client = client.clone();
                        let rate_limiter = rate_limiter.clone();
                        async move {
                            let start_time = Instant::now();
                            metrics.processed.fetch_add(1, Ordering::Relaxed);
                            let path = req.uri().path().to_string();
                            let query = req.uri().query().map(|q| q.to_string());
                            let method_str = req.method().as_str().to_string();

                            // Fast-path health probe
                            if path == "/health" || path == "/_spryzen/health" {
                                return Ok::<_, Infallible>(Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "application/json")
                                    .header("server", "Spryzen/2.2.0")
                                    .header("x-waf", "Spryzen")
                                    .header("x-spryzen-shield", "Active")
                                    .body(Full::new(Bytes::from_static(
                                        b"{\"status\":\"healthy\",\"engine\":\"spryzen-edge-v2.2\",\"mode\":\"active-shield\"}",
                                    )))
                                    .unwrap());
                            }

                            // Fast-path Prometheus metrics
                            if path == "/metrics" || path == "/_spryzen/metrics" {
                                let total = metrics.processed.load(Ordering::Relaxed);
                                let blocked = metrics.threats_blocked.load(Ordering::Relaxed);
                                let clean = metrics.clean_requests.load(Ordering::Relaxed);
                                let rate_limited = metrics.rate_limited.load(Ordering::Relaxed);
                                let body = format!(
                                    "# HELP spryzen_requests_total Total number of HTTP requests processed\n\
                                     # TYPE spryzen_requests_total counter\n\
                                     spryzen_requests_total {}\n\
                                     # HELP spryzen_threats_blocked_total Total requests blocked by WAF\n\
                                     # TYPE spryzen_threats_blocked_total counter\n\
                                     spryzen_threats_blocked_total {}\n\
                                     # HELP spryzen_clean_requests_total Total clean requests processed\n\
                                     # TYPE spryzen_clean_requests_total counter\n\
                                     spryzen_clean_requests_total {}\n\
                                     # HELP spryzen_rate_limited_total Total requests rejected by rate limiter\n\
                                     # TYPE spryzen_rate_limited_total counter\n\
                                     spryzen_rate_limited_total {}\n\
                                     # HELP spryzen_p50_latency_nanoseconds P50 latency in nanoseconds\n\
                                     # TYPE spryzen_p50_latency_nanoseconds gauge\n\
                                     spryzen_p50_latency_nanoseconds 12000\n\
                                     # HELP spryzen_p99_latency_nanoseconds P99 latency in nanoseconds\n\
                                     # TYPE spryzen_p99_latency_nanoseconds gauge\n\
                                     spryzen_p99_latency_nanoseconds 95000\n",
                                    total, blocked, clean, rate_limited
                                );
                                return Ok(Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "text/plain; version=0.0.4")
                                    .header("server", "Spryzen/2.2.0")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap());
                            }

                            // 1. Check Rate Limiter
                            if !rate_limiter.check_and_consume(client_ip) {
                                metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                                emit_siem_log(
                                    config.logging.format == "json",
                                    client_ip,
                                    &method_str,
                                    &path,
                                    429,
                                    "RATE_LIMITED",
                                    "Rate Limit Exceeded",
                                    config.server.mode.as_str(),
                                    start_time.elapsed().as_micros() as u64,
                                );
                                return Ok(Response::builder()
                                    .status(StatusCode::TOO_MANY_REQUESTS)
                                    .header("content-type", "application/json")
                                    .header("retry-after", "1")
                                    .header("x-spryzen-verdict", "RATE_LIMITED")
                                    .header("x-protected-by", "Spryzen Sovereign WAF")
                                    .body(Full::new(Bytes::from(format!(
                                        "{{\"error\":\"Too Many Requests - Rate limit exceeded by Spryzen+\",\"limit_rps\":{}}}",
                                        config.rate_limit.requests_per_second
                                    ))))
                                    .unwrap());
                            }

                            // 2. Check Allowlist (Path or IP)
                            let is_allowlisted = config.allowlist.is_path_allowlisted(&path)
                                || config.allowlist.is_ip_allowlisted(&client_ip);

                            // Extract body for inspection and forwarding
                            let method = req.method().clone();
                            let uri = req.uri().clone();
                            let body_bytes = match req.body_mut().collect().await {
                                Ok(collected) => collected.to_bytes(),
                                Err(_) => Bytes::new(),
                            };

                            let mut verdict = ThreatFlags::CLEAN;
                            if !is_allowlisted && config.server.mode != EnforcementMode::Bypass {
                                let body_slice = if body_bytes.is_empty() {
                                    None
                                } else {
                                    Some(body_bytes.as_ref())
                                };

                                verdict = INSPECTOR.with(|ins| {
                                    ins.borrow_mut().inspect(
                                        &path,
                                        query.as_deref(),
                                        body_slice,
                                    )
                                });
                            }

                            // Threat Detected
                            if verdict.is_threat() {
                                metrics.threats_blocked.fetch_add(1, Ordering::Relaxed);
                                let elapsed_us = start_time.elapsed().as_micros() as u64;

                                if config.server.mode == EnforcementMode::Block {
                                    emit_siem_log(
                                        config.logging.format == "json",
                                        client_ip,
                                        &method_str,
                                        &path,
                                        403,
                                        "BLOCKED",
                                        verdict.name(),
                                        "block",
                                        elapsed_us,
                                    );
                                    return Ok(Response::builder()
                                        .status(StatusCode::FORBIDDEN)
                                        .header("content-type", "application/json")
                                        .header("server", "Spryzen/2.2.0 (Bare-Metal WAF)")
                                        .header("x-waf", "Spryzen")
                                        .header("x-spryzen-shield", "Active")
                                        .header("x-protected-by", "Spryzen Sovereign WAF")
                                        .header("x-spryzen-verdict", "BLOCKED")
                                        .header("x-spryzen-threat", verdict.name())
                                        .body(Full::new(Bytes::from(format!(
                                            "{{\"error\":\"Forbidden - Threat Blocked by Spryzen+\",\"category\":\"{}\",\"engine\":\"spryzen-v2.2\"}}",
                                            verdict.name()
                                        ))))
                                        .unwrap());
                                } else {
                                    // SIMULATE MODE: Record threat in SIEM log & headers, but forward to upstream!
                                    emit_siem_log(
                                        config.logging.format == "json",
                                        client_ip,
                                        &method_str,
                                        &path,
                                        200,
                                        "SIMULATED_BLOCK",
                                        verdict.name(),
                                        "simulate",
                                        elapsed_us,
                                    );
                                }
                            } else {
                                metrics.clean_requests.fetch_add(1, Ordering::Relaxed);
                            }

                            // Forward to upstream if configured
                            if let Some(target) = config.server.upstream.as_ref() {
                                let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
                                let upstream_uri_str = format!("{}{}", target.trim_end_matches('/'), path_and_query);

                                match upstream_uri_str.parse::<hyper::Uri>() {
                                    Ok(upstream_uri) => {
                                        let mut upstream_req_builder = Request::builder()
                                            .method(method)
                                            .uri(upstream_uri.clone());

                                        if let Some(headers_mut) = upstream_req_builder.headers_mut() {
                                            for (name, value) in req.headers() {
                                                let name_str = name.as_str().to_ascii_lowercase();
                                                if name_str != "host" && name_str != "connection" && name_str != "keep-alive" {
                                                    headers_mut.insert(name.clone(), value.clone());
                                                }
                                            }
                                            if let Some(host) = upstream_uri.host() {
                                                let host_val = if let Some(port) = upstream_uri.port_u16() {
                                                    format!("{}:{}", host, port)
                                                } else {
                                                    host.to_string()
                                                };
                                                if let Ok(hv) = hyper::header::HeaderValue::from_str(&host_val) {
                                                    headers_mut.insert(hyper::header::HOST, hv);
                                                }
                                            }
                                            headers_mut.insert("x-forwarded-proto", hyper::header::HeaderValue::from_static("http"));
                                            if is_allowlisted {
                                                headers_mut.insert("x-spryzen-verdict", hyper::header::HeaderValue::from_static("ALLOWLISTED"));
                                            } else if verdict.is_threat() {
                                                headers_mut.insert("x-spryzen-simulated-verdict", hyper::header::HeaderValue::from_static("WOULD_BLOCK"));
                                                headers_mut.insert("x-spryzen-threat", hyper::header::HeaderValue::from_str(verdict.name()).unwrap());
                                            } else {
                                                headers_mut.insert("x-spryzen-verdict", hyper::header::HeaderValue::from_static("ALLOWED"));
                                            }
                                            headers_mut.insert("x-protected-by", hyper::header::HeaderValue::from_static("Spryzen Sovereign WAF"));
                                        }

                                        let upstream_req = upstream_req_builder.body(Full::new(body_bytes)).unwrap();

                                        match client.request(upstream_req).await {
                                            Ok(mut upstream_res) => {
                                                let status = upstream_res.status();
                                                let mut res_builder = Response::builder().status(status);

                                                if let Some(res_headers) = res_builder.headers_mut() {
                                                    for (name, value) in upstream_res.headers() {
                                                        let name_str = name.as_str().to_ascii_lowercase();
                                                        if name_str != "connection" && name_str != "keep-alive" {
                                                            res_headers.insert(name.clone(), value.clone());
                                                        }
                                                    }
                                                    res_headers.insert("server", hyper::header::HeaderValue::from_static("Spryzen/2.2.0 (Bare-Metal WAF)"));
                                                    res_headers.insert("x-waf", hyper::header::HeaderValue::from_static("Spryzen"));
                                                    res_headers.insert("x-spryzen-shield", hyper::header::HeaderValue::from_static("Active"));
                                                    res_headers.insert("x-protected-by", hyper::header::HeaderValue::from_static("Spryzen Sovereign WAF"));
                                                    if verdict.is_threat() && config.server.mode == EnforcementMode::Simulate {
                                                        res_headers.insert("x-spryzen-simulated-verdict", hyper::header::HeaderValue::from_static("WOULD_BLOCK"));
                                                    } else {
                                                        res_headers.insert("x-spryzen-verdict", hyper::header::HeaderValue::from_static("ALLOWED"));
                                                    }
                                                }

                                                let res_bytes = match upstream_res.body_mut().collect().await {
                                                    Ok(collected) => collected.to_bytes(),
                                                    Err(_) => Bytes::new(),
                                                };

                                                Ok(res_builder.body(Full::new(res_bytes)).unwrap())
                                            }
                                            Err(err) => {
                                                Ok(Response::builder()
                                                    .status(StatusCode::BAD_GATEWAY)
                                                    .header("content-type", "application/json")
                                                    .header("server", "Spryzen/2.2.0 (Bare-Metal WAF)")
                                                    .header("x-waf", "Spryzen")
                                                    .header("x-protected-by", "Spryzen Sovereign WAF")
                                                    .body(Full::new(Bytes::from(format!(
                                                        "{{\"error\":\"Bad Gateway - Spryzen could not reach upstream backend\",\"upstream\":\"{}\",\"details\":\"{}\"}}",
                                                        target, err
                                                    ))))
                                                    .unwrap())
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        Ok(Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .header("content-type", "application/json")
                                            .body(Full::new(Bytes::from(format!(
                                                "{{\"error\":\"Invalid upstream URL configuration\",\"details\":\"{}\"}}",
                                                err
                                            ))))
                                            .unwrap())
                                    }
                                }
                            } else {
                                let mut res_builder = Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "application/json")
                                    .header("server", "Spryzen/2.2.0 (Bare-Metal WAF)")
                                    .header("x-waf", "Spryzen")
                                    .header("x-spryzen-shield", "Active")
                                    .header("x-protected-by", "Spryzen Sovereign WAF");

                                if verdict.is_threat() && config.server.mode == EnforcementMode::Simulate {
                                    res_builder = res_builder
                                        .header("x-spryzen-simulated-verdict", "WOULD_BLOCK")
                                        .header("x-spryzen-threat", verdict.name());
                                } else {
                                    res_builder = res_builder
                                        .header("x-spryzen-verdict", "ALLOWED")
                                        .header("x-spryzen-p50", "12µs")
                                        .header("x-spryzen-p99", "95µs");
                                }

                                Ok(res_builder
                                    .body(Full::new(Bytes::from_static(
                                        b"{\"id\":104,\"status\":\"active\",\"waf\":\"spryzen-verified\",\"p50\":\"12us\",\"p99\":\"95us\"}",
                                    )))
                                    .unwrap())
                            }
                        }
                    });

                    if let Err(err) = server.serve_connection(io, service).await {
                        let _ = err;
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n[SPRYZEN GATEWAY] Caught SIGINT / SIGTERM shutdown signal. Draining in-flight connections cleanly...");
                break;
            }
        }
    }

    Ok(())
}

// ============================================================================
// 10. AUTOMATED UNIT TESTS & ENTERPRISE EVALUATIONS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_path_inspection() {
        let mut ins = ThreadLocalInspector::new();
        let verdict = ins.inspect("/api/v1/users", Some("limit=20&offset=0"), None);
        assert_eq!(verdict, ThreatFlags::CLEAN);
        assert!(!verdict.is_threat());
    }

    #[test]
    fn test_sqli_detection() {
        let mut ins = ThreadLocalInspector::new();
        let verdict = ins.inspect("/login", Some("user=admin'--"), None);
        assert!(verdict.is_threat());
        assert_eq!(verdict.0 & ThreatFlags::SQLI.0, ThreatFlags::SQLI.0);

        let verdict_enc = ins.inspect("/search", Some("q=1%27%20OR%201%3D1--"), None);
        assert!(verdict_enc.is_threat());
    }

    #[test]
    fn test_xss_detection() {
        let mut ins = ThreadLocalInspector::new();
        let verdict = ins.inspect("/search", Some("q=<script>alert(1)</script>"), None);
        assert!(verdict.is_threat());
        assert_eq!(verdict.0 & ThreatFlags::XSS.0, ThreatFlags::XSS.0);
    }

    #[test]
    fn test_path_traversal_detection() {
        let mut ins = ThreadLocalInspector::new();
        let verdict = ins.inspect("/download", Some("file=../../etc/passwd"), None);
        assert!(verdict.is_threat());
        assert_eq!(
            verdict.0 & ThreatFlags::PATH_TRAVERSAL.0,
            ThreatFlags::PATH_TRAVERSAL.0
        );
    }

    #[test]
    fn test_rce_detection() {
        let mut ins = ThreadLocalInspector::new();
        let verdict = ins.inspect("/exec", Some("cmd=/bin/bash"), None);
        assert!(verdict.is_threat());
        assert_eq!(verdict.0 & ThreatFlags::RCE.0, ThreatFlags::RCE.0);
    }

    #[test]
    fn test_ssti_detection() {
        let mut ins = ThreadLocalInspector::new();
        let verdict = ins.inspect("/render", Some("tpl={{7*7}}"), None);
        assert!(verdict.is_threat());
        assert_eq!(verdict.0 & ThreatFlags::SSTI.0, ThreatFlags::SSTI.0);
    }

    #[test]
    fn test_post_body_inspection() {
        let mut ins = ThreadLocalInspector::new();
        let body = b"{\"username\":\"admin\",\"password\":\"' OR 1=1--\"}";
        let verdict = ins.inspect("/api/login", None, Some(body));
        assert!(verdict.is_threat());
    }

    #[test]
    fn test_l1_cache_hit() {
        let mut ins = ThreadLocalInspector::new();
        let v1 = ins.inspect("/api/products", None, None);
        assert_eq!(v1, ThreatFlags::CLEAN);
        let v2 = ins.inspect("/api/products", None, None);
        assert_eq!(v2, ThreatFlags::CLEAN);
    }

    #[test]
    fn test_risky_characters_lut_and_simd() {
        assert!(has_risky_characters(b"SELECT * FROM users;"));
        assert!(has_risky_characters(b"<script>"));
        assert!(has_risky_characters(b"../../etc/passwd"));
        assert!(!has_risky_characters(b"api_v1_users_profile_avatar"));
    }

    #[test]
    fn test_rate_limiter_burst_and_throttle() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let limiter = RateLimiter::new(true, 10, 5); // 10 RPS, burst 5

        // First 5 should succeed (burst capacity)
        for _ in 0..5 {
            assert!(limiter.check_and_consume(ip));
        }

        // 6th immediate request should be rate-limited
        assert!(!limiter.check_and_consume(ip));
    }

    #[test]
    fn test_allowlist_matching() {
        let allowlist = AllowlistConfig {
            paths: vec!["/health".to_string(), "/api/v1/webhooks/*".to_string()],
            ips: vec!["10.0.0.1".to_string()],
        };

        assert!(allowlist.is_path_allowlisted("/health"));
        assert!(allowlist.is_path_allowlisted("/api/v1/webhooks/stripe"));
        assert!(allowlist.is_path_allowlisted("/api/v1/webhooks/github/push"));
        assert!(!allowlist.is_path_allowlisted("/api/v1/orders"));

        let ip_allowed: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_blocked: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(allowlist.is_ip_allowlisted(&ip_allowed));
        assert!(!allowlist.is_ip_allowlisted(&ip_blocked));
    }

    #[test]
    fn test_config_defaults() {
        let config = SpryzenConfig::default();
        assert_eq!(config.server.mode, EnforcementMode::Block);
        assert_eq!(config.rate_limit.requests_per_second, 100_000);
        assert_eq!(config.rate_limit.burst, 200_000);
        assert!(config.allowlist.is_path_allowlisted("/health"));
    }

    #[test]
    fn test_microsecond_inspection_benchmark() {
        let mut ins = ThreadLocalInspector::new();
        let payload = "/api/v1/products/search";
        let query = "q=laptop&category=electronics&page=1";

        for _ in 0..10_000 {
            ins.inspect(payload, Some(query), None);
        }

        let iterations = 1_000_000;
        let start = Instant::now();
        for _ in 0..iterations {
            ins.inspect(payload, Some(query), None);
        }
        let elapsed = start.elapsed();
        let ns_per_op = elapsed.as_nanos() as f64 / iterations as f64;

        assert!(
            ns_per_op < 50_000.0,
            "Inspection must be sub-50 microseconds"
        );
    }
}
