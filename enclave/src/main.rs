// SPDX-License-Identifier: MIT OR Apache-2.0

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use vsock::{VsockAddr, VsockListener, VsockStream};

mod aliyun_helper;
mod egress_boring;
mod egress_openssl;
mod egress_rustls_aws_lc;
mod evidence;
#[cfg(feature = "nitro")]
mod evidence_nitro;
#[cfg(feature = "qingtian")]
mod evidence_qingtian;
mod h2_client;
use crate::evidence::EvidenceProvider;
use attest::tls_profile;

trait ReadWrite: Read + Write {}
impl<T: Read + Write + ?Sized> ReadWrite for T {}

enum EgressStream {
    DirectVsock(VsockStream),
    QProxyTcp(TcpStream),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EgressMode {
    DirectVsock,
    QProxyTcp,
}

impl Read for EgressStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::DirectVsock(s) => s.read(buf),
            Self::QProxyTcp(s) => s.read(buf),
        }
    }
}

impl Write for EgressStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::DirectVsock(s) => s.write(buf),
            Self::QProxyTcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::DirectVsock(s) => s.flush(),
            Self::QProxyTcp(s) => s.flush(),
        }
    }
}

fn log_stderr(args: fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr(), "{args}");
}

macro_rules! elog {
    ($($arg:tt)*) => {
        log_stderr(format_args!($($arg)*))
    };
}

fn decode_profile(head: &ReqHead) -> Option<tls_profile::TlsProfile> {
    tls_profile::decode(&B64.decode(head.tls_spec.as_deref()?).ok()?).ok()
}

fn parse_parent_cid_candidates(raw: Option<&str>) -> Result<Vec<u32>, String> {
    let Some(raw) = raw else {
        return Ok(vec![DEFAULT_PARENT_CID]);
    };
    let mut cids = Vec::new();
    for part in raw.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        let cid = item
            .parse::<u32>()
            .map_err(|e| format!("invalid parent CID `{item}` in POO_PARENT_CIDS: {e}"))?;
        if !cids.contains(&cid) {
            cids.push(cid);
        }
    }
    if cids.is_empty() {
        return Err("POO_PARENT_CIDS/POO_PARENT_CID did not contain any CID".into());
    }
    Ok(cids)
}

fn parent_cid_candidates() -> Result<Vec<u32>, String> {
    let raw = env::var("POO_PARENT_CIDS")
        .ok()
        .or_else(|| env::var("POO_PARENT_CID").ok());
    parse_parent_cid_candidates(raw.as_deref())
}

fn connect_parent_vsock(port: u32) -> Result<VsockStream, String> {
    let cids = parent_cid_candidates()?;
    let mut errors = Vec::new();
    for cid in &cids {
        match VsockStream::connect(&VsockAddr::new(*cid, port)) {
            Ok(sock) => return Ok(sock),
            Err(e) => errors.push(format!("{cid}: {e}")),
        }
    }
    Err(format!(
        "连 vsock-proxy 失败: tried parent CID(s) [{}] on port {port}; {}",
        cids.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(","),
        errors.join("; ")
    ))
}

fn qproxy_host() -> String {
    env::var("POO_QPROXY_HOST")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

fn connect_qproxy_tcp(port: u32) -> Result<TcpStream, String> {
    let port: u16 = port
        .try_into()
        .map_err(|_| format!("qproxy local TCP port out of range: {port}"))?;
    let addr = (qproxy_host(), port);
    TcpStream::connect(addr.clone())
        .map_err(|e| format!("连 qproxy enclave 失败: {}:{}; {e}", addr.0, addr.1))
}

fn parse_egress_mode(raw: Option<&str>) -> Result<EgressMode, String> {
    match raw
        .unwrap_or("direct-vsock")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "qproxy" | "qproxy-tcp" => Ok(EgressMode::QProxyTcp),
        "direct-vsock" | "vsock" | "" => Ok(EgressMode::DirectVsock),
        other => Err(format!(
            "unsupported POO_EGRESS_MODE={other}; supported: direct-vsock, qproxy"
        )),
    }
}

fn egress_mode() -> Result<EgressMode, String> {
    let raw = env::var("POO_EGRESS_MODE").ok();
    parse_egress_mode(raw.as_deref())
}

fn connect_egress(port: u32) -> Result<EgressStream, String> {
    match egress_mode()? {
        EgressMode::QProxyTcp => connect_qproxy_tcp(port).map(EgressStream::QProxyTcp),
        EgressMode::DirectVsock => connect_parent_vsock(port).map(EgressStream::DirectVsock),
    }
}

fn set_egress_timeouts(sock: &EgressStream, timeout: Duration) {
    match sock {
        EgressStream::DirectVsock(s) => {
            s.set_read_timeout(Some(timeout)).ok();
            s.set_write_timeout(Some(timeout)).ok();
        }
        EgressStream::QProxyTcp(s) => {
            s.set_read_timeout(Some(timeout)).ok();
            s.set_write_timeout(Some(timeout)).ok();
        }
    }
}

const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
const DEFAULT_PARENT_CID: u32 = 3;
const PORT: u32 = 5005;
const DOMAIN_V2: &str = "tee-exchange-v2";

#[derive(Debug, Deserialize)]
struct FieldPolicyRegistry {
    #[serde(rename = "default")]
    _default_version: String,
    protocol_versions: BTreeMap<String, String>,
}

static FIELD_POLICY_REGISTRY: OnceLock<FieldPolicyRegistry> = OnceLock::new();
const SUPPORTED_PROTOCOLS: &[&str] = &[
    "openai.chat_completions",
    "openai.responses",
    "anthropic.messages",
    "google.gemini.generate_content",
    "alibaba.dashscope.generation",
    "aws.bedrock.converse",
    "cohere.chat",
];

fn field_policy_registry() -> &'static FieldPolicyRegistry {
    FIELD_POLICY_REGISTRY.get_or_init(|| {
        let registry: FieldPolicyRegistry =
            serde_json::from_str(include_str!("../field-policy-registry.json"))
                .expect("parse field policy registry");
        for protocol in SUPPORTED_PROTOCOLS {
            let version = registry.protocol_versions.get(*protocol);
            assert!(
                matches!(version, Some(v) if !v.is_empty()),
                "field policy registry missing supported protocol: {}",
                protocol
            );
        }
        registry
    })
}

fn field_policy_version(protocol: &str) -> String {
    let registry = field_policy_registry();
    registry
        .protocol_versions
        .get(protocol)
        .cloned()
        .unwrap_or_else(|| panic!("missing field policy version for supported protocol: {protocol}"))
}

const MAX_HEAD: usize = 64 * 1024;
const MAX_RESP: usize = 64 * 1024 * 1024;
const MAX_FIELD_CLAIMS_CAPTURE: usize = 8 * 1024 * 1024;
const MAX_STREAM_SNIFF_BYTES: usize = 4 * 1024;
const MAX_AWS_EVENTSTREAM_MESSAGE: usize = 1024 * 1024;
const MAX_REQ_HEAD: usize = 1024 * 1024;
const MAX_REQ_FRAME: usize = 64 * 1024 * 1024;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(300);
const UPSTREAM_IO_TIMEOUT: Duration = Duration::from_secs(300);
const ADMIN_TIMEOUT: Duration = Duration::from_secs(2);

const N_WORKERS: usize = 64;
const QUEUE_CAP: usize = 256;
const METRICS_PORT: u32 = 5006;
const DEFAULT_ALIYUN_HELPER_SOCKET: &str = "/run/aliyun-proof-helper.sock";

const REQ_HEAD: u8 = 0x01;
const REQ_BODY: u8 = 0x02;
const RESP_HEAD: u8 = 0x10;
const RESP_CHUNK: u8 = 0x11;
const RESP_TRAILER: u8 = 0x12;
const STATS: u8 = 0x20;
const ERR: u8 = 0x1f;

#[derive(Deserialize)]
struct Upstream {
    host: String,
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    // Ordered, case-preserving outgoing header template. When present it takes
    // precedence over `headers`: headers are emitted verbatim in this exact order
    // and case. `authorization` / `content-length` entries are empty-value
    // sentinels filled in here (token / actual body length). Loosely typed: each
    // item must be exactly [name, value], otherwise it is rejected and the build
    // falls back to the `headers` map path.
    #[serde(default, rename = "headersOrdered")]
    headers_ordered: Option<Vec<Vec<String>>>,
}

#[derive(Deserialize)]
struct ReqHead {
    nonce: String,
    egress_port: u32,
    upstream: Upstream,
    token: Option<String>,
    #[serde(default)]
    client_protocol_family: Option<String>,
    #[serde(default)]
    downstream_protocol_family: Option<String>,
    #[serde(default)]
    protocol_family: Option<String>,
    #[serde(default)]
    tls_seed: Option<String>,
    #[serde(default)]
    tls_spec: Option<String>,
}

fn read_frame<R: Read>(r: &mut R, max: usize) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr)?;
    let t = hdr[0];
    let n = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if n > max {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "请求帧超过上限",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok((t, buf))
}

fn write_frame<W: Write>(w: &mut W, t: u8, data: &[u8]) -> std::io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = t;
    hdr[1..].copy_from_slice(&(data.len() as u32).to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(data)?;
    Ok(())
}

struct AttestedH2Sink<'a> {
    control: &'a mut VsockStream,
    hasher: Sha256,
    field_collector: Option<FieldResponseCollector>,
    head: &'a ReqHead,
    req_body: &'a [u8],
    content_type: String,
}

impl h2_client::H2ResponseSink for AttestedH2Sink<'_> {
    fn on_head(&mut self, status: u16, headers: &[(String, String)]) -> Result<(), String> {
        let mut response_headers = serde_json::Map::new();
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("content-type") {
                self.content_type = value.clone();
            }
            response_headers.insert(name.clone(), Value::String(value.clone()));
        }
        self.field_collector =
            FieldResponseCollector::new(self.head, self.req_body, &self.content_type);
        write_frame(
            self.control,
            RESP_HEAD,
            json!({ "status": status, "headers": Value::Object(response_headers) })
                .to_string()
                .as_bytes(),
        )
        .map_err(|e| format!("写 h2 RESP_HEAD: {e}"))
    }

    fn on_chunk(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.hasher.update(chunk);
        if let Some(collector) = self.field_collector.as_mut() {
            collector.push(chunk);
        }
        write_frame(self.control, RESP_CHUNK, chunk).map_err(|e| format!("写 h2 RESP_CHUNK: {e}"))
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn no_crlf(s: &str) -> bool {
    !s.bytes().any(|b| b == b'\r' || b == b'\n')
}

fn path_no_query(p: &str) -> &str {
    match p.find('?') {
        Some(i) => &p[..i],
        None => p,
    }
}

fn canonical_json(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap(),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut parts = Vec::with_capacity(keys.len());
            for k in keys {
                parts.push(format!(
                    "{}:{}",
                    serde_json::to_string(k).unwrap(),
                    canonical_json(&map[k])
                ));
            }
            format!("{{{}}}", parts.join(","))
        }
    }
}

fn field_claims_sha256_hex(field_claims: &Value) -> String {
    sha256_hex(canonical_json(field_claims).as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn build_v2_statement(
    nonce_b64: &str,
    upstream_host: &str,
    upstream_path: &str,
    http_method: &str,
    http_status: u16,
    resp_content_type: &str,
    request_body_sha256_hex: &str,
    response_body_sha256_hex: &str,
    field_claims: Option<&Value>,
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(DOMAIN_V2);
    out.push('\n');
    out.push_str(&format!("nonce={}\n", nonce_b64));
    out.push_str(&format!("upstream-host={}\n", upstream_host.to_lowercase()));
    out.push_str(&format!("upstream-path={}\n", path_no_query(upstream_path)));
    out.push_str(&format!("http-method={}\n", http_method.to_uppercase()));
    out.push_str(&format!("http-status={}\n", http_status));
    out.push_str(&format!("resp-content-type={}\n", resp_content_type));
    out.push_str(&format!(
        "request-body-sha256={}\n",
        request_body_sha256_hex
    ));
    out.push_str(&format!(
        "response-body-sha256={}\n",
        response_body_sha256_hex
    ));
    if let Some(claims) = field_claims {
        out.push_str(&format!(
            "field-claims-sha256={}\n",
            field_claims_sha256_hex(claims)
        ));
    }
    out.into_bytes()
}

fn detect_protocol_family(
    host: &str,
    path: &str,
    body: &[u8],
    enhanced: Option<&str>,
    configured: Option<&str>,
) -> Option<&'static str> {
    let h = host.to_ascii_lowercase();
    let p = path_no_query(path).to_ascii_lowercase();
    if p.contains("/chat/completions") {
        return Some("openai.chat_completions");
    }
    if p.ends_with("/responses") || p.contains("/responses") {
        return Some("openai.responses");
    }
    if p.ends_with("/messages") || h.contains("anthropic") {
        return Some("anthropic.messages");
    }
    if p.contains(":generatecontent") || p.contains("generatecontent") {
        return Some("google.gemini.generate_content");
    }
    if p.contains("/services/aigc/text-generation/generation") {
        return Some("alibaba.dashscope.generation");
    }
    if p.contains("/converse") {
        return Some("aws.bedrock.converse");
    }
    if p.ends_with("/chat") || p.contains("/v2/chat") || h.contains("cohere") {
        return Some("cohere.chat");
    }
    if let Some(protocol) = enhanced.and_then(normalize_protocol_family) {
        return Some(protocol);
    }
    if let Some(protocol) = configured.and_then(normalize_protocol_family) {
        return Some(protocol);
    }
    let parsed: Value = serde_json::from_slice(body).ok()?;
    if parsed.get("messages").and_then(Value::as_array).is_some()
        && parsed.get("model").and_then(Value::as_str).is_some()
        && parsed.get("max_tokens").is_some()
    {
        return Some("anthropic.messages");
    }
    if parsed.get("messages").and_then(Value::as_array).is_some()
        && parsed.get("model").and_then(Value::as_str).is_some()
    {
        return Some("openai.chat_completions");
    }
    if parsed.get("input").is_some() && parsed.get("model").and_then(Value::as_str).is_some() {
        return Some("openai.responses");
    }
    if parsed.get("contents").is_some() {
        return Some("google.gemini.generate_content");
    }
    None
}

fn normalize_protocol_family(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "openai.chat_completions" => Some("openai.chat_completions"),
        "openai.responses" => Some("openai.responses"),
        "anthropic.messages" => Some("anthropic.messages"),
        "google.gemini.generate_content" => Some("google.gemini.generate_content"),
        "alibaba.dashscope.generation" => Some("alibaba.dashscope.generation"),
        "aws.bedrock.converse" => Some("aws.bedrock.converse"),
        "cohere.chat" => Some("cohere.chat"),
        _ => None,
    }
}

fn field_view(protocol: &str, kind: &str, body: &[u8], upstream_path: Option<&str>) -> Value {
    let parsed = if looks_like_sse(body) {
        parse_sse_data(body)
    } else {
        parse_json_body(body)
    };
    match (protocol, kind) {
        ("openai.chat_completions", "request") => pick_value(
            &parsed,
            &[
                "model",
                "messages",
                "tools",
                "tool_choice",
                "response_format",
                "temperature",
                "top_p",
                "max_tokens",
                "max_completion_tokens",
                "presence_penalty",
                "frequency_penalty",
                "parallel_tool_calls",
                "stop",
                "seed",
                "stream",
                "user",
                "reasoning_effort",
                "service_tier",
                "modalities",
                "audio",
            ],
        ),
        ("openai.chat_completions", "response") => {
            if parsed.is_array() {
                aggregate_openai_chat_stream(&parsed)
            } else {
                pick_value(
                    &parsed,
                    &[
                        "model",
                        "choices",
                        "usage",
                        "error",
                        "system_fingerprint",
                        "service_tier",
                    ],
                )
            }
        }
        ("openai.responses", "request") => pick_value(
            &parsed,
            &[
                "model",
                "input",
                "tools",
                "tool_choice",
                "temperature",
                "top_p",
                "max_output_tokens",
                "stream",
                "parallel_tool_calls",
                "truncation",
                "text",
                "metadata",
                "reasoning",
                "store",
                "include",
            ],
        ),
        ("openai.responses", "response") => openai_responses_view("response", &parsed),
        ("anthropic.messages", _) => anthropic_messages_view(kind, &parsed),
        ("google.gemini.generate_content", "request") => pick_value(
            &parsed,
            &[
                "contents",
                "systemInstruction",
                "tools",
                "toolConfig",
                "generationConfig",
                "safetySettings",
                "model",
                "cachedContent",
                "labels",
                "thinkingConfig",
            ],
        ),
        ("google.gemini.generate_content", "response") => {
            gemini_generate_content_view("response", &parsed)
        }
        ("alibaba.dashscope.generation", "request") => pick_value(
            &parsed,
            &[
                "model",
                "input",
                "parameters",
                "system",
                "messages",
                "response_format",
                "thinking_budget",
            ],
        ),
        ("alibaba.dashscope.generation", "response") => {
            dashscope_generation_view("response", &parsed)
        }
        ("aws.bedrock.converse", "request") => {
            bedrock_converse_request_view(&parsed, upstream_path)
        }
        ("aws.bedrock.converse", "response") => bedrock_converse_view("response", &parsed),
        ("cohere.chat", "request") => pick_value(
            &parsed,
            &[
                "model",
                "messages",
                "message",
                "tools",
                "tool_choice",
                "temperature",
                "p",
                "k",
                "max_tokens",
                "stop_sequences",
                "response_format",
                "stream",
                "documents",
                "safety_mode",
                "metadata",
            ],
        ),
        ("cohere.chat", "response") => cohere_chat_view("response", &parsed),
        _ => parsed,
    }
}

fn build_field_claims(
    head: &ReqHead,
    norm_method: &str,
    status: u16,
    req_body: &[u8],
    resp_body: &[u8],
) -> Option<Value> {
    let enhanced = head
        .client_protocol_family
        .as_deref()
        .or(head.downstream_protocol_family.as_deref());
    let configured_env = env::var("FIELD_PROOF_PROTOCOL_FAMILY").ok();
    let configured = head
        .protocol_family
        .as_deref()
        .or(configured_env.as_deref());
    let protocol = detect_protocol_family(
        &head.upstream.host,
        &head.upstream.path,
        req_body,
        enhanced,
        configured,
    )?;
    let req_view = field_view(protocol, "request", req_body, Some(&head.upstream.path));
    let resp_view = field_view(protocol, "response", resp_body, Some(&head.upstream.path));
    build_field_claims_from_views(
        head,
        norm_method,
        status,
        protocol,
        req_view,
        resp_view,
        looks_like_sse(resp_body),
    )
}

fn build_field_claims_from_views(
    head: &ReqHead,
    norm_method: &str,
    status: u16,
    protocol: &'static str,
    req_view: Value,
    resp_view: Value,
    streaming: bool,
) -> Option<Value> {
    if !has_required_presence(protocol, "request", &req_view) {
        return None;
    }
    if !has_required_presence(protocol, "response", &resp_view) {
        return None;
    }
    let request_fields_hash = sha256_hex(canonical_json(&req_view).as_bytes());
    let response_fields_hash = sha256_hex(canonical_json(&resp_view).as_bytes());
    let host = head.upstream.host.to_ascii_lowercase();
    let path = path_no_query(&head.upstream.path).to_string();
    Some(json!({
        "v": 1,
        "proof_type": "field-proof",
        "nonce": head.nonce,
        "protocol_family": protocol,
        "assurance_level": "strong",
        "verification_mode": "field_claims",
        "cross_protocol": false,
        "semantic_equivalence_not_proven": false,
        "request_schema_version": format!("{}.v1", protocol),
        "response_schema_version": format!("{}.v1", protocol),
        "upstream_host": host,
        "upstream_path": path,
        "http_method": norm_method.to_ascii_uppercase(),
        "http_status": status,
        "field_policy_id": format!("{}.default@{}", protocol, field_policy_version(protocol)),
        "upstream_request_fields_sha256": request_fields_hash,
        "upstream_response_fields_sha256": response_fields_hash,
        "request_body_sha256_severity": "advisory",
        "response_body_sha256_severity": "advisory",
        "body_hash_policy": "advisory",
        "streaming": streaming,
    }))
}

fn parse_json_body(body: &[u8]) -> Value {
    let trimmed = String::from_utf8_lossy(body).trim().to_string();
    if trimmed.is_empty() {
        return Value::Null;
    }
    serde_json::from_str(&trimmed).unwrap_or_else(|_| {
        json!({
            "raw_sha256": sha256_hex(body),
            "parse_error": "invalid_json"
        })
    })
}

fn parse_sse_data(body: &[u8]) -> Value {
    let text = String::from_utf8_lossy(body);
    let mut items = Vec::new();
    let mut data_lines: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            flush_sse_data(&mut data_lines, &mut items);
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.trim_start().to_string());
        }
    }
    flush_sse_data(&mut data_lines, &mut items);
    Value::Array(items)
}

fn flush_sse_data(data_lines: &mut Vec<String>, items: &mut Vec<Value>) {
    if data_lines.is_empty() {
        return;
    }
    let data = data_lines.join("\n");
    data_lines.clear();
    if data.trim().is_empty() || data.trim() == "[DONE]" {
        return;
    }
    let parsed = serde_json::from_str(&data).unwrap_or_else(|_| {
        json!({
            "raw_data_sha256": sha256_hex(data.as_bytes()),
            "parse_error": "invalid_sse_json"
        })
    });
    items.push(parsed);
}

fn looks_like_sse(body: &[u8]) -> bool {
    let n = body.len().min(512);
    let prefix = String::from_utf8_lossy(&body[..n]);
    prefix
        .lines()
        .any(|line| line.starts_with("data:") || line.starts_with("event:"))
}

fn is_sse_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(|v| v.trim().eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
}

fn is_aws_event_stream_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/vnd.amazon.eventstream")
        })
        .unwrap_or(false)
}

fn path_is_bedrock_converse_stream(path: &str) -> bool {
    path_no_query(path)
        .to_ascii_lowercase()
        .contains("/converse-stream")
}

fn path_indicates_gemini_stream(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("alt=sse")
        || lower.contains(":streamgeneratecontent")
        || lower.contains("/streamgeneratecontent")
}

fn request_indicates_streaming(protocol: &str, req_view: &Value, upstream_path: &str) -> bool {
    match protocol {
        "openai.chat_completions" | "openai.responses" | "anthropic.messages" | "cohere.chat" => {
            req_view
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }
        "alibaba.dashscope.generation" => req_view
            .get("parameters")
            .and_then(Value::as_object)
            .and_then(|p| p.get("stream"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "google.gemini.generate_content" => path_indicates_gemini_stream(upstream_path),
        "aws.bedrock.converse" => path_is_bedrock_converse_stream(upstream_path),
        _ => false,
    }
}

fn body_prefix_indicates_sse(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&body[..body.len().min(MAX_STREAM_SNIFF_BYTES)]);
    let trimmed = text.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    trimmed.starts_with("data:") || trimmed.starts_with("event:") || trimmed.starts_with(':')
}

enum FieldResponseBody {
    Streaming {
        parser: SseEventParser,
        state: StreamFieldState,
    },
    AwsEventStream {
        parser: AwsEventStreamParser,
        state: BedrockConverseStreamState,
    },
    Sniffing {
        body: Vec<u8>,
        truncated: bool,
        state: Option<StreamFieldState>,
    },
}

struct FieldResponseCollector {
    protocol: &'static str,
    req_view: Value,
    body: FieldResponseBody,
}

impl FieldResponseCollector {
    fn new(head: &ReqHead, req_body: &[u8], content_type: &str) -> Option<Self> {
        let enhanced = head
            .client_protocol_family
            .as_deref()
            .or(head.downstream_protocol_family.as_deref());
        let configured_env = env::var("FIELD_PROOF_PROTOCOL_FAMILY").ok();
        let configured = head
            .protocol_family
            .as_deref()
            .or(configured_env.as_deref());
        let protocol = detect_protocol_family(
            &head.upstream.host,
            &head.upstream.path,
            req_body,
            enhanced,
            configured,
        )?;
        let req_view = field_view(protocol, "request", req_body, Some(&head.upstream.path));
        if !has_required_presence(protocol, "request", &req_view) {
            return None;
        }
        let request_streaming =
            request_indicates_streaming(protocol, &req_view, &head.upstream.path);
        let body = if is_sse_content_type(content_type) {
            FieldResponseBody::Streaming {
                parser: SseEventParser::default(),
                state: StreamFieldState::new(protocol)?,
            }
        } else if protocol == "aws.bedrock.converse"
            && (is_aws_event_stream_content_type(content_type)
                || request_streaming
                || (content_type.is_empty()
                    && path_is_bedrock_converse_stream(&head.upstream.path)))
        {
            FieldResponseBody::AwsEventStream {
                parser: AwsEventStreamParser::default(),
                state: BedrockConverseStreamState::default(),
            }
        } else if request_streaming {
            FieldResponseBody::Streaming {
                parser: SseEventParser::default(),
                state: StreamFieldState::new(protocol)?,
            }
        } else {
            FieldResponseBody::Sniffing {
                body: Vec::new(),
                truncated: false,
                state: StreamFieldState::new(protocol),
            }
        };
        Some(Self {
            protocol,
            req_view,
            body,
        })
    }

    fn push(&mut self, chunk: &[u8]) {
        match &mut self.body {
            FieldResponseBody::Streaming { parser, state } => {
                parser.push(chunk, |event| state.apply(&event));
            }
            FieldResponseBody::AwsEventStream { parser, state } => {
                parser.push(chunk, |event| state.apply(&event));
            }
            FieldResponseBody::Sniffing {
                body,
                truncated,
                state,
            } => {
                capture_field_body(body, truncated, chunk);
                if state.is_some() && body_prefix_indicates_sse(body) {
                    let mut parser = SseEventParser::default();
                    let mut streaming_state = state.take().expect("checked above");
                    parser.push(body, |event| streaming_state.apply(&event));
                    self.body = FieldResponseBody::Streaming {
                        parser,
                        state: streaming_state,
                    };
                }
            }
        }
    }

    fn finish(mut self, head: &ReqHead, norm_method: &str, status: u16) -> Option<Value> {
        let (resp_view, streaming) = match &mut self.body {
            FieldResponseBody::Streaming { parser, state } => {
                parser.finish(|event| state.apply(&event));
                (state.finish(), true)
            }
            FieldResponseBody::AwsEventStream { parser, state } => {
                parser.finish(|event| state.apply(&event));
                if parser.failed {
                    return None;
                }
                (state.finish(), true)
            }
            FieldResponseBody::Sniffing {
                body, truncated, ..
            } => {
                if *truncated {
                    return None;
                }
                (
                    field_view(self.protocol, "response", body, Some(&head.upstream.path)),
                    false,
                )
            }
        };
        build_field_claims_from_views(
            head,
            norm_method,
            status,
            self.protocol,
            self.req_view,
            resp_view,
            streaming,
        )
    }
}

#[derive(Default)]
struct SseEventParser {
    pending: Vec<u8>,
    data_lines: Vec<String>,
}

impl SseEventParser {
    fn push<F: FnMut(Value)>(&mut self, chunk: &[u8], mut on_event: F) {
        self.pending.extend_from_slice(chunk);
        while let Some(pos) = self.pending.iter().position(|b| *b == b'\n') {
            let mut line = self.pending.drain(..=pos).collect::<Vec<u8>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.process_line(&line, &mut on_event);
        }
    }

    fn finish<F: FnMut(Value)>(&mut self, mut on_event: F) {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            self.process_line(&line, &mut on_event);
        }
        self.flush(&mut on_event);
    }

    fn process_line<F: FnMut(Value)>(&mut self, line: &[u8], on_event: &mut F) {
        if line.is_empty() {
            self.flush(on_event);
            return;
        }
        let text = String::from_utf8_lossy(line);
        if let Some(rest) = text.strip_prefix("data:") {
            self.data_lines.push(rest.trim_start().to_string());
        }
    }

    fn flush<F: FnMut(Value)>(&mut self, on_event: &mut F) {
        if self.data_lines.is_empty() {
            return;
        }
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        if data.trim().is_empty() || data.trim() == "[DONE]" {
            return;
        }
        let parsed = serde_json::from_str(&data).unwrap_or_else(|_| {
            json!({
                "raw_data_sha256": sha256_hex(data.as_bytes()),
                "parse_error": "invalid_sse_json"
            })
        });
        on_event(parsed);
    }
}

#[derive(Default)]
struct AwsEventStreamParser {
    pending: Vec<u8>,
    failed: bool,
}

impl AwsEventStreamParser {
    fn push<F: FnMut(Value)>(&mut self, chunk: &[u8], mut on_event: F) {
        if self.failed {
            return;
        }
        self.pending.extend_from_slice(chunk);
        loop {
            if self.pending.len() < 12 {
                return;
            }
            let total_len = u32::from_be_bytes([
                self.pending[0],
                self.pending[1],
                self.pending[2],
                self.pending[3],
            ]) as usize;
            let headers_len = u32::from_be_bytes([
                self.pending[4],
                self.pending[5],
                self.pending[6],
                self.pending[7],
            ]) as usize;
            if total_len < 16
                || total_len > MAX_AWS_EVENTSTREAM_MESSAGE
                || headers_len > total_len.saturating_sub(16)
            {
                self.failed = true;
                self.pending.clear();
                return;
            }
            if self.pending.len() < total_len {
                return;
            }
            let message = self.pending.drain(..total_len).collect::<Vec<u8>>();
            let payload_start = 12 + headers_len;
            let payload_end = total_len - 4;
            if payload_start > payload_end {
                continue;
            }
            let payload = &message[payload_start..payload_end];
            let trimmed = String::from_utf8_lossy(payload).trim().to_string();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(&trimmed) {
                Ok(parsed) => on_event(parsed),
                Err(_) => {
                    self.failed = true;
                    self.pending.clear();
                    return;
                }
            }
        }
    }

    fn finish<F: FnMut(Value)>(&mut self, _on_event: F) {
        if !self.pending.is_empty() {
            self.failed = true;
            self.pending.clear();
        }
    }
}

enum StreamFieldState {
    OpenAiChat(OpenAiChatStreamState),
    OpenAiResponses(OpenAiResponsesStreamState),
    AnthropicMessages(AnthropicMessagesStreamState),
    GeminiGenerateContent(GeminiGenerateContentStreamState),
    DashscopeGeneration(DashscopeGenerationStreamState),
    BedrockConverse(BedrockConverseStreamState),
    CohereChat(CohereChatStreamState),
}

impl StreamFieldState {
    fn new(protocol: &str) -> Option<Self> {
        match protocol {
            "openai.chat_completions" => Some(Self::OpenAiChat(Default::default())),
            "openai.responses" => Some(Self::OpenAiResponses(Default::default())),
            "anthropic.messages" => Some(Self::AnthropicMessages(Default::default())),
            "google.gemini.generate_content" => {
                Some(Self::GeminiGenerateContent(Default::default()))
            }
            "alibaba.dashscope.generation" => Some(Self::DashscopeGeneration(Default::default())),
            "aws.bedrock.converse" => Some(Self::BedrockConverse(Default::default())),
            "cohere.chat" => Some(Self::CohereChat(Default::default())),
            _ => None,
        }
    }

    fn apply(&mut self, event: &Value) {
        match self {
            Self::OpenAiChat(state) => state.apply(event),
            Self::OpenAiResponses(state) => state.apply(event),
            Self::AnthropicMessages(state) => state.apply(event),
            Self::GeminiGenerateContent(state) => state.apply(event),
            Self::DashscopeGeneration(state) => state.apply(event),
            Self::BedrockConverse(state) => state.apply(event),
            Self::CohereChat(state) => state.apply(event),
        }
    }

    fn finish(&mut self) -> Value {
        match self {
            Self::OpenAiChat(state) => state.finish(),
            Self::OpenAiResponses(state) => state.finish(),
            Self::AnthropicMessages(state) => state.finish(),
            Self::GeminiGenerateContent(state) => state.finish(),
            Self::DashscopeGeneration(state) => state.finish(),
            Self::BedrockConverse(state) => state.finish(),
            Self::CohereChat(state) => state.finish(),
        }
    }
}

#[derive(Default)]
struct OpenAiChatStreamState {
    out: serde_json::Map<String, Value>,
    choices: BTreeMap<i64, serde_json::Map<String, Value>>,
}

impl OpenAiChatStreamState {
    fn apply(&mut self, item: &Value) {
        let Some(chunk) = item.as_object() else {
            return;
        };
        if !self.out.contains_key("model") {
            if let Some(model) = chunk.get("model").and_then(Value::as_str) {
                self.out
                    .insert("model".into(), Value::String(model.to_string()));
            }
        }
        if let Some(usage) = chunk.get("usage") {
            self.out.insert("usage".into(), usage.clone());
        }
        if let Some(error) = chunk.get("error") {
            self.out.insert("error".into(), error.clone());
        }
        let Some(raw_choices) = chunk.get("choices").and_then(Value::as_array) else {
            return;
        };
        for raw_choice in raw_choices {
            let Some(choice_obj) = raw_choice.as_object() else {
                continue;
            };
            let index = choice_obj
                .get("index")
                .and_then(Value::as_i64)
                .unwrap_or(self.choices.len() as i64);
            let choice = self.choices.entry(index).or_insert_with(|| {
                let mut m = serde_json::Map::new();
                m.insert("index".into(), json!(index));
                m.insert("message".into(), Value::Object(serde_json::Map::new()));
                m
            });
            let mut message = choice
                .get("message")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if let Some(delta) = choice_obj.get("delta").and_then(Value::as_object) {
                merge_openai_chat_delta(&mut message, delta);
            }
            if let Some(full_message) = choice_obj.get("message").and_then(Value::as_object) {
                for (k, v) in full_message {
                    message.insert(k.clone(), v.clone());
                }
            }
            choice.insert("message".into(), Value::Object(message));
            if let Some(finish_reason) = choice_obj.get("finish_reason") {
                if !finish_reason.is_null() {
                    choice.insert("finish_reason".into(), finish_reason.clone());
                }
            }
            if let Some(logprobs) = choice_obj.get("logprobs") {
                choice.insert("logprobs".into(), logprobs.clone());
            }
        }
    }

    fn finish(&mut self) -> Value {
        if !self.choices.is_empty() {
            let choices = std::mem::take(&mut self.choices);
            self.out.insert(
                "choices".into(),
                Value::Array(choices.into_values().map(Value::Object).collect()),
            );
        }
        Value::Object(std::mem::take(&mut self.out))
    }
}

fn aggregate_openai_chat_stream(value: &Value) -> Value {
    let Some(items) = value.as_array() else {
        return pick_value(value, &["model", "choices", "usage", "error"]);
    };
    let mut out = serde_json::Map::new();
    let mut choices: BTreeMap<i64, serde_json::Map<String, Value>> = BTreeMap::new();
    for item in items {
        let Some(chunk) = item.as_object() else {
            continue;
        };
        if !out.contains_key("model") {
            if let Some(model) = chunk.get("model").and_then(Value::as_str) {
                out.insert("model".into(), Value::String(model.to_string()));
            }
        }
        if let Some(usage) = chunk.get("usage") {
            out.insert("usage".into(), usage.clone());
        }
        if let Some(error) = chunk.get("error") {
            out.insert("error".into(), error.clone());
        }
        let Some(raw_choices) = chunk.get("choices").and_then(Value::as_array) else {
            continue;
        };
        for raw_choice in raw_choices {
            let Some(choice_obj) = raw_choice.as_object() else {
                continue;
            };
            let index = choice_obj
                .get("index")
                .and_then(Value::as_i64)
                .unwrap_or(choices.len() as i64);
            let choice = choices.entry(index).or_insert_with(|| {
                let mut m = serde_json::Map::new();
                m.insert("index".into(), json!(index));
                m.insert("message".into(), Value::Object(serde_json::Map::new()));
                m
            });
            let mut message = choice
                .get("message")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if let Some(delta) = choice_obj.get("delta").and_then(Value::as_object) {
                merge_openai_chat_delta(&mut message, delta);
            }
            if let Some(full_message) = choice_obj.get("message").and_then(Value::as_object) {
                for (k, v) in full_message {
                    message.insert(k.clone(), v.clone());
                }
            }
            choice.insert("message".into(), Value::Object(message));
            if let Some(finish_reason) = choice_obj.get("finish_reason") {
                if !finish_reason.is_null() {
                    choice.insert("finish_reason".into(), finish_reason.clone());
                }
            }
            if let Some(logprobs) = choice_obj.get("logprobs") {
                choice.insert("logprobs".into(), logprobs.clone());
            }
        }
    }
    if !choices.is_empty() {
        out.insert(
            "choices".into(),
            Value::Array(choices.into_values().map(Value::Object).collect()),
        );
    }
    Value::Object(out)
}

fn openai_responses_view(kind: &str, parsed: &Value) -> Value {
    if kind == "request" {
        return pick_value(
            parsed,
            &[
                "model",
                "input",
                "tools",
                "tool_choice",
                "temperature",
                "top_p",
                "max_output_tokens",
                "stream",
                "parallel_tool_calls",
                "truncation",
                "text",
                "metadata",
                "reasoning",
                "store",
                "include",
            ],
        );
    }
    if parsed.is_array() {
        aggregate_openai_responses_stream(parsed)
    } else {
        pick_value(
            parsed,
            &[
                "id",
                "model",
                "status",
                "output",
                "output_text",
                "usage",
                "error",
                "incomplete_details",
                "reasoning",
            ],
        )
    }
}

fn aggregate_openai_responses_stream(value: &Value) -> Value {
    let Some(items) = value.as_array() else {
        return pick_value(
            value,
            &[
                "id",
                "model",
                "status",
                "output",
                "output_text",
                "usage",
                "error",
                "incomplete_details",
                "reasoning",
            ],
        );
    };
    let mut out = serde_json::Map::new();
    let mut output_items: BTreeMap<i64, serde_json::Map<String, Value>> = BTreeMap::new();
    for item in items {
        let Some(event) = item.as_object() else {
            continue;
        };
        let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
        if let Some(response) = event.get("response") {
            merge_value_object(
                &mut out,
                pick_value(
                    response,
                    &[
                        "id",
                        "model",
                        "status",
                        "output",
                        "output_text",
                        "usage",
                        "error",
                        "incomplete_details",
                        "reasoning",
                    ],
                ),
            );
        }
        match event_type {
            "response.output_item.added" | "response.output_item.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(output_items.len() as i64);
                let item_out = output_items.entry(index).or_default();
                if let Some(raw_item) = event.get("item").and_then(Value::as_object) {
                    for (k, v) in raw_item {
                        item_out.insert(k.clone(), v.clone());
                    }
                }
            }
            "response.content_part.added" | "response.content_part.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(output_items.len() as i64);
                let item_out = output_items.entry(index).or_default();
                merge_openai_response_content_part(
                    item_out,
                    event.get("content_index"),
                    event.get("part"),
                    None,
                    None,
                    None,
                    None,
                );
            }
            "response.output_text.delta" | "response.output_text.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(output_items.len() as i64);
                let item_out = output_items.entry(index).or_default();
                let part = json!({"type": "output_text"});
                let value = if event_type.ends_with(".done") {
                    event.get("text")
                } else {
                    event.get("delta")
                };
                if event_type.ends_with(".done") {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        None,
                        None,
                        Some("text"),
                        value,
                    );
                } else {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        Some("text"),
                        value,
                        None,
                        None,
                    );
                }
            }
            "response.refusal.delta" | "response.refusal.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(output_items.len() as i64);
                let item_out = output_items.entry(index).or_default();
                let part = json!({"type": "refusal"});
                let value = if event_type.ends_with(".done") {
                    event.get("refusal")
                } else {
                    event.get("delta")
                };
                if event_type.ends_with(".done") {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        None,
                        None,
                        Some("refusal"),
                        value,
                    );
                } else {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        Some("refusal"),
                        value,
                        None,
                        None,
                    );
                }
            }
            "response.reasoning_text.delta" | "response.reasoning_text.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(output_items.len() as i64);
                let item_out = output_items.entry(index).or_default();
                let part = json!({"type": "reasoning_text"});
                let value = if event_type.ends_with(".done") {
                    event.get("text")
                } else {
                    event.get("delta")
                };
                if event_type.ends_with(".done") {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        None,
                        None,
                        Some("text"),
                        value,
                    );
                } else {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        Some("text"),
                        value,
                        None,
                        None,
                    );
                }
            }
            "response.function_call_arguments.delta" | "response.function_call_arguments.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(output_items.len() as i64);
                let item_out = output_items.entry(index).or_default();
                let value = if event_type.ends_with(".done") {
                    event.get("arguments")
                } else {
                    event.get("delta")
                };
                if event_type.ends_with(".done") {
                    set_string_field(item_out, "arguments", value);
                } else {
                    append_string_field(item_out, "arguments", value);
                }
            }
            "response.completed" => {
                if !out.contains_key("status") {
                    out.insert("status".into(), Value::String("completed".to_string()));
                }
            }
            "response.failed" => {
                if let Some(error) = event.get("error") {
                    out.insert("error".into(), error.clone());
                }
            }
            _ => {}
        }
    }
    let output_is_empty = out
        .get("output")
        .and_then(Value::as_array)
        .is_none_or(|a| a.is_empty());
    if output_is_empty && !output_items.is_empty() {
        out.insert(
            "output".into(),
            Value::Array(output_items.into_values().map(Value::Object).collect()),
        );
    }
    pick_value(
        &Value::Object(out),
        &[
            "id",
            "model",
            "status",
            "output",
            "output_text",
            "usage",
            "error",
            "incomplete_details",
            "reasoning",
        ],
    )
}

#[derive(Default)]
struct OpenAiResponsesStreamState {
    out: serde_json::Map<String, Value>,
    output_items: BTreeMap<i64, serde_json::Map<String, Value>>,
}

impl OpenAiResponsesStreamState {
    fn apply(&mut self, item: &Value) {
        let Some(event) = item.as_object() else {
            return;
        };
        let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
        if let Some(response) = event.get("response") {
            merge_value_object(
                &mut self.out,
                pick_value(
                    response,
                    &[
                        "id",
                        "model",
                        "status",
                        "output",
                        "output_text",
                        "usage",
                        "error",
                        "incomplete_details",
                        "reasoning",
                    ],
                ),
            );
        }
        match event_type {
            "response.output_item.added" | "response.output_item.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(self.output_items.len() as i64);
                let item_out = self.output_items.entry(index).or_default();
                if let Some(raw_item) = event.get("item").and_then(Value::as_object) {
                    for (k, v) in raw_item {
                        item_out.insert(k.clone(), v.clone());
                    }
                }
            }
            "response.content_part.added" | "response.content_part.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(self.output_items.len() as i64);
                let item_out = self.output_items.entry(index).or_default();
                merge_openai_response_content_part(
                    item_out,
                    event.get("content_index"),
                    event.get("part"),
                    None,
                    None,
                    None,
                    None,
                );
            }
            "response.output_text.delta" | "response.output_text.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(self.output_items.len() as i64);
                let item_out = self.output_items.entry(index).or_default();
                let part = json!({"type": "output_text"});
                let value = if event_type.ends_with(".done") {
                    event.get("text")
                } else {
                    event.get("delta")
                };
                if event_type.ends_with(".done") {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        None,
                        None,
                        Some("text"),
                        value,
                    );
                } else {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        Some("text"),
                        value,
                        None,
                        None,
                    );
                }
            }
            "response.refusal.delta" | "response.refusal.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(self.output_items.len() as i64);
                let item_out = self.output_items.entry(index).or_default();
                let part = json!({"type": "refusal"});
                let value = if event_type.ends_with(".done") {
                    event.get("refusal")
                } else {
                    event.get("delta")
                };
                if event_type.ends_with(".done") {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        None,
                        None,
                        Some("refusal"),
                        value,
                    );
                } else {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        Some("refusal"),
                        value,
                        None,
                        None,
                    );
                }
            }
            "response.reasoning_text.delta" | "response.reasoning_text.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(self.output_items.len() as i64);
                let item_out = self.output_items.entry(index).or_default();
                let part = json!({"type": "reasoning_text"});
                let value = if event_type.ends_with(".done") {
                    event.get("text")
                } else {
                    event.get("delta")
                };
                if event_type.ends_with(".done") {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        None,
                        None,
                        Some("text"),
                        value,
                    );
                } else {
                    merge_openai_response_content_part(
                        item_out,
                        event.get("content_index"),
                        Some(&part),
                        Some("text"),
                        value,
                        None,
                        None,
                    );
                }
            }
            "response.function_call_arguments.delta" | "response.function_call_arguments.done" => {
                let index = event
                    .get("output_index")
                    .and_then(Value::as_i64)
                    .unwrap_or(self.output_items.len() as i64);
                let item_out = self.output_items.entry(index).or_default();
                let value = if event_type.ends_with(".done") {
                    event.get("arguments")
                } else {
                    event.get("delta")
                };
                if event_type.ends_with(".done") {
                    set_string_field(item_out, "arguments", value);
                } else {
                    append_string_field(item_out, "arguments", value);
                }
            }
            "response.completed" => {
                if !self.out.contains_key("status") {
                    self.out
                        .insert("status".into(), Value::String("completed".to_string()));
                }
            }
            "response.failed" => {
                if let Some(error) = event.get("error") {
                    self.out.insert("error".into(), error.clone());
                }
            }
            _ => {}
        }
    }

    fn finish(&mut self) -> Value {
        let output_is_empty = self
            .out
            .get("output")
            .and_then(Value::as_array)
            .is_none_or(|a| a.is_empty());
        if output_is_empty && !self.output_items.is_empty() {
            let output_items = std::mem::take(&mut self.output_items);
            self.out.insert(
                "output".into(),
                Value::Array(output_items.into_values().map(Value::Object).collect()),
            );
        }
        pick_value(
            &Value::Object(std::mem::take(&mut self.out)),
            &[
                "id",
                "model",
                "status",
                "output",
                "output_text",
                "usage",
                "error",
                "incomplete_details",
                "reasoning",
            ],
        )
    }
}

fn anthropic_messages_view(kind: &str, parsed: &Value) -> Value {
    if kind == "request" {
        return pick_value(
            parsed,
            &[
                "model",
                "messages",
                "system",
                "tools",
                "tool_choice",
                "max_tokens",
                "temperature",
                "top_p",
                "top_k",
                "stream",
                "stop_sequences",
                "thinking",
                "metadata",
                "container",
                "mcp_servers",
            ],
        );
    }
    if parsed.is_array() {
        return aggregate_anthropic_messages_stream(parsed);
    }
    pick_value(
        parsed,
        &[
            "id",
            "type",
            "role",
            "model",
            "content",
            "stop_reason",
            "stop_sequence",
            "usage",
            "error",
            "container",
        ],
    )
}

fn aggregate_anthropic_messages_stream(value: &Value) -> Value {
    let Some(items) = value.as_array() else {
        return pick_value(
            value,
            &[
                "id",
                "type",
                "role",
                "model",
                "content",
                "stop_reason",
                "stop_sequence",
                "usage",
                "error",
            ],
        );
    };
    let mut out = serde_json::Map::new();
    let mut content_blocks: BTreeMap<i64, serde_json::Map<String, Value>> = BTreeMap::new();
    for item in items {
        let Some(event) = item.as_object() else {
            continue;
        };
        let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
        match event_type {
            "message_start" => {
                if let Some(message) = event.get("message") {
                    merge_value_object(
                        &mut out,
                        pick_value(
                            message,
                            &[
                                "id",
                                "type",
                                "role",
                                "model",
                                "stop_reason",
                                "stop_sequence",
                                "usage",
                                "container",
                            ],
                        ),
                    );
                    seed_anthropic_content_blocks(&mut content_blocks, message.get("content"));
                }
            }
            "content_block_start" => {
                if let Some(block) = event.get("content_block").and_then(Value::as_object) {
                    let index = event
                        .get("index")
                        .and_then(Value::as_i64)
                        .unwrap_or(content_blocks.len() as i64);
                    content_blocks.insert(index, block.clone());
                }
            }
            "content_block_delta" => {
                let Some(delta) = event.get("delta").and_then(Value::as_object) else {
                    continue;
                };
                let index = event
                    .get("index")
                    .and_then(Value::as_i64)
                    .unwrap_or(content_blocks.len() as i64);
                let mut block = content_blocks.remove(&index).unwrap_or_default();
                merge_anthropic_content_delta(&mut block, delta);
                content_blocks.insert(index, block);
            }
            "message_delta" => {
                if let Some(delta) = event.get("delta") {
                    merge_value_object(
                        &mut out,
                        pick_value(delta, &["stop_reason", "stop_sequence"]),
                    );
                }
                merge_nested_object(&mut out, "usage", event.get("usage"));
            }
            "error" => {
                out.insert(
                    "error".into(),
                    event.get("error").cloned().unwrap_or_else(|| item.clone()),
                );
            }
            _ => {}
        }
    }
    if !content_blocks.is_empty() {
        out.insert(
            "content".into(),
            Value::Array(content_blocks.into_values().map(Value::Object).collect()),
        );
    }
    pick_value(
        &Value::Object(out),
        &[
            "id",
            "type",
            "role",
            "model",
            "content",
            "stop_reason",
            "stop_sequence",
            "usage",
            "error",
            "container",
        ],
    )
}

#[derive(Default)]
struct AnthropicMessagesStreamState {
    out: serde_json::Map<String, Value>,
    content_blocks: BTreeMap<i64, serde_json::Map<String, Value>>,
}

impl AnthropicMessagesStreamState {
    fn apply(&mut self, item: &Value) {
        let Some(event) = item.as_object() else {
            return;
        };
        let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
        match event_type {
            "message_start" => {
                if let Some(message) = event.get("message") {
                    merge_value_object(
                        &mut self.out,
                        pick_value(
                            message,
                            &[
                                "id",
                                "type",
                                "role",
                                "model",
                                "stop_reason",
                                "stop_sequence",
                                "usage",
                            ],
                        ),
                    );
                    seed_anthropic_content_blocks(&mut self.content_blocks, message.get("content"));
                }
            }
            "content_block_start" => {
                if let Some(block) = event.get("content_block").and_then(Value::as_object) {
                    let index = event
                        .get("index")
                        .and_then(Value::as_i64)
                        .unwrap_or(self.content_blocks.len() as i64);
                    self.content_blocks.insert(index, block.clone());
                }
            }
            "content_block_delta" => {
                let Some(delta) = event.get("delta").and_then(Value::as_object) else {
                    return;
                };
                let index = event
                    .get("index")
                    .and_then(Value::as_i64)
                    .unwrap_or(self.content_blocks.len() as i64);
                let mut block = self.content_blocks.remove(&index).unwrap_or_default();
                merge_anthropic_content_delta(&mut block, delta);
                self.content_blocks.insert(index, block);
            }
            "message_delta" => {
                if let Some(delta) = event.get("delta") {
                    merge_value_object(
                        &mut self.out,
                        pick_value(delta, &["stop_reason", "stop_sequence"]),
                    );
                }
                merge_nested_object(&mut self.out, "usage", event.get("usage"));
            }
            "error" => {
                self.out.insert(
                    "error".into(),
                    event.get("error").cloned().unwrap_or_else(|| item.clone()),
                );
            }
            _ => {}
        }
    }

    fn finish(&mut self) -> Value {
        if !self.content_blocks.is_empty() {
            let content_blocks = std::mem::take(&mut self.content_blocks);
            self.out.insert(
                "content".into(),
                Value::Array(content_blocks.into_values().map(Value::Object).collect()),
            );
        }
        pick_value(
            &Value::Object(std::mem::take(&mut self.out)),
            &[
                "id",
                "type",
                "role",
                "model",
                "content",
                "stop_reason",
                "stop_sequence",
                "usage",
                "error",
            ],
        )
    }
}

fn gemini_generate_content_view(kind: &str, parsed: &Value) -> Value {
    if kind == "request" {
        return pick_value(
            parsed,
            &[
                "contents",
                "systemInstruction",
                "tools",
                "toolConfig",
                "generationConfig",
                "safetySettings",
                "model",
                "cachedContent",
                "labels",
                "thinkingConfig",
            ],
        );
    }
    if parsed.is_array() {
        aggregate_gemini_generate_content_stream(parsed)
    } else {
        pick_value(
            parsed,
            &[
                "candidates",
                "promptFeedback",
                "usageMetadata",
                "error",
                "modelVersion",
            ],
        )
    }
}

fn aggregate_gemini_generate_content_stream(value: &Value) -> Value {
    let Some(items) = value.as_array() else {
        return pick_value(
            value,
            &[
                "candidates",
                "promptFeedback",
                "usageMetadata",
                "error",
                "modelVersion",
            ],
        );
    };
    let mut out = serde_json::Map::new();
    let mut candidates: BTreeMap<i64, serde_json::Map<String, Value>> = BTreeMap::new();
    for item in items {
        let Some(chunk) = item.as_object() else {
            continue;
        };
        for key in ["promptFeedback", "usageMetadata", "error", "modelVersion"] {
            if let Some(v) = chunk.get(key) {
                out.insert(key.to_string(), v.clone());
            }
        }
        let Some(raw_candidates) = chunk.get("candidates").and_then(Value::as_array) else {
            continue;
        };
        for (i, raw_candidate) in raw_candidates.iter().enumerate() {
            let Some(candidate_obj) = raw_candidate.as_object() else {
                continue;
            };
            let index = candidate_obj
                .get("index")
                .and_then(Value::as_i64)
                .unwrap_or(i as i64);
            let candidate = candidates.entry(index).or_insert_with(|| {
                let mut m = serde_json::Map::new();
                m.insert("index".into(), json!(index));
                m
            });
            merge_gemini_candidate(candidate, candidate_obj);
        }
    }
    if !candidates.is_empty() {
        out.insert(
            "candidates".into(),
            Value::Array(candidates.into_values().map(Value::Object).collect()),
        );
    }
    pick_value(
        &Value::Object(out),
        &[
            "candidates",
            "promptFeedback",
            "usageMetadata",
            "error",
            "modelVersion",
        ],
    )
}

#[derive(Default)]
struct GeminiGenerateContentStreamState {
    out: serde_json::Map<String, Value>,
    candidates: BTreeMap<i64, serde_json::Map<String, Value>>,
}

impl GeminiGenerateContentStreamState {
    fn apply(&mut self, item: &Value) {
        let Some(chunk) = item.as_object() else {
            return;
        };
        for key in ["promptFeedback", "usageMetadata", "error", "modelVersion"] {
            if let Some(v) = chunk.get(key) {
                self.out.insert(key.to_string(), v.clone());
            }
        }
        let Some(raw_candidates) = chunk.get("candidates").and_then(Value::as_array) else {
            return;
        };
        for (i, raw_candidate) in raw_candidates.iter().enumerate() {
            let Some(candidate_obj) = raw_candidate.as_object() else {
                continue;
            };
            let index = candidate_obj
                .get("index")
                .and_then(Value::as_i64)
                .unwrap_or(i as i64);
            let candidate = self.candidates.entry(index).or_insert_with(|| {
                let mut m = serde_json::Map::new();
                m.insert("index".into(), json!(index));
                m
            });
            merge_gemini_candidate(candidate, candidate_obj);
        }
    }

    fn finish(&mut self) -> Value {
        if !self.candidates.is_empty() {
            let candidates = std::mem::take(&mut self.candidates);
            self.out.insert(
                "candidates".into(),
                Value::Array(candidates.into_values().map(Value::Object).collect()),
            );
        }
        pick_value(
            &Value::Object(std::mem::take(&mut self.out)),
            &[
                "candidates",
                "promptFeedback",
                "usageMetadata",
                "error",
                "modelVersion",
            ],
        )
    }
}

fn dashscope_generation_view(kind: &str, parsed: &Value) -> Value {
    if kind == "request" {
        return pick_value(
            parsed,
            &[
                "model",
                "input",
                "parameters",
                "system",
                "messages",
                "response_format",
                "thinking_budget",
            ],
        );
    }
    if parsed.is_array() {
        aggregate_dashscope_generation_stream(parsed)
    } else {
        pick_value(
            parsed,
            &["output", "usage", "request_id", "code", "message"],
        )
    }
}

fn aggregate_dashscope_generation_stream(value: &Value) -> Value {
    let Some(items) = value.as_array() else {
        return pick_value(value, &["output", "usage", "request_id", "code", "message"]);
    };
    let mut out = serde_json::Map::new();
    let mut output = serde_json::Map::new();
    let mut choices: BTreeMap<i64, serde_json::Map<String, Value>> = BTreeMap::new();
    for item in items {
        let Some(chunk) = item.as_object() else {
            continue;
        };
        for key in ["usage", "request_id", "code", "message"] {
            if let Some(v) = chunk.get(key) {
                out.insert(key.to_string(), v.clone());
            }
        }
        let Some(raw_output) = chunk.get("output").and_then(Value::as_object) else {
            continue;
        };
        for (k, v) in raw_output {
            if k != "choices" {
                output.insert(k.clone(), v.clone());
            }
        }
        let Some(raw_choices) = raw_output.get("choices").and_then(Value::as_array) else {
            continue;
        };
        for (i, raw_choice) in raw_choices.iter().enumerate() {
            let Some(choice_obj) = raw_choice.as_object() else {
                continue;
            };
            let index = choice_obj
                .get("index")
                .and_then(Value::as_i64)
                .unwrap_or(i as i64);
            let choice = choices.entry(index).or_insert_with(|| {
                let mut m = serde_json::Map::new();
                m.insert("index".into(), json!(index));
                m.insert("message".into(), Value::Object(serde_json::Map::new()));
                m
            });
            let mut message = choice
                .get("message")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if let Some(raw_message) = choice_obj.get("message").and_then(Value::as_object) {
                merge_dashscope_message(&mut message, raw_message);
            }
            if let Some(raw_delta) = choice_obj.get("delta").and_then(Value::as_object) {
                merge_dashscope_message(&mut message, raw_delta);
            }
            choice.insert("message".into(), Value::Object(message));
            for (k, v) in choice_obj {
                if k != "index" && k != "message" && k != "delta" && !v.is_null() {
                    choice.insert(k.clone(), v.clone());
                }
            }
        }
    }
    if !choices.is_empty() {
        output.insert(
            "choices".into(),
            Value::Array(choices.into_values().map(Value::Object).collect()),
        );
    }
    if !output.is_empty() {
        out.insert("output".into(), Value::Object(output));
    }
    pick_value(
        &Value::Object(out),
        &["output", "usage", "request_id", "code", "message"],
    )
}

#[derive(Default)]
struct DashscopeGenerationStreamState {
    out: serde_json::Map<String, Value>,
    output: serde_json::Map<String, Value>,
    choices: BTreeMap<i64, serde_json::Map<String, Value>>,
}

impl DashscopeGenerationStreamState {
    fn apply(&mut self, item: &Value) {
        let Some(chunk) = item.as_object() else {
            return;
        };
        for key in ["usage", "request_id", "code", "message"] {
            if let Some(v) = chunk.get(key) {
                self.out.insert(key.to_string(), v.clone());
            }
        }
        let Some(raw_output) = chunk.get("output").and_then(Value::as_object) else {
            return;
        };
        for (k, v) in raw_output {
            if k != "choices" {
                self.output.insert(k.clone(), v.clone());
            }
        }
        let Some(raw_choices) = raw_output.get("choices").and_then(Value::as_array) else {
            return;
        };
        for (i, raw_choice) in raw_choices.iter().enumerate() {
            let Some(choice_obj) = raw_choice.as_object() else {
                continue;
            };
            let index = choice_obj
                .get("index")
                .and_then(Value::as_i64)
                .unwrap_or(i as i64);
            let choice = self.choices.entry(index).or_insert_with(|| {
                let mut m = serde_json::Map::new();
                m.insert("index".into(), json!(index));
                m.insert("message".into(), Value::Object(serde_json::Map::new()));
                m
            });
            let mut message = choice
                .get("message")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if let Some(raw_message) = choice_obj.get("message").and_then(Value::as_object) {
                merge_dashscope_message(&mut message, raw_message);
            }
            if let Some(raw_delta) = choice_obj.get("delta").and_then(Value::as_object) {
                merge_dashscope_message(&mut message, raw_delta);
            }
            choice.insert("message".into(), Value::Object(message));
            for (k, v) in choice_obj {
                if k != "index" && k != "message" && k != "delta" && !v.is_null() {
                    choice.insert(k.clone(), v.clone());
                }
            }
        }
    }

    fn finish(&mut self) -> Value {
        if !self.choices.is_empty() {
            let choices = std::mem::take(&mut self.choices);
            self.output.insert(
                "choices".into(),
                Value::Array(choices.into_values().map(Value::Object).collect()),
            );
        }
        if !self.output.is_empty() {
            self.out.insert(
                "output".into(),
                Value::Object(std::mem::take(&mut self.output)),
            );
        }
        pick_value(
            &Value::Object(std::mem::take(&mut self.out)),
            &["output", "usage", "request_id", "code", "message"],
        )
    }
}

fn seed_anthropic_content_blocks(
    blocks: &mut BTreeMap<i64, serde_json::Map<String, Value>>,
    content: Option<&Value>,
) {
    let Some(items) = content.and_then(Value::as_array) else {
        return;
    };
    for (i, item) in items.iter().enumerate() {
        if let Some(block) = item.as_object() {
            blocks.entry(i as i64).or_insert_with(|| block.clone());
        }
    }
}

fn merge_anthropic_content_delta(
    block: &mut serde_json::Map<String, Value>,
    delta: &serde_json::Map<String, Value>,
) {
    if !block.contains_key("type") {
        if let Some(delta_type) = delta.get("type").and_then(Value::as_str) {
            block.insert(
                "type".into(),
                Value::String(delta_type.trim_end_matches("_delta").to_string()),
            );
        }
    }
    append_string_field(block, "text", delta.get("text"));
    append_string_field(block, "thinking", delta.get("thinking"));
    append_string_field(block, "signature", delta.get("signature"));
    append_string_field(block, "input_json", delta.get("partial_json"));
}

fn merge_value_object(target: &mut serde_json::Map<String, Value>, source: Value) {
    if let Value::Object(map) = source {
        for (k, v) in map {
            target.insert(k, v);
        }
    }
}

fn merge_nested_object(
    target: &mut serde_json::Map<String, Value>,
    field: &str,
    value: Option<&Value>,
) {
    let Some(value) = value else {
        return;
    };
    if let (Some(existing), Some(incoming)) = (
        target.get(field).and_then(Value::as_object),
        value.as_object(),
    ) {
        let mut merged = existing.clone();
        for (k, v) in incoming {
            merged.insert(k.clone(), v.clone());
        }
        target.insert(field.to_string(), Value::Object(merged));
    } else {
        target.insert(field.to_string(), value.clone());
    }
}

fn bedrock_converse_view(kind: &str, parsed: &Value) -> Value {
    if kind == "request" {
        return bedrock_converse_request_view(parsed, None);
    }
    if parsed.is_array() {
        aggregate_bedrock_converse_stream(parsed)
    } else {
        pick_value(
            parsed,
            &[
                "output",
                "stopReason",
                "usage",
                "metrics",
                "additionalModelResponseFields",
                "error",
            ],
        )
    }
}

fn aggregate_bedrock_converse_stream(value: &Value) -> Value {
    let Some(items) = value.as_array() else {
        return pick_value(
            value,
            &[
                "output",
                "stopReason",
                "usage",
                "metrics",
                "additionalModelResponseFields",
                "error",
            ],
        );
    };
    let mut out = serde_json::Map::new();
    let mut message = serde_json::Map::new();
    let mut content_blocks: BTreeMap<i64, serde_json::Map<String, Value>> = BTreeMap::new();
    for item in items {
        let Some(event) = item.as_object() else {
            continue;
        };
        if let Some(message_start) = event.get("messageStart").and_then(Value::as_object) {
            if let Some(role) = message_start.get("role") {
                message.insert("role".into(), role.clone());
            }
        }
        if let Some(block_start) = event.get("contentBlockStart").and_then(Value::as_object) {
            let index = block_start
                .get("contentBlockIndex")
                .and_then(Value::as_i64)
                .unwrap_or(content_blocks.len() as i64);
            let block = content_blocks.entry(index).or_default();
            if let Some(start) = block_start.get("start").and_then(Value::as_object) {
                for (k, v) in start {
                    block.insert(k.clone(), v.clone());
                }
            }
        }
        if let Some(block_delta) = event.get("contentBlockDelta").and_then(Value::as_object) {
            let index = block_delta
                .get("contentBlockIndex")
                .and_then(Value::as_i64)
                .unwrap_or(content_blocks.len() as i64);
            let block = content_blocks.entry(index).or_default();
            if let Some(delta) = block_delta.get("delta").and_then(Value::as_object) {
                merge_bedrock_content_delta(block, delta);
            }
        }
        if let Some(message_stop) = event.get("messageStop").and_then(Value::as_object) {
            if let Some(stop_reason) = message_stop.get("stopReason") {
                out.insert("stopReason".into(), stop_reason.clone());
            }
            if let Some(fields) = message_stop.get("additionalModelResponseFields") {
                out.insert("additionalModelResponseFields".into(), fields.clone());
            }
        }
        if let Some(metadata) = event.get("metadata").and_then(Value::as_object) {
            if let Some(usage) = metadata.get("usage") {
                out.insert("usage".into(), usage.clone());
            }
            if let Some(metrics) = metadata.get("metrics") {
                out.insert("metrics".into(), metrics.clone());
            }
        }
        if event.get("output").is_some() {
            merge_value_object(
                &mut out,
                pick_value(
                    item,
                    &[
                        "output",
                        "stopReason",
                        "usage",
                        "metrics",
                        "additionalModelResponseFields",
                        "error",
                    ],
                ),
            );
        }
        if let Some(error) = event.get("error") {
            out.insert("error".into(), error.clone());
        }
    }
    if !content_blocks.is_empty() {
        message.insert(
            "content".into(),
            Value::Array(content_blocks.into_values().map(Value::Object).collect()),
        );
    }
    if !message.is_empty() && !out.contains_key("output") {
        out.insert(
            "output".into(),
            json!({ "message": Value::Object(message) }),
        );
    }
    pick_value(
        &Value::Object(out),
        &[
            "output",
            "stopReason",
            "usage",
            "metrics",
            "additionalModelResponseFields",
            "error",
        ],
    )
}

#[derive(Default)]
struct BedrockConverseStreamState {
    out: serde_json::Map<String, Value>,
    message: serde_json::Map<String, Value>,
    content_blocks: BTreeMap<i64, serde_json::Map<String, Value>>,
}

impl BedrockConverseStreamState {
    fn apply(&mut self, item: &Value) {
        let Some(event) = item.as_object() else {
            return;
        };
        if let Some(message_start) = event.get("messageStart").and_then(Value::as_object) {
            if let Some(role) = message_start.get("role") {
                self.message.insert("role".into(), role.clone());
            }
        }
        if let Some(block_start) = event.get("contentBlockStart").and_then(Value::as_object) {
            let index = block_start
                .get("contentBlockIndex")
                .and_then(Value::as_i64)
                .unwrap_or(self.content_blocks.len() as i64);
            let block = self.content_blocks.entry(index).or_default();
            if let Some(start) = block_start.get("start").and_then(Value::as_object) {
                for (k, v) in start {
                    block.insert(k.clone(), v.clone());
                }
            }
        }
        if let Some(block_delta) = event.get("contentBlockDelta").and_then(Value::as_object) {
            let index = block_delta
                .get("contentBlockIndex")
                .and_then(Value::as_i64)
                .unwrap_or(self.content_blocks.len() as i64);
            let block = self.content_blocks.entry(index).or_default();
            if let Some(delta) = block_delta.get("delta").and_then(Value::as_object) {
                merge_bedrock_content_delta(block, delta);
            }
        }
        if let Some(message_stop) = event.get("messageStop").and_then(Value::as_object) {
            if let Some(stop_reason) = message_stop.get("stopReason") {
                self.out.insert("stopReason".into(), stop_reason.clone());
            }
            if let Some(fields) = message_stop.get("additionalModelResponseFields") {
                self.out
                    .insert("additionalModelResponseFields".into(), fields.clone());
            }
        }
        if let Some(metadata) = event.get("metadata").and_then(Value::as_object) {
            if let Some(usage) = metadata.get("usage") {
                self.out.insert("usage".into(), usage.clone());
            }
            if let Some(metrics) = metadata.get("metrics") {
                self.out.insert("metrics".into(), metrics.clone());
            }
        }
        if event.get("output").is_some() {
            merge_value_object(
                &mut self.out,
                pick_value(
                    item,
                    &[
                        "output",
                        "stopReason",
                        "usage",
                        "metrics",
                        "additionalModelResponseFields",
                        "error",
                    ],
                ),
            );
        }
        if let Some(error) = event.get("error") {
            self.out.insert("error".into(), error.clone());
        }
    }

    fn finish(&mut self) -> Value {
        if !self.content_blocks.is_empty() {
            let content_blocks = std::mem::take(&mut self.content_blocks);
            self.message.insert(
                "content".into(),
                Value::Array(content_blocks.into_values().map(Value::Object).collect()),
            );
        }
        if !self.message.is_empty() && !self.out.contains_key("output") {
            self.out.insert(
                "output".into(),
                json!({ "message": Value::Object(std::mem::take(&mut self.message)) }),
            );
        }
        pick_value(
            &Value::Object(std::mem::take(&mut self.out)),
            &[
                "output",
                "stopReason",
                "usage",
                "metrics",
                "additionalModelResponseFields",
                "error",
            ],
        )
    }
}

fn cohere_chat_view(kind: &str, parsed: &Value) -> Value {
    if kind == "request" {
        return pick_value(
            parsed,
            &[
                "model",
                "messages",
                "message",
                "tools",
                "tool_choice",
                "temperature",
                "p",
                "k",
                "max_tokens",
                "stop_sequences",
                "response_format",
                "stream",
                "documents",
                "safety_mode",
                "metadata",
            ],
        );
    }
    if parsed.is_array() {
        aggregate_cohere_chat_stream(parsed)
    } else {
        pick_value(
            parsed,
            &[
                "id",
                "message",
                "text",
                "finish_reason",
                "usage",
                "tool_calls",
                "citations",
                "error",
            ],
        )
    }
}

fn aggregate_cohere_chat_stream(value: &Value) -> Value {
    let Some(items) = value.as_array() else {
        return pick_value(
            value,
            &[
                "id",
                "message",
                "text",
                "finish_reason",
                "usage",
                "tool_calls",
                "citations",
                "error",
            ],
        );
    };
    let mut out = serde_json::Map::new();
    let mut message = serde_json::Map::new();
    let mut content_blocks: BTreeMap<i64, serde_json::Map<String, Value>> = BTreeMap::new();
    let mut text = String::new();
    for item in items {
        let Some(event) = item.as_object() else {
            continue;
        };
        let event_type = event
            .get("type")
            .or_else(|| event.get("event_type"))
            .or_else(|| event.get("eventType"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Some(response) = event.get("response") {
            merge_value_object(
                &mut out,
                pick_value(
                    response,
                    &[
                        "id",
                        "message",
                        "text",
                        "finish_reason",
                        "usage",
                        "tool_calls",
                        "citations",
                        "error",
                    ],
                ),
            );
        }
        if let Some(delta) = event.get("delta").and_then(Value::as_object) {
            if let Some(raw_message) = delta.get("message") {
                merge_cohere_message_delta(&mut message, &mut content_blocks, raw_message);
            }
            if event_type == "message-end" {
                if let Some(finish_reason) = delta.get("finish_reason") {
                    out.insert("finish_reason".into(), finish_reason.clone());
                    message.insert("finish_reason".into(), finish_reason.clone());
                }
                if let Some(usage) = delta.get("usage") {
                    out.insert("usage".into(), usage.clone());
                }
            }
        }
        if event_type == "text-generation" {
            if let Some(piece) = event.get("text").and_then(Value::as_str) {
                text.push_str(piece);
            }
        }
        if let Some(finish_reason) = event.get("finish_reason") {
            out.insert("finish_reason".into(), finish_reason.clone());
            message.insert("finish_reason".into(), finish_reason.clone());
        }
        if let Some(error) = event.get("error") {
            out.insert("error".into(), error.clone());
        }
    }
    if !content_blocks.is_empty() {
        message.insert(
            "content".into(),
            Value::Array(content_blocks.into_values().map(Value::Object).collect()),
        );
    } else if !text.is_empty() {
        message.insert("content".into(), json!([{ "type": "text", "text": text }]));
        out.insert("text".into(), Value::String(text));
    }
    if !message.is_empty() && !out.contains_key("message") {
        out.insert("message".into(), Value::Object(message));
    }
    pick_value(
        &Value::Object(out),
        &[
            "id",
            "message",
            "text",
            "finish_reason",
            "usage",
            "tool_calls",
            "citations",
            "error",
        ],
    )
}

#[derive(Default)]
struct CohereChatStreamState {
    out: serde_json::Map<String, Value>,
    message: serde_json::Map<String, Value>,
    content_blocks: BTreeMap<i64, serde_json::Map<String, Value>>,
    text: String,
}

impl CohereChatStreamState {
    fn apply(&mut self, item: &Value) {
        let Some(event) = item.as_object() else {
            return;
        };
        let event_type = event
            .get("type")
            .or_else(|| event.get("event_type"))
            .or_else(|| event.get("eventType"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Some(response) = event.get("response") {
            merge_value_object(
                &mut self.out,
                pick_value(
                    response,
                    &[
                        "id",
                        "message",
                        "text",
                        "finish_reason",
                        "usage",
                        "tool_calls",
                        "citations",
                        "error",
                    ],
                ),
            );
        }
        if let Some(delta) = event.get("delta").and_then(Value::as_object) {
            if let Some(raw_message) = delta.get("message") {
                merge_cohere_message_delta(
                    &mut self.message,
                    &mut self.content_blocks,
                    raw_message,
                );
            }
            if event_type == "message-end" {
                if let Some(finish_reason) = delta.get("finish_reason") {
                    self.out
                        .insert("finish_reason".into(), finish_reason.clone());
                    self.message
                        .insert("finish_reason".into(), finish_reason.clone());
                }
                if let Some(usage) = delta.get("usage") {
                    self.out.insert("usage".into(), usage.clone());
                }
            }
        }
        if event_type == "text-generation" {
            if let Some(piece) = event.get("text").and_then(Value::as_str) {
                self.text.push_str(piece);
            }
        }
        if let Some(finish_reason) = event.get("finish_reason") {
            self.out
                .insert("finish_reason".into(), finish_reason.clone());
            self.message
                .insert("finish_reason".into(), finish_reason.clone());
        }
        if let Some(error) = event.get("error") {
            self.out.insert("error".into(), error.clone());
        }
    }

    fn finish(&mut self) -> Value {
        if !self.content_blocks.is_empty() {
            let content_blocks = std::mem::take(&mut self.content_blocks);
            self.message.insert(
                "content".into(),
                Value::Array(content_blocks.into_values().map(Value::Object).collect()),
            );
        } else if !self.text.is_empty() {
            self.message.insert(
                "content".into(),
                json!([{ "type": "text", "text": self.text }]),
            );
            self.out
                .insert("text".into(), Value::String(std::mem::take(&mut self.text)));
        }
        if !self.message.is_empty() && !self.out.contains_key("message") {
            self.out.insert(
                "message".into(),
                Value::Object(std::mem::take(&mut self.message)),
            );
        }
        pick_value(
            &Value::Object(std::mem::take(&mut self.out)),
            &[
                "id",
                "message",
                "text",
                "finish_reason",
                "usage",
                "tool_calls",
                "citations",
                "error",
            ],
        )
    }
}

fn bedrock_converse_request_view(parsed: &Value, upstream_path: Option<&str>) -> Value {
    let view = pick_value(
        parsed,
        &[
            "modelId",
            "messages",
            "system",
            "inferenceConfig",
            "toolConfig",
            "additionalModelRequestFields",
            "promptVariables",
            "guardrailConfig",
            "additionalModelResponseFieldPaths",
        ],
    );
    let Value::Object(mut out) = view else {
        return view;
    };
    if !out.contains_key("modelId") {
        if let Some(model_id) = upstream_path.and_then(bedrock_model_id_from_path) {
            out.insert("modelId".into(), Value::String(model_id));
        }
    }
    Value::Object(out)
}

fn bedrock_model_id_from_path(path: &str) -> Option<String> {
    let parts: Vec<&str> = path_no_query(path).split('/').collect();
    let model_idx = parts.iter().position(|part| *part == "model")?;
    if model_idx + 2 >= parts.len() {
        return None;
    }
    let operation = parts[model_idx + 2].to_ascii_lowercase();
    if operation != "converse" && operation != "converse-stream" {
        return None;
    }
    let model_id = parts[model_idx + 1];
    if model_id.is_empty() {
        None
    } else {
        Some(model_id.to_string())
    }
}

fn merge_openai_chat_delta(
    message: &mut serde_json::Map<String, Value>,
    delta: &serde_json::Map<String, Value>,
) {
    if !message.contains_key("role") {
        if let Some(role) = delta.get("role").and_then(Value::as_str) {
            message.insert("role".into(), Value::String(role.to_string()));
        }
    }
    append_string_field(message, "content", delta.get("content"));
    append_string_field(message, "reasoning_content", delta.get("reasoning_content"));
    if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
        let current = message
            .get("tool_calls")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        message.insert(
            "tool_calls".into(),
            Value::Array(merge_tool_calls(current, tool_calls)),
        );
    }
}

fn merge_tool_calls(mut current: Vec<Value>, delta: &[Value]) -> Vec<Value> {
    for raw in delta {
        let Some(raw_obj) = raw.as_object() else {
            continue;
        };
        let index = raw_obj
            .get("index")
            .and_then(Value::as_u64)
            .map(|v| v as usize)
            .unwrap_or(current.len());
        while current.len() <= index {
            current.push(Value::Object(serde_json::Map::new()));
        }
        let mut item = current[index].as_object().cloned().unwrap_or_default();
        for (key, value) in raw_obj {
            if key == "index" {
                continue;
            }
            if key == "function" {
                if let Some(fn_delta) = value.as_object() {
                    let mut fn_obj = item
                        .get("function")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default();
                    append_string_field(&mut fn_obj, "name", fn_delta.get("name"));
                    append_string_field(&mut fn_obj, "arguments", fn_delta.get("arguments"));
                    item.insert("function".into(), Value::Object(fn_obj));
                }
            } else {
                item.insert(key.clone(), value.clone());
            }
        }
        current[index] = Value::Object(item);
    }
    current
}

fn merge_openai_response_content_part(
    item: &mut serde_json::Map<String, Value>,
    raw_index: Option<&Value>,
    raw_part: Option<&Value>,
    append_field: Option<&str>,
    append_value: Option<&Value>,
    set_field: Option<&str>,
    set_value: Option<&Value>,
) {
    let mut content = item
        .get("content")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let index = raw_index
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(content.len());
    while content.len() <= index {
        content.push(Value::Object(serde_json::Map::new()));
    }
    let mut part = content[index].as_object().cloned().unwrap_or_default();
    if let Some(raw_part) = raw_part.and_then(Value::as_object) {
        for (k, v) in raw_part {
            part.insert(k.clone(), v.clone());
        }
    }
    if let Some(field) = append_field {
        append_string_field(&mut part, field, append_value);
    }
    if let Some(field) = set_field {
        set_string_field(&mut part, field, set_value);
    }
    content[index] = Value::Object(part);
    item.insert("content".into(), Value::Array(content));
}

fn merge_gemini_candidate(
    target: &mut serde_json::Map<String, Value>,
    source: &serde_json::Map<String, Value>,
) {
    for (k, v) in source {
        if k == "index" {
            continue;
        }
        if k == "content" {
            if let Some(content_obj) = v.as_object() {
                let mut content = target
                    .get("content")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                for (content_key, content_value) in content_obj {
                    if content_key == "parts" {
                        if let Some(parts) = content_value.as_array() {
                            let merged = merge_indexed_parts(content.get("parts"), parts);
                            content.insert("parts".into(), merged);
                        }
                    } else if !content_value.is_null() {
                        content.insert(content_key.clone(), content_value.clone());
                    }
                }
                target.insert("content".into(), Value::Object(content));
            }
        } else if !v.is_null() {
            target.insert(k.clone(), v.clone());
        }
    }
}

fn merge_indexed_parts(existing: Option<&Value>, incoming: &[Value]) -> Value {
    let mut out = existing
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (i, raw) in incoming.iter().enumerate() {
        while out.len() <= i {
            out.push(Value::Object(serde_json::Map::new()));
        }
        let Some(raw_obj) = raw.as_object() else {
            out[i] = raw.clone();
            continue;
        };
        let mut current = out[i].as_object().cloned().unwrap_or_default();
        merge_semantic_part(&mut current, raw_obj);
        out[i] = Value::Object(current);
    }
    Value::Array(out)
}

fn merge_semantic_part(
    target: &mut serde_json::Map<String, Value>,
    source: &serde_json::Map<String, Value>,
) {
    for (k, v) in source {
        if k == "text" || k == "thinking" || k == "signature" {
            append_string_field(target, k, Some(v));
        } else if let (Some(existing), Some(incoming)) =
            (target.get(k).and_then(Value::as_object), v.as_object())
        {
            let mut merged = existing.clone();
            for (inner_key, inner_value) in incoming {
                merged.insert(inner_key.clone(), inner_value.clone());
            }
            target.insert(k.clone(), Value::Object(merged));
        } else if !v.is_null() {
            target.insert(k.clone(), v.clone());
        }
    }
}

fn merge_dashscope_message(
    target: &mut serde_json::Map<String, Value>,
    source: &serde_json::Map<String, Value>,
) {
    append_string_field(target, "content", source.get("content"));
    append_string_field(target, "reasoning_content", source.get("reasoning_content"));
    if let Some(tool_calls) = source.get("tool_calls").and_then(Value::as_array) {
        let current = target
            .get("tool_calls")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        target.insert(
            "tool_calls".into(),
            Value::Array(merge_tool_calls(current, tool_calls)),
        );
    }
    for (k, v) in source {
        if k != "content" && k != "reasoning_content" && k != "tool_calls" && !v.is_null() {
            target.insert(k.clone(), v.clone());
        }
    }
}

fn merge_bedrock_content_delta(
    block: &mut serde_json::Map<String, Value>,
    delta: &serde_json::Map<String, Value>,
) {
    append_string_field(block, "text", delta.get("text"));
    if delta.get("text").is_some() && !block.contains_key("type") {
        block.insert("type".into(), Value::String("text".to_string()));
    }
    if let Some(reasoning) = delta.get("reasoningContent").and_then(Value::as_object) {
        block.insert(
            "reasoningContent".into(),
            merge_nested_semantic_object(
                block.get("reasoningContent"),
                reasoning,
                &["text", "signature"],
            ),
        );
    }
    if let Some(tool_use) = delta.get("toolUse").and_then(Value::as_object) {
        block.insert(
            "toolUse".into(),
            merge_nested_semantic_object(block.get("toolUse"), tool_use, &["input"]),
        );
    }
    if let Some(citations) = delta.get("citationsContent").and_then(Value::as_object) {
        block.insert(
            "citationsContent".into(),
            merge_nested_semantic_object(block.get("citationsContent"), citations, &["text"]),
        );
    }
    for (k, v) in delta {
        if k != "text"
            && k != "reasoningContent"
            && k != "toolUse"
            && k != "citationsContent"
            && !v.is_null()
        {
            block.insert(k.clone(), v.clone());
        }
    }
}

fn merge_nested_semantic_object(
    existing: Option<&Value>,
    incoming: &serde_json::Map<String, Value>,
    append_fields: &[&str],
) -> Value {
    let mut out = existing
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (k, v) in incoming {
        if append_fields.contains(&k.as_str()) {
            append_string_field(&mut out, k, Some(v));
        } else if let (Some(existing), Some(incoming)) =
            (out.get(k).and_then(Value::as_object), v.as_object())
        {
            let mut merged = existing.clone();
            for (inner_key, inner_value) in incoming {
                merged.insert(inner_key.clone(), inner_value.clone());
            }
            out.insert(k.clone(), Value::Object(merged));
        } else if !v.is_null() {
            out.insert(k.clone(), v.clone());
        }
    }
    Value::Object(out)
}

fn merge_cohere_message_delta(
    message: &mut serde_json::Map<String, Value>,
    content_blocks: &mut BTreeMap<i64, serde_json::Map<String, Value>>,
    raw_message: &Value,
) {
    let Some(message_obj) = raw_message.as_object() else {
        return;
    };
    for (k, v) in message_obj {
        if k != "content" && !v.is_null() {
            message.insert(k.clone(), v.clone());
        }
    }
    let Some(raw_content) = message_obj.get("content") else {
        return;
    };
    if let Some(items) = raw_content.as_array() {
        for (i, item) in items.iter().enumerate() {
            merge_cohere_content_block(content_blocks, i as i64, item);
        }
    } else if let Some(content_obj) = raw_content.as_object() {
        let index = content_obj
            .get("index")
            .and_then(Value::as_i64)
            .unwrap_or_else(|| {
                if content_blocks.is_empty() {
                    0
                } else {
                    content_blocks.len() as i64 - 1
                }
            });
        merge_cohere_content_block(content_blocks, index, raw_content);
    } else if let Some(s) = raw_content.as_str() {
        let block = content_blocks.entry(0).or_insert_with(|| {
            let mut m = serde_json::Map::new();
            m.insert("type".into(), Value::String("text".to_string()));
            m
        });
        append_string_field(block, "text", Some(&Value::String(s.to_string())));
    }
}

fn merge_cohere_content_block(
    blocks: &mut BTreeMap<i64, serde_json::Map<String, Value>>,
    index: i64,
    raw_block: &Value,
) {
    let Some(raw_obj) = raw_block.as_object() else {
        return;
    };
    let block = blocks.entry(index).or_default();
    merge_semantic_part(block, raw_obj);
}

fn append_string_field(
    target: &mut serde_json::Map<String, Value>,
    field: &str,
    value: Option<&Value>,
) {
    let Some(s) = value.and_then(Value::as_str) else {
        return;
    };
    let merged = match target.get(field).and_then(Value::as_str) {
        Some(existing) => format!("{}{}", existing, s),
        None => s.to_string(),
    };
    target.insert(field.to_string(), Value::String(merged));
}

fn set_string_field(
    target: &mut serde_json::Map<String, Value>,
    field: &str,
    value: Option<&Value>,
) {
    let Some(s) = value.and_then(Value::as_str) else {
        return;
    };
    target.insert(field.to_string(), Value::String(s.to_string()));
}

fn has_required_presence(protocol: &str, kind: &str, view: &Value) -> bool {
    if kind == "response" && is_error_response_view(protocol, view) {
        return true;
    }
    required_presence(protocol, kind)
        .iter()
        .all(|alternatives| alternatives.iter().any(|path| has_present_path(view, path)))
}

fn is_error_response_view(protocol: &str, view: &Value) -> bool {
    match protocol {
        "alibaba.dashscope.generation" => {
            has_present_path(view, "code") && has_present_path(view, "message")
        }
        _ => has_present_path(view, "error"),
    }
}

fn required_presence(protocol: &str, kind: &str) -> Vec<Vec<&'static str>> {
    match (protocol, kind) {
        ("openai.chat_completions", "request") => vec![vec!["model"], vec!["messages"]],
        ("openai.chat_completions", "response") => vec![vec!["choices"]],
        ("openai.responses", "request") => vec![vec!["model"], vec!["input"]],
        ("openai.responses", "response") => vec![vec!["output", "status"]],
        ("anthropic.messages", "request") => {
            vec![vec!["model"], vec!["messages"], vec!["max_tokens"]]
        }
        ("anthropic.messages", "response") => vec![vec!["content"], vec!["stop_reason"]],
        ("google.gemini.generate_content", "request") => vec![vec!["contents"]],
        ("google.gemini.generate_content", "response") => vec![vec!["candidates"]],
        ("alibaba.dashscope.generation", "request") => vec![vec!["model"], vec!["input"]],
        ("alibaba.dashscope.generation", "response") => vec![vec!["output"]],
        ("aws.bedrock.converse", "request") => vec![vec!["modelId"], vec!["messages"]],
        ("aws.bedrock.converse", "response") => vec![vec!["output", "stopReason"]],
        ("cohere.chat", "request") => vec![vec!["model"], vec!["messages"]],
        ("cohere.chat", "response") => vec![vec!["message", "finish_reason"]],
        _ => Vec::new(),
    }
}

fn has_present_path(value: &Value, path: &str) -> bool {
    let mut cur = value;
    for part in path.split('.') {
        let Some(next) = cur.get(part) else {
            return false;
        };
        cur = next;
    }
    match cur {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}

fn capture_field_body(body: &mut Vec<u8>, truncated: &mut bool, chunk: &[u8]) {
    if *truncated {
        return;
    }
    let remaining = MAX_FIELD_CLAIMS_CAPTURE.saturating_sub(body.len());
    if chunk.len() > remaining {
        body.extend_from_slice(&chunk[..remaining]);
        *truncated = true;
    } else {
        body.extend_from_slice(chunk);
    }
}

fn pick_value(value: &Value, keys: &[&str]) -> Value {
    if let Value::Array(items) = value {
        return Value::Array(items.iter().map(|item| pick_value(item, keys)).collect());
    }
    let Value::Object(map) = value else {
        return value.clone();
    };
    let mut out = serde_json::Map::new();
    for key in keys {
        if let Some(v) = map.get(*key) {
            out.insert((*key).to_string(), v.clone());
        }
    }
    Value::Object(out)
}

/// Validate the caller-provided ordered header template: each item must be exactly
/// [name, value]; any malformed item yields None (caller falls back to the map path).
fn parse_headers_ordered(v: &Option<Vec<Vec<String>>>) -> Option<Vec<(String, String)>> {
    let arr = v.as_ref()?;
    let mut out = Vec::with_capacity(arr.len());
    for pair in arr {
        if pair.len() != 2 {
            return None;
        }
        out.push((pair[0].clone(), pair[1].clone()));
    }
    Some(out)
}

/// Assemble the HTTP/1.1 request head verbatim from the ordered template
/// (exact order and case, no sorting, no lowercasing). The `authorization` slot is
/// filled from the token (only if present); the `content-length` slot is filled with
/// the actual body length (both are empty-value sentinels). `transfer-encoding` is
/// stripped. Safety net: if the template omits host / content-length they are
/// appended so the request stays well-formed. `connection` is NOT hard-coded here —
/// it is carried by the template when provided.
fn build_request_head_ordered(
    norm_method: &str,
    path: &str,
    host: &str,
    ordered: &[(String, String)],
    token: Option<&str>,
    body_len: usize,
) -> String {
    let mut s = format!("{} {} HTTP/1.1\r\n", norm_method, path);
    let mut host_seen = false;
    let mut clen_seen = false;
    for (k, v) in ordered {
        if k.eq_ignore_ascii_case("authorization") {
            if let Some(t) = token {
                s.push_str(&format!("{}: Bearer {}\r\n", k, t));
            }
        } else if k.eq_ignore_ascii_case("content-length") {
            s.push_str(&format!("{}: {}\r\n", k, body_len));
            clen_seen = true;
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            // strip: a fixed-length body must not carry TE (matches the map path)
        } else {
            if k.eq_ignore_ascii_case("host") {
                host_seen = true;
            }
            s.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    if !host_seen {
        s.push_str(&format!("host: {}\r\n", host));
    }
    if !clen_seen {
        s.push_str(&format!("content-length: {}\r\n", body_len));
    }
    s.push_str("\r\n");
    s
}

struct Headers {
    status: u16,
    content_type: Option<String>,
    chunked: bool,
    content_length: Option<usize>,
    headers: BTreeMap<String, String>,
}

fn parse_headers(head: &[u8]) -> Result<Headers, String> {
    let s = String::from_utf8_lossy(head);
    let mut lines = s.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("状态行解析失败")?;
    let mut content_type = None;
    let mut chunked = false;
    let mut content_length = None;
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        if let Some(idx) = line.find(':') {
            let k = line[..idx].trim().to_lowercase();
            let v = line[idx + 1..].trim().to_string();
            match k.as_str() {
                "content-type" => content_type = Some(v.clone()),
                "transfer-encoding" if v.to_lowercase().contains("chunked") => chunked = true,
                "content-length" => content_length = v.parse().ok(),
                _ => {}
            }
            match headers.get_mut(&k) {
                Some(existing) => {
                    existing.push_str(", ");
                    existing.push_str(&v);
                }
                None => {
                    headers.insert(k, v);
                }
            }
        }
    }
    Ok(Headers {
        status,
        content_type,
        chunked,
        content_length,
        headers,
    })
}

fn read_until_headers<R: Read + ?Sized>(tls: &mut R) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            let leftover = buf[pos + 4..].to_vec();
            buf.truncate(pos);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_HEAD {
            return Err("响应头超过上限".into());
        }
        match tls.read(&mut tmp) {
            Ok(0) => return Err("读响应头时连接关闭".into()),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => return Err("读响应头 EOF".into()),
            Err(e) => return Err(format!("读响应头失败: {}", e)),
        }
    }
}

fn stream_chunked<R: Read + ?Sized, F: FnMut(&[u8]) -> Result<(), String>>(
    mut buf: Vec<u8>,
    tls: &mut R,
    mut sink: F,
) -> Result<(), String> {
    let mut tmp = [0u8; 16384];
    let mut total = 0usize;
    loop {
        let p = loop {
            if let Some(p) = find(&buf, b"\r\n") {
                break p;
            }
            let n = tls
                .read(&mut tmp)
                .map_err(|e| format!("读 chunk 头失败: {}", e))?;
            if n == 0 {
                return Err("chunked 提前 EOF".into());
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&buf[..p])
                .trim()
                .split(';')
                .next()
                .unwrap_or("0")
                .trim(),
            16,
        )
        .map_err(|_| "chunk size 解析失败".to_string())?;
        buf.drain(..p + 2);
        if size == 0 {
            break;
        }
        total += size;
        if total > MAX_RESP {
            return Err("响应体超过上限".into());
        }
        while buf.len() < size + 2 {
            let n = tls
                .read(&mut tmp)
                .map_err(|e| format!("读 chunk 体失败: {}", e))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let take = size.min(buf.len());
        sink(&buf[..take])?;
        buf.drain(..take);
        if buf.len() >= 2 && &buf[..2] == b"\r\n" {
            buf.drain(..2);
        }
    }
    Ok(())
}

fn stream_plain<R: Read + ?Sized, F: FnMut(&[u8]) -> Result<(), String>>(
    initial: Vec<u8>,
    tls: &mut R,
    content_length: Option<usize>,
    mut sink: F,
) -> Result<(), String> {
    let mut total = 0usize;
    let mut tmp = [0u8; 16384];
    if let Some(cl) = content_length {
        if cl > MAX_RESP {
            return Err("响应体超过上限".into());
        }
        let initial_body = initial.len().min(cl);
        if initial_body > 0 {
            total += initial_body;
            sink(&initial[..initial_body])?;
        }
        while total < cl {
            let remaining = cl - total;
            let limit = remaining.min(tmp.len());
            match tls.read(&mut tmp[..limit]) {
                Ok(0) => {
                    return Err(format!(
                        "content-length 响应提前 EOF: got {} of {}",
                        total, cl
                    ));
                }
                Ok(n) => {
                    total += n;
                    sink(&tmp[..n])?;
                }
                Err(ref e)
                    if e.kind() == ErrorKind::UnexpectedEof
                        || e.kind() == ErrorKind::ConnectionAborted =>
                {
                    return Err(format!(
                        "content-length 响应提前 EOF: got {} of {}",
                        total, cl
                    ));
                }
                Err(e) => return Err(format!("读响应体失败: {}", e)),
            }
        }
        return Ok(());
    }

    if !initial.is_empty() {
        total += initial.len();
        if total > MAX_RESP {
            return Err("响应体超过上限".into());
        }
        sink(&initial)?;
    }
    loop {
        match tls.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total > MAX_RESP {
                    return Err("响应体超过上限".into());
                }
                sink(&tmp[..n])?;
            }
            Err(ref e)
                if e.kind() == ErrorKind::UnexpectedEof
                    || e.kind() == ErrorKind::ConnectionAborted =>
            {
                break
            }
            Err(e) => return Err(format!("读响应体失败: {}", e)),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_attested_trailer(
    s: &mut VsockStream,
    backend: &ProofBackend,
    m: &Metrics,
    head: &ReqHead,
    nonce_bytes: &[u8],
    norm_method: &str,
    status: u16,
    content_type: &str,
    req_body_hex: &str,
    resp_body_hex: &str,
    field_claims: Option<&Value>,
) -> Result<(), String> {
    if !no_crlf(content_type) {
        return write_proof_unavailable_trailer(
            s,
            head,
            norm_method,
            status,
            content_type,
            req_body_hex,
            resp_body_hex,
            "invalid_content_type",
            "上游 content-type 含非法 CR/LF",
        );
    }
    let norm_host = head.upstream.host.to_lowercase();
    let norm_path = path_no_query(&head.upstream.path).to_string();
    match backend {
        ProofBackend::LocalEvidence(local) => write_local_attested_trailer(
            s,
            local,
            m,
            head,
            nonce_bytes,
            norm_method,
            status,
            content_type,
            req_body_hex,
            resp_body_hex,
            field_claims,
            &norm_host,
            &norm_path,
        ),
        ProofBackend::AliyunVtpm(aliyun) => write_aliyun_vtpm_trailer(
            s,
            aliyun,
            head,
            norm_method,
            status,
            content_type,
            req_body_hex,
            resp_body_hex,
            field_claims,
            &norm_host,
            &norm_path,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn write_local_attested_trailer(
    s: &mut VsockStream,
    local: &LocalEvidenceBackend,
    m: &Metrics,
    head: &ReqHead,
    nonce_bytes: &[u8],
    norm_method: &str,
    status: u16,
    content_type: &str,
    req_body_hex: &str,
    resp_body_hex: &str,
    field_claims: Option<&Value>,
    norm_host: &str,
    norm_path: &str,
) -> Result<(), String> {
    let statement = build_v2_statement(
        &head.nonce,
        norm_host,
        norm_path,
        norm_method,
        status,
        content_type,
        req_body_hex,
        resp_body_hex,
        field_claims,
    );
    let sig = local.sk.sign(&statement).to_bytes();
    let t_nsm = Instant::now();
    let evidence = match local.evidence_provider.attest(&local.spki, nonce_bytes) {
        Ok(evidence) => evidence,
        Err(e) => {
            return write_proof_unavailable_trailer(
                s,
                head,
                norm_method,
                status,
                content_type,
                req_body_hex,
                resp_body_hex,
                "attestation_failed",
                &e,
            );
        }
    };
    m.nsm_ns_total
        .fetch_add(t_nsm.elapsed().as_nanos() as u64, Ordering::Relaxed);
    m.nsm_calls.fetch_add(1, Ordering::Relaxed);
    let mut trailer = json!({
        "v": 2,
        "alg": "ed25519",
        "public_key": B64.encode(&local.spki),
        "nonce": head.nonce,
        "upstream_host": norm_host,
        "upstream_path": norm_path,
        "http_method": norm_method,
        "http_status": status,
        "resp_content_type": content_type,
        "request_body_sha256": req_body_hex,
        "response_body_sha256": resp_body_hex,
        "signature": B64.encode(sig),
        "attestation": B64.encode(&evidence.attestation),
    });
    let trailer_obj = trailer
        .as_object_mut()
        .expect("proof trailer is a JSON object");
    if evidence.profile != "nitro" {
        trailer_obj.insert("profile".into(), json!(evidence.profile));
    }
    if let Some(pcr0) = evidence.pcr0 {
        trailer_obj.insert("pcr0".into(), json!(pcr0));
    }
    if let Some(pcr8) = evidence.pcr8 {
        trailer_obj.insert("pcr8".into(), json!(pcr8));
    }
    if !evidence.measurements.is_empty() {
        trailer_obj.insert("measurements".into(), json!(evidence.measurements));
    }
    if let Some(claims) = field_claims {
        trailer_obj.insert("field_claims".into(), claims.clone());
    }
    write_frame(s, RESP_TRAILER, trailer.to_string().as_bytes())
        .map_err(|e| format!("写 RESP_TRAILER: {e}"))
}

#[allow(clippy::too_many_arguments)]
fn write_aliyun_vtpm_trailer(
    s: &mut VsockStream,
    aliyun: &AliyunBackend,
    head: &ReqHead,
    norm_method: &str,
    status: u16,
    content_type: &str,
    req_body_hex: &str,
    resp_body_hex: &str,
    field_claims: Option<&Value>,
    norm_host: &str,
    norm_path: &str,
) -> Result<(), String> {
    let req = aliyun_helper::ProofRequest::new(
        &head.nonce,
        norm_host,
        norm_path,
        norm_method,
        status,
        content_type,
        req_body_hex,
        resp_body_hex,
        field_claims,
    );
    let proof = match aliyun_helper::request_proof(&aliyun.socket_path, &req) {
        Ok(proof) => proof,
        Err(e) => {
            return write_proof_unavailable_trailer(
                s,
                head,
                norm_method,
                status,
                content_type,
                req_body_hex,
                resp_body_hex,
                "attestation_failed",
                &e,
            );
        }
    };
    write_frame(s, RESP_TRAILER, &proof).map_err(|e| format!("写 RESP_TRAILER: {e}"))
}

#[allow(clippy::too_many_arguments)]
fn write_proof_unavailable_trailer(
    s: &mut VsockStream,
    head: &ReqHead,
    norm_method: &str,
    status: u16,
    content_type: &str,
    req_body_hex: &str,
    resp_body_hex: &str,
    code: &str,
    message: &str,
) -> Result<(), String> {
    let payload = build_proof_unavailable_payload(
        head,
        norm_method,
        status,
        content_type,
        req_body_hex,
        resp_body_hex,
        code,
        message,
    );
    write_frame(s, RESP_TRAILER, payload.to_string().as_bytes())
        .map_err(|e| format!("写 proof_unavailable RESP_TRAILER: {e}"))
}

#[allow(clippy::too_many_arguments)]
fn build_proof_unavailable_payload(
    head: &ReqHead,
    norm_method: &str,
    status: u16,
    content_type: &str,
    req_body_hex: &str,
    resp_body_hex: &str,
    code: &str,
    message: &str,
) -> Value {
    json!({
        "type": "tee.proof_unavailable",
        "code": code,
        "message": message,
        "attested": false,
        "upstream_host": head.upstream.host.to_ascii_lowercase(),
        "upstream_path": path_no_query(&head.upstream.path),
        "http_method": norm_method.to_ascii_uppercase(),
        "http_status": status,
        "resp_content_type": content_type,
        "request_body_sha256": req_body_hex,
        "response_body_sha256": resp_body_hex,
    })
}

fn handle(s: &mut VsockStream, backend: &ProofBackend, m: &Metrics) -> Result<(), String> {
    let (t1, head_buf) = read_frame(s, MAX_REQ_HEAD).map_err(|e| format!("读 HEAD 帧: {}", e))?;
    if t1 != REQ_HEAD {
        return Err(format!("期望 REQ_HEAD，收到 {:#x}", t1));
    }
    let head: ReqHead =
        serde_json::from_slice(&head_buf).map_err(|e| format!("HEAD JSON: {}", e))?;
    drop(head_buf);
    let (t2, body) = read_frame(s, MAX_REQ_FRAME).map_err(|e| format!("读 BODY 帧: {}", e))?;
    if t2 != REQ_BODY {
        return Err(format!("期望 REQ_BODY，收到 {:#x}", t2));
    }
    let req_body_hex = {
        let mut hh = Sha256::new();
        hh.update(&body);
        hex(&hh.finalize())
    };
    let nonce_bytes = B64
        .decode(head.nonce.as_bytes())
        .map_err(|e| format!("nonce base64: {}", e))?;

    if !no_crlf(&head.upstream.host)
        || !no_crlf(&head.upstream.method)
        || !no_crlf(&head.upstream.path)
    {
        return Err("upstream host/method/path 含非法 CR/LF".into());
    }
    for (k, v) in &head.upstream.headers {
        if !no_crlf(k) || !no_crlf(v) {
            return Err("请求头含非法 CR/LF".into());
        }
    }
    if let Some(tok) = &head.token {
        if !no_crlf(tok) {
            return Err("token 含非法 CR/LF".into());
        }
    }

    let profile = decode_profile(&head);
    let seed = head.tls_seed.as_deref().and_then(|s| B64.decode(s).ok());
    let sock = connect_egress(head.egress_port)?;
    set_egress_timeouts(&sock, UPSTREAM_IO_TIMEOUT);
    let norm_method = head.upstream.method.to_uppercase();
    if profile.as_ref().map(|p| p.stack) == Some(tls_profile::Stack::RustlsAwsLc) {
        let profile = profile.as_ref().unwrap();
        let mut tls = egress_rustls_aws_lc::connect(profile, sock, &head.upstream.host)
            .map_err(|e| format!("rustls/aws-lc 出口: {e}"))?;
        while tls.conn.is_handshaking() {
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|e| format!("rustls/aws-lc handshake: {e}"))?;
        }
        if tls.conn.alpn_protocol() != Some(b"h2") {
            return Err(format!(
                "Grok upstream did not negotiate h2: {:?}",
                tls.conn.alpn_protocol()
            ));
        }
        set_egress_timeouts(&tls.sock, Duration::from_millis(250));
        let h2 = profile
            .h2
            .as_ref()
            .ok_or_else(|| "Grok profile missing h2 fingerprint".to_string())?;
        let ordered = parse_headers_ordered(&head.upstream.headers_ordered).unwrap_or_else(|| {
            head.upstream
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        });
        let (response, resp_body_hex, content_type, field_claims) = {
            let mut sink = AttestedH2Sink {
                control: s,
                hasher: Sha256::new(),
                field_collector: None,
                head: &head,
                req_body: &body,
                content_type: String::new(),
            };
            let response = h2_client::execute(
                tls,
                h2,
                &head.upstream.host,
                &norm_method,
                &head.upstream.path,
                &ordered,
                head.token.as_deref(),
                &body,
                MAX_RESP,
                &mut sink,
            )?;
            let AttestedH2Sink {
                hasher,
                field_collector,
                content_type,
                ..
            } = sink;
            let resp_body_hex = hex(&hasher.finalize());
            let field_claims =
                field_collector.and_then(|c| c.finish(&head, &norm_method, response.status));
            (response, resp_body_hex, content_type, field_claims)
        };
        m.resp_bytes_total
            .fetch_add(response.body_bytes as u64, Ordering::Relaxed);
        write_attested_trailer(
            s,
            backend,
            m,
            &head,
            &nonce_bytes,
            &norm_method,
            response.status,
            &content_type,
            &req_body_hex,
            &resp_body_hex,
            field_claims.as_ref(),
        )?;
        return Ok(());
    }
    let mut tls: Box<dyn ReadWrite> = match profile.as_ref().map(|p| p.stack) {
        Some(tls_profile::Stack::Boring) => Box::new(
            egress_boring::connect(
                profile.as_ref().unwrap(),
                sock,
                &head.upstream.host,
                seed.as_deref(),
            )
            .map_err(|e| format!("btls 出口: {}", e))?,
        ),
        Some(tls_profile::Stack::OpenSsl) => Box::new(
            egress_openssl::connect(
                profile.as_ref().unwrap(),
                sock,
                &head.upstream.host,
                seed.as_deref(),
            )
            .map_err(|e| format!("openssl 出口: {}", e))?,
        ),
        Some(tls_profile::Stack::RustlsAwsLc) => unreachable!("handled by h2 branch"),
        _ => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            // 两个 provider 同时编入后必须显式选 ring；保持历史无画像兜底逐字节不变。
            let config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("rustls/ring versions: {}", e))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            let server_name = ServerName::try_from(head.upstream.host.clone())
                .map_err(|e| format!("SNI 非法: {:?}", e))?;
            let conn = ClientConnection::new(Arc::new(config), server_name)
                .map_err(|e| format!("TLS 初始化失败: {}", e))?;
            Box::new(rustls::StreamOwned::new(conn, sock))
        }
    };

    // When an ordered header template is supplied, emit headers verbatim (exact
    // order/case). Otherwise fall back to the map path (sorted + lowercased +
    // connection: close), byte-identical to before.
    let req = match parse_headers_ordered(&head.upstream.headers_ordered) {
        Some(ordered) => build_request_head_ordered(
            &norm_method,
            &head.upstream.path,
            &head.upstream.host,
            &ordered,
            head.token.as_deref(),
            body.len(),
        ),
        None => {
            let mut req = format!("{} {} HTTP/1.1\r\n", norm_method, head.upstream.path);
            req.push_str(&format!("host: {}\r\n", head.upstream.host));
            for (k, v) in &head.upstream.headers {
                let lk = k.to_lowercase();
                if lk == "host"
                    || lk == "authorization"
                    || lk == "content-length"
                    || lk == "connection"
                    || lk == "transfer-encoding"
                    || lk == "te"
                    || lk == "trailer"
                    || lk == "upgrade"
                    || lk == "proxy-connection"
                    || lk == "keep-alive"
                {
                    continue;
                }
                req.push_str(&format!("{}: {}\r\n", k, v));
            }
            if let Some(tok) = &head.token {
                req.push_str(&format!("authorization: Bearer {}\r\n", tok));
            }
            req.push_str(&format!("content-length: {}\r\n", body.len()));
            req.push_str("connection: close\r\n\r\n");
            req
        }
    };

    tls.write_all(req.as_bytes())
        .map_err(|e| format!("TLS 写请求头失败: {}", e))?;
    tls.write_all(&body)
        .map_err(|e| format!("TLS 写请求体失败: {}", e))?;
    tls.flush().ok();

    let (head_bytes, leftover) = read_until_headers(&mut *tls)?;
    let h = parse_headers(&head_bytes)?;

    write_frame(
        s,
        RESP_HEAD,
        json!({ "status": h.status, "headers": h.headers })
            .to_string()
            .as_bytes(),
    )
    .map_err(|e| format!("写 RESP_HEAD: {}", e))?;

    let mut hasher = Sha256::new();
    let mut streamed = 0usize;
    let content_type = h.content_type.as_deref().unwrap_or("");
    let mut field_collector = FieldResponseCollector::new(&head, &body, content_type);
    {
        let mut sink = |bytes: &[u8]| -> Result<(), String> {
            hasher.update(bytes);
            if let Some(collector) = field_collector.as_mut() {
                collector.push(bytes);
            }
            streamed += bytes.len();
            write_frame(s, RESP_CHUNK, bytes).map_err(|e| format!("写 RESP_CHUNK: {}", e))
        };
        if h.chunked {
            stream_chunked(leftover, &mut *tls, &mut sink)?;
        } else {
            stream_plain(leftover, &mut *tls, h.content_length, &mut sink)?;
        }
    }
    let d_body = hasher.finalize();
    m.resp_bytes_total
        .fetch_add(streamed as u64, Ordering::Relaxed);

    let resp_body_hex = hex(&d_body);
    let field_claims = field_collector.and_then(|c| c.finish(&head, &norm_method, h.status));
    write_attested_trailer(
        s,
        backend,
        m,
        &head,
        &nonce_bytes,
        &norm_method,
        h.status,
        content_type,
        &req_body_hex,
        &resp_body_hex,
        field_claims.as_ref(),
    )
}

#[derive(Default)]
struct Metrics {
    accepted: AtomicU64,
    shed: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    panicked: AtomicU64,
    in_flight: AtomicUsize,
    in_flight_max: AtomicUsize,
    queue_depth: AtomicUsize,
    queue_depth_max: AtomicUsize,
    handle_ns_total: AtomicU64,
    nsm_ns_total: AtomicU64,
    nsm_calls: AtomicU64,
    resp_bytes_total: AtomicU64,
}

impl Metrics {
    fn snapshot(&self) -> String {
        let r = Ordering::Relaxed;
        let done = self.completed.load(r) + self.failed.load(r) + self.panicked.load(r);
        let round2 = |x: f64| (x * 100.0).round() / 100.0;
        let avg_handle_ms = if done > 0 {
            round2(self.handle_ns_total.load(r) as f64 / done as f64 / 1.0e6)
        } else {
            0.0
        };
        let nc = self.nsm_calls.load(r);
        let avg_nsm_ms = if nc > 0 {
            round2(self.nsm_ns_total.load(r) as f64 / nc as f64 / 1.0e6)
        } else {
            0.0
        };
        json!({
            "n_workers": N_WORKERS,
            "queue_cap": QUEUE_CAP,
            "accepted": self.accepted.load(r),
            "shed": self.shed.load(r),
            "completed": self.completed.load(r),
            "failed": self.failed.load(r),
            "panicked": self.panicked.load(r),
            "in_flight": self.in_flight.load(r),
            "in_flight_max": self.in_flight_max.load(r),
            "queue_depth": self.queue_depth.load(r),
            "queue_depth_max": self.queue_depth_max.load(r),
            "avg_handle_ms": avg_handle_ms,
            "avg_nsm_ms": avg_nsm_ms,
            "nsm_calls": nc,
            "resp_bytes_total": self.resp_bytes_total.load(r),
        })
        .to_string()
    }
}

fn bump_max(cur: usize, max: &AtomicUsize) {
    let mut m = max.load(Ordering::Relaxed);
    while cur > m {
        match max.compare_exchange_weak(m, cur, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => m = x,
        }
    }
}

struct Ctx {
    backend: ProofBackend,
    m: Metrics,
}

struct LocalEvidenceBackend {
    sk: SigningKey,
    spki: Vec<u8>,
    evidence_provider: Arc<dyn EvidenceProvider>,
}

struct AliyunBackend {
    socket_path: String,
}

enum ProofBackend {
    LocalEvidence(LocalEvidenceBackend),
    AliyunVtpm(AliyunBackend),
}

fn worker(rx: Arc<Mutex<Receiver<VsockStream>>>, ctx: Arc<Ctx>) {
    loop {
        let job = { rx.lock().unwrap().recv() };
        let mut s = match job {
            Ok(s) => s,
            Err(_) => return,
        };
        ctx.m.queue_depth.fetch_sub(1, Ordering::Relaxed);
        let now = ctx.m.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        bump_max(now, &ctx.m.in_flight_max);
        let start = Instant::now();

        s.set_read_timeout(Some(CONTROL_IO_TIMEOUT)).ok();
        s.set_write_timeout(Some(CONTROL_IO_TIMEOUT)).ok();
        let res = catch_unwind(AssertUnwindSafe(|| handle(&mut s, &ctx.backend, &ctx.m)));

        ctx.m
            .handle_ns_total
            .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        ctx.m.in_flight.fetch_sub(1, Ordering::Relaxed);
        match res {
            Ok(Ok(())) => {
                ctx.m.completed.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Err(e)) => {
                ctx.m.failed.fetch_add(1, Ordering::Relaxed);
                elog!("handle error: {}", e);
                let _ = write_frame(
                    &mut s,
                    ERR,
                    json!({ "code": "enclave", "message": e })
                        .to_string()
                        .as_bytes(),
                );
            }
            Err(_) => {
                ctx.m.panicked.fetch_add(1, Ordering::Relaxed);
                elog!("handle panicked (caught)");
            }
        }
    }
}

fn serve_metrics(ctx: Arc<Ctx>) {
    let l = match VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, METRICS_PORT)) {
        Ok(l) => l,
        Err(e) => {
            elog!("metrics bind 失败: {}", e);
            return;
        }
    };
    for stream in l.incoming() {
        if let Ok(mut s) = stream {
            s.set_write_timeout(Some(ADMIN_TIMEOUT)).ok();
            let _ = write_frame(&mut s, STATS, ctx.m.snapshot().as_bytes());
        }
    }
}

fn configured_tee_profile() -> String {
    env::var("TEE_PROFILE")
        .or_else(|_| env::var("POO_EVIDENCE_PROFILE"))
        .unwrap_or_else(|_| "nitro".to_string())
        .to_ascii_lowercase()
}

fn build_evidence_provider(profile: &str) -> Arc<dyn EvidenceProvider> {
    match profile {
        "" | "nitro" => {
            #[cfg(feature = "nitro")]
            {
                Arc::new(evidence_nitro::NitroEvidenceProvider::new())
            }
            #[cfg(not(feature = "nitro"))]
            {
                panic!("TEE_PROFILE=nitro but binary was built without the nitro feature");
            }
        }
        "qingtian" => {
            #[cfg(feature = "qingtian")]
            {
                Arc::new(
                    evidence_qingtian::QingTianEvidenceProvider::new().unwrap_or_else(|e| {
                        panic!("failed to initialize QingTian QTSM provider: {e}")
                    }),
                )
            }
            #[cfg(not(feature = "qingtian"))]
            {
                panic!("TEE_PROFILE=qingtian but binary was built without the qingtian feature");
            }
        }
        other => {
            panic!(
                "unsupported local evidence profile={other}; supported profiles: nitro, qingtian"
            );
        }
    }
}

fn build_local_evidence_backend(profile: &str) -> LocalEvidenceBackend {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key().to_bytes();
    let mut spki = vec![
        0x30u8, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(&vk);
    let evidence_provider = build_evidence_provider(profile);
    elog!("evidence profile: {}", evidence_provider.profile());
    LocalEvidenceBackend {
        sk,
        spki,
        evidence_provider,
    }
}

fn main() {
    let profile = configured_tee_profile();
    let backend = match profile.as_str() {
        "" | "nitro" | "qingtian" => {
            ProofBackend::LocalEvidence(build_local_evidence_backend(profile.as_str()))
        }
        "aliyun-vtpm" => ProofBackend::AliyunVtpm(AliyunBackend {
            socket_path: std::env::var("ALIYUN_PROOF_HELPER_SOCKET")
                .unwrap_or_else(|_| DEFAULT_ALIYUN_HELPER_SOCKET.to_string()),
        }),
        other => panic!(
            "unsupported TEE_PROFILE={other}; supported profiles: nitro, qingtian, aliyun-vtpm"
        ),
    };
    let ctx = Arc::new(Ctx {
        backend,
        m: Metrics::default(),
    });

    let (tx, rx) = sync_channel::<VsockStream>(QUEUE_CAP);
    let rx = Arc::new(Mutex::new(rx));
    let mut spawned = 0usize;
    for i in 0..N_WORKERS {
        let rx = Arc::clone(&rx);
        let ctx = Arc::clone(&ctx);
        match thread::Builder::new()
            .name(format!("worker-{}", i))
            .spawn(move || worker(rx, ctx))
        {
            Ok(_) => spawned += 1,
            Err(e) => elog!("起 worker {} 失败（非致命）: {}", i, e),
        }
    }

    {
        let ctx = Arc::clone(&ctx);
        if let Err(e) = thread::Builder::new()
            .name("metrics".into())
            .spawn(move || serve_metrics(ctx))
        {
            elog!("起 metrics 线程失败（非致命）: {}", e);
        }
    }

    let listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, PORT)).expect("bind vsock");
    elog!(
        "listening on vsock :{} (workers={}/{}, queue={}), metrics :{}",
        PORT,
        spawned,
        N_WORKERS,
        QUEUE_CAP,
        METRICS_PORT
    );

    for stream in listener.incoming() {
        let s = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let q = ctx.m.queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        bump_max(q, &ctx.m.queue_depth_max);
        match tx.try_send(s) {
            Ok(()) => {
                ctx.m.accepted.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(mut s)) => {
                ctx.m.queue_depth.fetch_sub(1, Ordering::Relaxed);
                ctx.m.shed.fetch_add(1, Ordering::Relaxed);
                s.set_write_timeout(Some(ADMIN_TIMEOUT)).ok();
                let _ = write_frame(
                    &mut s,
                    ERR,
                    json!({ "code": "busy", "message": "enclave at capacity, retry" })
                        .to_string()
                        .as_bytes(),
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                ctx.m.queue_depth.fetch_sub(1, Ordering::Relaxed);
                break;
            }
        }
    }
}

#[cfg(test)]
mod parent_cid_tests {
    use super::*;

    #[test]
    fn parent_cid_candidates_default_to_nitro_compatible_parent() {
        assert_eq!(
            parse_parent_cid_candidates(None).unwrap(),
            vec![DEFAULT_PARENT_CID]
        );
    }

    #[test]
    fn parent_cid_candidates_parse_lists_trim_and_deduplicate() {
        assert_eq!(
            parse_parent_cid_candidates(Some(" 3, 2,3, 4 ")).unwrap(),
            vec![3, 2, 4]
        );
    }

    #[test]
    fn parent_cid_candidates_reject_empty_or_invalid_values() {
        assert!(parse_parent_cid_candidates(Some(" , ")).is_err());
        assert!(parse_parent_cid_candidates(Some("3,nope")).is_err());
    }

    #[test]
    fn egress_mode_defaults_to_direct_vsock() {
        assert_eq!(parse_egress_mode(None).unwrap(), EgressMode::DirectVsock);
        assert_eq!(
            parse_egress_mode(Some(" vsock ")).unwrap(),
            EgressMode::DirectVsock
        );
    }

    #[test]
    fn egress_mode_accepts_qproxy_aliases() {
        assert_eq!(
            parse_egress_mode(Some("qproxy")).unwrap(),
            EgressMode::QProxyTcp
        );
        assert_eq!(
            parse_egress_mode(Some("QPROXY-TCP")).unwrap(),
            EgressMode::QProxyTcp
        );
    }

    #[test]
    fn egress_mode_rejects_unknown_values() {
        assert!(parse_egress_mode(Some("http-proxy")).is_err());
    }
}

#[cfg(test)]
mod response_stream_tests {
    use super::stream_plain;
    use std::io::{Cursor, Error, ErrorKind, Read, Result as IoResult};

    #[test]
    fn content_length_short_read_is_rejected() {
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut out = Vec::new();
        let err = stream_plain(b"abc".to_vec(), &mut reader, Some(5), |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .expect_err("short content-length body must fail");

        assert!(err.contains("content-length 响应提前 EOF"));
        assert_eq!(out, b"abc");
    }

    #[test]
    fn content_length_unexpected_eof_is_rejected() {
        struct OneThenUnexpectedEof {
            sent: bool,
        }

        impl Read for OneThenUnexpectedEof {
            fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
                if !self.sent {
                    self.sent = true;
                    buf[0] = b'a';
                    return Ok(1);
                }
                Err(Error::new(ErrorKind::UnexpectedEof, "truncated"))
            }
        }

        let mut reader = OneThenUnexpectedEof { sent: false };
        let mut out = Vec::new();
        let err = stream_plain(Vec::new(), &mut reader, Some(2), |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .expect_err("unexpected EOF before content-length must fail");

        assert!(err.contains("content-length 响应提前 EOF"));
        assert_eq!(out, b"a");
    }

    #[test]
    fn content_length_only_forwards_declared_initial_bytes() {
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut out = Vec::new();
        stream_plain(b"abcdef".to_vec(), &mut reader, Some(3), |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .expect("declared content-length bytes are complete");

        assert_eq!(out, b"abc");
    }

    #[test]
    fn close_delimited_response_still_reads_to_eof() {
        let mut reader = Cursor::new(b"def".to_vec());
        let mut out = Vec::new();
        stream_plain(b"abc".to_vec(), &mut reader, None, |bytes| {
            out.extend_from_slice(bytes);
            Ok(())
        })
        .expect("close-delimited body can end at EOF");

        assert_eq!(out, b"abcdef");
    }
}

#[cfg(test)]
mod field_claims_tests {
    use super::{
        build_field_claims, build_proof_unavailable_payload, canonical_json, field_policy_registry,
        field_view, FieldResponseCollector, ReqHead, Upstream, MAX_FIELD_CLAIMS_CAPTURE,
        SUPPORTED_PROTOCOLS,
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn head(path: &str) -> ReqHead {
        ReqHead {
            nonce: "bm9uY2U=".to_string(),
            egress_port: 8444,
            upstream: Upstream {
                host: "api.example.com".to_string(),
                method: "POST".to_string(),
                path: path.to_string(),
                headers: BTreeMap::new(),
                headers_ordered: None,
            },
            token: None,
            client_protocol_family: None,
            downstream_protocol_family: None,
            protocol_family: None,
            tls_seed: None,
            tls_spec: None,
        }
    }

    fn assert_same_response_view(protocol: &str, stream: &[u8], merged: &[u8]) {
        let stream_view = field_view(protocol, "response", stream, None);
        let merged_view = field_view(protocol, "response", merged, None);
        assert_eq!(canonical_json(&stream_view), canonical_json(&merged_view));
    }

    fn assert_streaming_collector_matches_body_claims(path: &str, request: &[u8], stream: &[u8]) {
        let head = head(path);
        let buffered =
            build_field_claims(&head, "POST", 200, request, stream).expect("body-backed claims");
        let mut collector =
            FieldResponseCollector::new(&head, request, "text/event-stream; charset=utf-8")
                .expect("streaming collector");
        for chunk in stream.chunks(17) {
            collector.push(chunk);
        }
        let streamed = collector
            .finish(&head, "POST", 200)
            .expect("streaming claims");
        assert_eq!(canonical_json(&streamed), canonical_json(&buffered));
    }

    fn aws_eventstream_message(payload: &[u8]) -> Vec<u8> {
        let total_len = 12 + payload.len() + 4;
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&(total_len as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }

    #[test]
    fn missing_required_request_fields_do_not_build_field_claims() {
        let claims = build_field_claims(
            &head("/v1/chat/completions"),
            "POST",
            200,
            br#"{"model":"gpt-test"}"#,
            br#"{"choices":[{"message":{"content":"ok"}}]}"#,
        );
        assert!(claims.is_none());
    }

    #[test]
    fn openai_chat_sse_rechunking_keeps_same_semantic_view() {
        let split = b"data: {\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"he\"},\"finish_reason\":null}]}\n\ndata: {\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"llo\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"total_tokens\":3}}\n\ndata: [DONE]\n\n";
        let merged = b"data: {\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hello\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"total_tokens\":3}}\n\ndata: [DONE]\n\n";
        let split_view = field_view("openai.chat_completions", "response", split, None);
        let merged_view = field_view("openai.chat_completions", "response", merged, None);
        assert_eq!(canonical_json(&split_view), canonical_json(&merged_view));
    }

    #[test]
    fn bedrock_converse_model_id_is_extracted_from_path() {
        let path = "/model/anthropic.claude-3-sonnet-20240229-v1%3A0/converse";
        let request = br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}],"inferenceConfig":{"maxTokens":64}}"#;
        let response = br#"{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":1}}"#;
        let request_view = field_view("aws.bedrock.converse", "request", request, Some(path));
        assert_eq!(
            request_view
                .get("modelId")
                .and_then(serde_json::Value::as_str),
            Some("anthropic.claude-3-sonnet-20240229-v1%3A0")
        );
        let claims = build_field_claims(&head(path), "POST", 200, request, response);
        assert!(claims.is_some());
    }

    #[test]
    fn anthropic_messages_sse_rechunking_keeps_same_semantic_view() {
        let stream = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-test\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":3}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"he\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"llo\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":2}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let merged = br#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":3,"output_tokens":2}}"#;
        assert_same_response_view("anthropic.messages", stream, merged);
    }

    #[test]
    fn openai_responses_sse_rechunking_keeps_same_semantic_view() {
        let stream = b"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\",\"output\":[]}}\n\ndata: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}\n\ndata: {\"type\":\"response.content_part.added\",\"output_index\":0,\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"\"}}\n\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"he\"}\n\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"llo\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"hello\"}]}],\"usage\":{\"total_tokens\":3}}}\n\n";
        let merged = br#"{"id":"resp_1","status":"completed","output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}],"usage":{"total_tokens":3}}"#;
        assert_same_response_view("openai.responses", stream, merged);
    }

    #[test]
    fn openai_responses_done_events_replace_final_values() {
        let stream = b"data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}\n\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"he\"}\n\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"llo\"}\n\ndata: {\"type\":\"response.output_text.done\",\"output_index\":0,\"content_index\":0,\"text\":\"hello\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"total_tokens\":3}}}\n\n";
        let merged = br#"{"id":"resp_1","status":"completed","output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}],"usage":{"total_tokens":3}}"#;
        assert_same_response_view("openai.responses", stream, merged);
    }

    #[test]
    fn openai_responses_request_hash_ignores_instructions() {
        let with_instructions = br#"{"model":"qwen3.7-plus","input":[{"role":"user","content":"hi"}],"instructions":"answer carefully","temperature":0.7,"stream":false}"#;
        let without_instructions =
            br#"{"model":"qwen3.7-plus","input":[{"role":"user","content":"hi"}],"temperature":0.7,"stream":false}"#;
        let with_view = field_view("openai.responses", "request", with_instructions, None);
        let without_view = field_view("openai.responses", "request", without_instructions, None);
        assert_eq!(canonical_json(&with_view), canonical_json(&without_view));
    }

    #[test]
    fn field_policy_version_is_protocol_specific() {
        let chat_request = br#"{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}"#;
        let chat_response = br#"{"choices":[{"message":{"content":"ok"}}]}"#;
        let chat_claims = build_field_claims(
            &head("/v1/chat/completions"),
            "POST",
            200,
            chat_request,
            chat_response,
        )
        .expect("chat claims");
        assert_eq!(
            chat_claims
                .get("field_policy_id")
                .and_then(serde_json::Value::as_str),
            Some("openai.chat_completions.default@2026-07-27")
        );

        let responses_request = br#"{"model":"gpt-test","input":[{"role":"user","content":"hi"}]}"#;
        let responses_response = br#"{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]}"#;
        let responses_claims = build_field_claims(
            &head("/v1/responses"),
            "POST",
            200,
            responses_request,
            responses_response,
        )
        .expect("responses claims");
        assert_eq!(
            responses_claims
                .get("field_policy_id")
                .and_then(serde_json::Value::as_str),
            Some("openai.responses.default@2026-07-29")
        );
    }

    #[test]
    fn field_policy_registry_covers_all_supported_protocols() {
        let registry = field_policy_registry();
        for protocol in SUPPORTED_PROTOCOLS {
            let version = registry.protocol_versions.get(*protocol);
            assert!(
                matches!(version, Some(v) if !v.is_empty()),
                "missing field policy version for supported protocol: {}",
                protocol
            );
        }
    }

    #[test]
    fn multiline_sse_data_is_parsed_as_one_event() {
        let stream = b"data: {\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\ndata: \"delta\":{\"role\":\"assistant\",\"content\":\"hello\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n";
        let merged = b"data: {\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hello\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n";
        assert_same_response_view("openai.chat_completions", stream, merged);
    }

    #[test]
    fn streaming_collector_matches_body_claims_for_supported_protocols() {
        assert_streaming_collector_matches_body_claims(
            "/v1/chat/completions",
            br#"{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"stream":true}"#,
            b"data: {\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"he\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"llo\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        );
        assert_streaming_collector_matches_body_claims(
            "/v1/responses",
            br#"{"model":"gpt-test","input":"hello","stream":true}"#,
            b"data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}\n\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"hello\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"total_tokens\":3}}}\n\n",
        );
        assert_streaming_collector_matches_body_claims(
            "/v1/messages",
            br#"{"model":"claude-test","messages":[{"role":"user","content":"hello"}],"max_tokens":16,"stream":true}"#,
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-test\",\"usage\":{\"input_tokens\":3}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
        );
        assert_streaming_collector_matches_body_claims(
            "/v1beta/models/gemini-test:generateContent?alt=sse",
            br#"{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}"#,
            b"data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"hello\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"totalTokenCount\":3}}\n\n",
        );
        assert_streaming_collector_matches_body_claims(
            "/api/v1/services/aigc/text-generation/generation",
            br#"{"model":"qwen-test","input":{"messages":[{"role":"user","content":"hello"}]},"parameters":{"stream":true}}"#,
            b"data: {\"output\":{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"hello\"},\"finish_reason\":\"stop\"}]},\"usage\":{\"total_tokens\":3},\"request_id\":\"req_1\"}\n\n",
        );
        assert_streaming_collector_matches_body_claims(
            "/model/anthropic.claude-3-sonnet-20240229-v1%3A0/converse-stream",
            br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}],"inferenceConfig":{"maxTokens":64}}"#,
            b"data: {\"messageStart\":{\"role\":\"assistant\"}}\n\ndata: {\"contentBlockDelta\":{\"contentBlockIndex\":0,\"delta\":{\"text\":\"hello\"}}}\n\ndata: {\"messageStop\":{\"stopReason\":\"end_turn\"}}\n\n",
        );
        assert_streaming_collector_matches_body_claims(
            "/v2/chat",
            br#"{"model":"command-test","messages":[{"role":"user","content":"hello"}],"stream":true}"#,
            b"data: {\"type\":\"message-start\",\"delta\":{\"message\":{\"role\":\"assistant\"}}}\n\ndata: {\"type\":\"content-delta\",\"delta\":{\"message\":{\"content\":{\"type\":\"text\",\"text\":\"hello\"}}}}\n\ndata: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"total_tokens\":3}}}\n\n",
        );
    }

    #[test]
    fn streaming_collector_sniffs_sse_when_content_type_is_not_event_stream() {
        let head = head("/v1/chat/completions");
        let request =
            br#"{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"stream":true}"#;
        let stream = b"data: {\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n";
        let buffered =
            build_field_claims(&head, "POST", 200, request, stream).expect("body-backed claims");
        let mut collector =
            FieldResponseCollector::new(&head, request, "application/json").expect("collector");
        for chunk in stream.chunks(9) {
            collector.push(chunk);
        }
        let sniffed = collector
            .finish(&head, "POST", 200)
            .expect("sniffed claims");
        assert_eq!(canonical_json(&sniffed), canonical_json(&buffered));
        assert_eq!(
            sniffed
                .get("streaming")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn bedrock_eventstream_collector_builds_field_claims() {
        let path = "/model/anthropic.claude-3-sonnet-20240229-v1%3A0/converse-stream";
        let head = head(path);
        let request =
            br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}],"inferenceConfig":{"maxTokens":64}}"#;
        let mut collector =
            FieldResponseCollector::new(&head, request, "application/vnd.amazon.eventstream")
                .expect("eventstream collector");
        let mut wire = Vec::new();
        wire.extend_from_slice(&aws_eventstream_message(
            br#"{"messageStart":{"role":"assistant"}}"#,
        ));
        wire.extend_from_slice(&aws_eventstream_message(
            br#"{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"hello"}}}"#,
        ));
        wire.extend_from_slice(&aws_eventstream_message(
            br#"{"messageStop":{"stopReason":"end_turn"}}"#,
        ));
        for chunk in wire.chunks(11) {
            collector.push(chunk);
        }
        let claims = collector
            .finish(&head, "POST", 200)
            .expect("eventstream claims");
        let expected_view = field_view(
            "aws.bedrock.converse",
            "response",
            br#"{"output":{"message":{"role":"assistant","content":[{"type":"text","text":"hello"}]}},"stopReason":"end_turn"}"#,
            Some(path),
        );
        let expected_hash = super::hex(&Sha256::digest(canonical_json(&expected_view).as_bytes()));
        assert_eq!(
            claims
                .get("upstream_response_fields_sha256")
                .and_then(serde_json::Value::as_str),
            Some(expected_hash.as_str())
        );
        assert_eq!(
            claims.get("streaming").and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn bedrock_request_hint_uses_eventstream_parser_without_event_stream_content_type() {
        let path = "/model/anthropic.claude-3-sonnet-20240229-v1%3A0/converse-stream";
        let head = head(path);
        let request =
            br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}],"inferenceConfig":{"maxTokens":64}}"#;
        let mut collector =
            FieldResponseCollector::new(&head, request, "application/json").expect("collector");
        let mut wire = Vec::new();
        wire.extend_from_slice(&aws_eventstream_message(
            br#"{"messageStart":{"role":"assistant"}}"#,
        ));
        wire.extend_from_slice(&aws_eventstream_message(
            br#"{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"hello"}}}"#,
        ));
        wire.extend_from_slice(&aws_eventstream_message(
            br#"{"messageStop":{"stopReason":"end_turn"}}"#,
        ));
        for chunk in wire.chunks(9) {
            collector.push(chunk);
        }
        let claims = collector
            .finish(&head, "POST", 200)
            .expect("eventstream claims");
        assert_eq!(
            claims
                .get("upstream_response_fields_sha256")
                .and_then(serde_json::Value::as_str)
                .map(|s| s.len()),
            Some(64)
        );
        assert_eq!(
            claims.get("streaming").and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn bedrock_eventstream_parser_failure_disables_field_claims() {
        let path = "/model/anthropic.claude-3-sonnet-20240229-v1%3A0/converse-stream";
        let head = head(path);
        let request =
            br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}],"inferenceConfig":{"maxTokens":64}}"#;
        let mut collector =
            FieldResponseCollector::new(&head, request, "application/vnd.amazon.eventstream")
                .expect("eventstream collector");
        collector.push(&aws_eventstream_message(
            br#"{"messageStart":{"role":"assistant"}}"#,
        ));
        collector.push(&aws_eventstream_message(br#"not-json"#));
        assert!(collector.finish(&head, "POST", 200).is_none());
    }

    #[test]
    fn streaming_collector_uses_request_hint_without_event_stream_content_type() {
        let head = head("/v1/chat/completions");
        let request =
            br#"{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"stream":true}"#;
        let mut collector =
            FieldResponseCollector::new(&head, request, "application/json").expect("collector");
        collector.push(
            b"data: {\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"},\"finish_reason\":null}]}\n\n",
        );
        collector.push(
            b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"total_tokens\":3}}\n\n",
        );
        collector.push(b"data: [DONE]\n\n");
        let claims = collector
            .finish(&head, "POST", 200)
            .expect("field claims must survive request-hinted SSE");
        assert_eq!(
            claims.get("streaming").and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn proof_unavailable_payload_keeps_response_observable() {
        let payload = build_proof_unavailable_payload(
            &head("/v1/chat/completions?debug=true"),
            "post",
            200,
            "application/json",
            "req",
            "resp",
            "attestation_failed",
            "nsm unavailable",
        );
        assert_eq!(
            payload.get("type").and_then(serde_json::Value::as_str),
            Some("tee.proof_unavailable")
        );
        assert_eq!(
            payload.get("attested").and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            payload
                .get("upstream_path")
                .and_then(serde_json::Value::as_str),
            Some("/v1/chat/completions")
        );
        assert_eq!(
            payload
                .get("http_method")
                .and_then(serde_json::Value::as_str),
            Some("POST")
        );
    }

    #[test]
    fn streaming_collector_builds_claims_beyond_body_capture_limit() {
        let head = head("/v1/chat/completions");
        let request =
            br#"{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"stream":true}"#;
        let mut collector =
            FieldResponseCollector::new(&head, request, "text/event-stream; charset=utf-8")
                .expect("collector");
        let padding = "x".repeat(1024);
        let mut streamed = 0usize;
        while streamed <= MAX_FIELD_CLAIMS_CAPTURE {
            let event = format!("data: {{\"padding\":\"{}\"}}\n\n", padding);
            streamed += event.len();
            collector.push(event.as_bytes());
        }
        collector.push(
            b"data: {\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"},\"finish_reason\":null}]}\n\n",
        );
        collector.push(
            b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"total_tokens\":3}}\n\n",
        );
        collector.push(b"data: [DONE]\n\n");
        let claims = collector
            .finish(&head, "POST", 200)
            .expect("field claims must survive large SSE streams");
        assert_eq!(
            claims.get("streaming").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(claims
            .get("upstream_response_fields_sha256")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|v| v.len() == 64));
    }

    #[test]
    fn gemini_generate_content_sse_rechunking_keeps_same_semantic_view() {
        let stream = b"data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"he\"}]}}]}\n\ndata: {\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"text\":\"llo\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"totalTokenCount\":3}}\n\n";
        let merged = br#"{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"hello"}]},"finishReason":"STOP"}],"usageMetadata":{"totalTokenCount":3}}"#;
        assert_same_response_view("google.gemini.generate_content", stream, merged);
    }

    #[test]
    fn dashscope_generation_sse_rechunking_keeps_same_semantic_view() {
        let stream = b"data: {\"output\":{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"he\"},\"finish_reason\":null}]}}\n\ndata: {\"output\":{\"choices\":[{\"message\":{\"content\":\"llo\"},\"finish_reason\":\"stop\"}]},\"usage\":{\"total_tokens\":3},\"request_id\":\"req_1\"}\n\n";
        let merged = br#"{"output":{"choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]},"usage":{"total_tokens":3},"request_id":"req_1"}"#;
        assert_same_response_view("alibaba.dashscope.generation", stream, merged);
    }

    #[test]
    fn bedrock_converse_stream_rechunking_keeps_same_semantic_view() {
        let stream = b"data: {\"messageStart\":{\"role\":\"assistant\"}}\n\ndata: {\"contentBlockDelta\":{\"contentBlockIndex\":0,\"delta\":{\"text\":\"he\"}}}\n\ndata: {\"contentBlockDelta\":{\"contentBlockIndex\":0,\"delta\":{\"text\":\"llo\"}}}\n\ndata: {\"messageStop\":{\"stopReason\":\"end_turn\"}}\n\ndata: {\"metadata\":{\"usage\":{\"inputTokens\":1,\"outputTokens\":2},\"metrics\":{\"latencyMs\":42}}}\n\n";
        let merged = br#"{"output":{"message":{"role":"assistant","content":[{"type":"text","text":"hello"}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":2},"metrics":{"latencyMs":42}}"#;
        assert_same_response_view("aws.bedrock.converse", stream, merged);
    }

    #[test]
    fn cohere_chat_sse_rechunking_keeps_same_semantic_view() {
        let stream = b"data: {\"type\":\"message-start\",\"delta\":{\"message\":{\"role\":\"assistant\"}}}\n\ndata: {\"type\":\"content-start\",\"delta\":{\"message\":{\"content\":{\"type\":\"text\",\"text\":\"\"}}}}\n\ndata: {\"type\":\"content-delta\",\"delta\":{\"message\":{\"content\":{\"type\":\"text\",\"text\":\"he\"}}}}\n\ndata: {\"type\":\"content-delta\",\"delta\":{\"message\":{\"content\":{\"type\":\"text\",\"text\":\"llo\"}}}}\n\ndata: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"total_tokens\":3}}}\n\n";
        let merged = br#"{"message":{"role":"assistant","content":[{"type":"text","text":"hello"}],"finish_reason":"COMPLETE"},"finish_reason":"COMPLETE","usage":{"total_tokens":3}}"#;
        assert_same_response_view("cohere.chat", stream, merged);
    }
}

#[cfg(test)]
mod golden {
    use super::{build_v2_statement, hex};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use serde::Deserialize;
    use sha2::{Digest, Sha256};

    #[derive(Deserialize)]
    struct ExpectedV2 {
        statement: String,
        statement_hex: String,
        request_body_sha256: String,
        response_body_sha256: String,
    }
    #[derive(Deserialize)]
    struct CaseV2 {
        name: String,
        nonce_b64: String,
        upstream_host: String,
        upstream_path: String,
        http_method: String,
        http_status: u16,
        resp_content_type: String,
        request_body_b64: String,
        response_body_b64: String,
        expected: ExpectedV2,
    }
    #[derive(Deserialize)]
    struct Fixture {
        cases_v2: Vec<CaseV2>,
    }

    #[test]
    fn rust_v2_statement_matches_frozen_vectors() {
        let fx: Fixture =
            serde_json::from_str(include_str!("../signing-vectors.json")).expect("parse fixture");
        assert!(!fx.cases_v2.is_empty(), "cases_v2 为空");
        for c in &fx.cases_v2 {
            let req_body = B64.decode(c.request_body_b64.as_bytes()).expect("req b64");
            let resp_body = B64
                .decode(c.response_body_b64.as_bytes())
                .expect("resp b64");
            let req_hex = hex(&Sha256::digest(&req_body));
            let resp_hex = hex(&Sha256::digest(&resp_body));
            assert_eq!(
                req_hex, c.expected.request_body_sha256,
                "req hash [{}]",
                c.name
            );
            assert_eq!(
                resp_hex, c.expected.response_body_sha256,
                "resp hash [{}]",
                c.name
            );

            let stmt = build_v2_statement(
                &c.nonce_b64,
                &c.upstream_host,
                &c.upstream_path,
                &c.http_method,
                c.http_status,
                &c.resp_content_type,
                &req_hex,
                &resp_hex,
                None,
            );
            assert_eq!(
                String::from_utf8(stmt.clone()).unwrap(),
                c.expected.statement,
                "v2 statement [{}]",
                c.name
            );
            assert_eq!(
                hex(&stmt),
                c.expected.statement_hex,
                "v2 statement hex [{}]",
                c.name
            );
        }
    }
}

// Ordered outgoing headers: emitted verbatim in the given order and case.
#[cfg(test)]
mod ordered_headers {
    use super::{build_request_head_ordered, parse_headers_ordered};

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn ordered_emit_preserves_order_case_and_fills_sentinels() {
        let ordered = vec![
            (s("Accept"), s("application/json")),
            (s("Authorization"), s("")), // empty sentinel -> filled from token
            (s("User-Agent"), s("example-client/1.0")),
            (s("Connection"), s("keep-alive")),
            (s("Host"), s("api.example.com")),
            (s("Content-Length"), s("")), // empty sentinel -> filled with body_len
        ];
        let text = build_request_head_ordered(
            "POST",
            "/v1/messages?beta=true",
            "fallback",
            &ordered,
            Some("tok123"),
            2,
        );
        let head = text.split("\r\n\r\n").next().unwrap();
        let lines: Vec<&str> = head.split("\r\n").collect();
        assert_eq!(lines[0], "POST /v1/messages?beta=true HTTP/1.1");
        assert_eq!(
            lines[1..].to_vec(),
            vec![
                "Accept: application/json",
                "Authorization: Bearer tok123",
                "User-Agent: example-client/1.0",
                "Connection: keep-alive", // not connection: close
                "Host: api.example.com",
                "Content-Length: 2",
            ]
        );
        assert!(text.ends_with("\r\n\r\n")); // head only; body written by caller
        assert_eq!(text.matches("Content-Length").count(), 1);
    }

    #[test]
    fn ordered_emit_strips_te_and_backfills_missing_host_and_clen() {
        let ordered = vec![
            (s("Accept"), s("application/json")),
            (s("transfer-encoding"), s("chunked")), // stripped
        ];
        let text = build_request_head_ordered("POST", "/x", "host.example", &ordered, None, 3);
        assert!(!text.to_lowercase().contains("transfer-encoding"));
        assert!(text.contains("host: host.example\r\n")); // backfilled
        assert!(text.contains("content-length: 3\r\n")); // backfilled
        assert!(!text.to_lowercase().contains("authorization")); // no token -> omitted
    }

    #[test]
    fn parse_headers_ordered_preserves_order() {
        let v = Some(vec![
            vec![s("B-Header"), s("1")],
            vec![s("a-header"), s("2")],
        ]);
        assert_eq!(
            parse_headers_ordered(&v).unwrap(),
            vec![(s("B-Header"), s("1")), (s("a-header"), s("2"))]
        );
    }

    #[test]
    fn parse_headers_ordered_rejects_malformed_and_missing() {
        assert!(parse_headers_ordered(&None).is_none());
        assert!(parse_headers_ordered(&Some(vec![vec![s("only-one")]])).is_none());
        assert!(parse_headers_ordered(&Some(vec![vec![s("a"), s("b"), s("c")]])).is_none());
    }
}
