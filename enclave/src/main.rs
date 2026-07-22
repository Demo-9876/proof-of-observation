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
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use vsock::{VsockAddr, VsockListener, VsockStream};

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
enum ForwardProxyProtocol {
    HttpConnect,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardProxyConfig {
    protocol: ForwardProxyProtocol,
    port: Option<u32>,
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

fn parse_forward_proxy_protocol(raw: &str) -> Result<ForwardProxyProtocol, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "http" | "http-connect" | "http_connect" | "connect" => {
            Ok(ForwardProxyProtocol::HttpConnect)
        }
        "socks5" | "socks5h" => Ok(ForwardProxyProtocol::Socks5),
        "https" | "https-connect" | "https_connect" => Err(
            "HTTPS proxy transport is not supported yet; use an HTTP CONNECT proxy endpoint".into(),
        ),
        other => Err(format!(
            "unsupported forward proxy protocol `{other}`; supported: http-connect, socks5"
        )),
    }
}

fn parse_forward_proxy_url(raw: Option<&str>) -> Result<Option<ForwardProxyConfig>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("off") || raw.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let Some((scheme, rest)) = raw.split_once("://") else {
        return Ok(Some(ForwardProxyConfig {
            protocol: parse_forward_proxy_protocol(raw)?,
            port: None,
        }));
    };
    let protocol = parse_forward_proxy_protocol(scheme)?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let port = parse_proxy_authority_port(authority)?;
    Ok(Some(ForwardProxyConfig { protocol, port }))
}

fn parse_proxy_authority_port(authority: &str) -> Result<Option<u32>, String> {
    if authority.is_empty() {
        return Ok(None);
    }
    if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return Err(format!("invalid proxy authority `{authority}`"));
        };
        let tail = &authority[end + 1..];
        return parse_proxy_port_tail(authority, tail);
    }
    match authority.rsplit_once(':') {
        Some((_, port)) => parse_proxy_port(authority, port).map(Some),
        None => Ok(None),
    }
}

fn parse_proxy_port_tail(authority: &str, tail: &str) -> Result<Option<u32>, String> {
    if tail.is_empty() {
        return Ok(None);
    }
    let Some(port) = tail.strip_prefix(':') else {
        return Err(format!("invalid proxy authority `{authority}`"));
    };
    parse_proxy_port(authority, port).map(Some)
}

fn parse_proxy_port(authority: &str, port: &str) -> Result<u32, String> {
    let parsed = port
        .parse::<u32>()
        .map_err(|e| format!("invalid proxy port in `{authority}`: {e}"))?;
    if parsed == 0 || parsed > u16::MAX as u32 {
        return Err(format!("proxy port out of range in `{authority}`"));
    }
    Ok(parsed)
}

fn forward_proxy_config() -> Result<Option<ForwardProxyConfig>, String> {
    let url = env::var("POO_UPSTREAM_PROXY_URL")
        .ok()
        .or_else(|| env::var("POO_FORWARD_PROXY_URL").ok());
    if url
        .as_deref()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        return parse_forward_proxy_url(url.as_deref());
    }
    let protocol = env::var("POO_FORWARD_PROXY_PROTOCOL").ok();
    parse_forward_proxy_url(protocol.as_deref())
}

fn connect_upstream_socket(
    egress_port: u32,
    upstream_host: &str,
    upstream_port: u16,
) -> Result<EgressStream, String> {
    let proxy = forward_proxy_config()?;
    let next_hop_port = proxy.as_ref().and_then(|p| p.port).unwrap_or(egress_port);
    let mut sock = connect_egress(next_hop_port)?;
    set_egress_timeouts(&sock, UPSTREAM_IO_TIMEOUT);
    if let Some(proxy) = proxy {
        match proxy.protocol {
            ForwardProxyProtocol::HttpConnect => {
                http_connect_proxy(&mut sock, upstream_host, upstream_port)?
            }
            ForwardProxyProtocol::Socks5 => {
                socks5_connect_proxy(&mut sock, upstream_host, upstream_port)?
            }
        }
    }
    Ok(sock)
}

fn http_connect_proxy<S: Read + Write>(
    sock: &mut S,
    upstream_host: &str,
    upstream_port: u16,
) -> Result<(), String> {
    let target = format!("{upstream_host}:{upstream_port}");
    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nhost: {target}\r\nproxy-connection: keep-alive\r\n\r\n"
    );
    sock.write_all(req.as_bytes())
        .map_err(|e| format!("HTTP CONNECT write failed: {e}"))?;
    sock.flush()
        .map_err(|e| format!("HTTP CONNECT flush failed: {e}"))?;

    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while buf.len() < 16 * 1024 {
        sock.read_exact(&mut byte)
            .map_err(|e| format!("HTTP CONNECT response read failed: {e}"))?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !buf.ends_with(b"\r\n\r\n") {
        return Err("HTTP CONNECT response header too large or incomplete".into());
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head
        .lines()
        .next()
        .ok_or_else(|| "HTTP CONNECT response missing status line".to_string())?;
    let code = status
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("HTTP CONNECT malformed status line: {status}"))?
        .parse::<u16>()
        .map_err(|e| format!("HTTP CONNECT invalid status code `{status}`: {e}"))?;
    if !(200..300).contains(&code) {
        return Err(format!("HTTP CONNECT proxy rejected {target}: {status}"));
    }
    Ok(())
}

fn socks5_connect_proxy<S: Read + Write>(
    sock: &mut S,
    upstream_host: &str,
    upstream_port: u16,
) -> Result<(), String> {
    let host = upstream_host.as_bytes();
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err("SOCKS5 target host length out of range".into());
    }
    sock.write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("SOCKS5 greeting write failed: {e}"))?;
    sock.flush()
        .map_err(|e| format!("SOCKS5 greeting flush failed: {e}"))?;
    let mut greeting = [0u8; 2];
    sock.read_exact(&mut greeting)
        .map_err(|e| format!("SOCKS5 greeting read failed: {e}"))?;
    if greeting != [0x05, 0x00] {
        return Err(format!(
            "SOCKS5 proxy rejected no-auth greeting: {:02x?}",
            greeting
        ));
    }

    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host);
    req.extend_from_slice(&upstream_port.to_be_bytes());
    sock.write_all(&req)
        .map_err(|e| format!("SOCKS5 connect write failed: {e}"))?;
    sock.flush()
        .map_err(|e| format!("SOCKS5 connect flush failed: {e}"))?;

    let mut head = [0u8; 4];
    sock.read_exact(&mut head)
        .map_err(|e| format!("SOCKS5 connect response read failed: {e}"))?;
    if head[0] != 0x05 {
        return Err(format!("SOCKS5 invalid response version: {}", head[0]));
    }
    if head[1] != 0x00 {
        return Err(format!("SOCKS5 connect failed with reply code {}", head[1]));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len)
                .map_err(|e| format!("SOCKS5 domain response read failed: {e}"))?;
            len[0] as usize
        }
        0x04 => 16,
        other => return Err(format!("SOCKS5 unsupported bound address type {other}")),
    };
    let mut discard = vec![0u8; addr_len + 2];
    sock.read_exact(&mut discard)
        .map_err(|e| format!("SOCKS5 bound address read failed: {e}"))?;
    Ok(())
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

const MAX_HEAD: usize = 64 * 1024;
const MAX_RESP: usize = 64 * 1024 * 1024;
const MAX_REQ_HEAD: usize = 1024 * 1024;
const MAX_REQ_FRAME: usize = 64 * 1024 * 1024;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(300);
const UPSTREAM_IO_TIMEOUT: Duration = Duration::from_secs(300);
const ADMIN_TIMEOUT: Duration = Duration::from_secs(2);

const N_WORKERS: usize = 64;
const QUEUE_CAP: usize = 256;
const METRICS_PORT: u32 = 5006;

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
    out.into_bytes()
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
    sk: &SigningKey,
    spki: &[u8],
    evidence_provider: &dyn EvidenceProvider,
    m: &Metrics,
    head: &ReqHead,
    nonce_bytes: &[u8],
    norm_method: &str,
    status: u16,
    content_type: &str,
    req_body_hex: &str,
    resp_body_hex: &str,
) -> Result<(), String> {
    if !no_crlf(content_type) {
        return Err("上游 content-type 含非法 CR/LF".into());
    }
    let norm_host = head.upstream.host.to_lowercase();
    let norm_path = path_no_query(&head.upstream.path).to_string();
    let statement = build_v2_statement(
        &head.nonce,
        &norm_host,
        &norm_path,
        norm_method,
        status,
        content_type,
        req_body_hex,
        resp_body_hex,
    );
    let sig = sk.sign(&statement).to_bytes();
    let t_nsm = Instant::now();
    let evidence = evidence_provider.attest(spki, nonce_bytes)?;
    m.nsm_ns_total
        .fetch_add(t_nsm.elapsed().as_nanos() as u64, Ordering::Relaxed);
    m.nsm_calls.fetch_add(1, Ordering::Relaxed);
    let mut trailer = json!({
        "v": 2,
        "alg": "ed25519",
        "public_key": B64.encode(spki),
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
    write_frame(s, RESP_TRAILER, trailer.to_string().as_bytes())
        .map_err(|e| format!("写 RESP_TRAILER: {e}"))
}

fn handle(
    s: &mut VsockStream,
    sk: &SigningKey,
    spki: &[u8],
    evidence_provider: &dyn EvidenceProvider,
    m: &Metrics,
) -> Result<(), String> {
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
    let sock = connect_upstream_socket(head.egress_port, &head.upstream.host, 443)?;
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
        let (response, resp_body_hex, content_type) = {
            let mut sink = AttestedH2Sink {
                control: s,
                hasher: Sha256::new(),
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
            let resp_body_hex = hex(&sink.hasher.finalize());
            (response, resp_body_hex, sink.content_type)
        };
        m.resp_bytes_total
            .fetch_add(response.body_bytes as u64, Ordering::Relaxed);
        write_attested_trailer(
            s,
            sk,
            spki,
            evidence_provider,
            m,
            &head,
            &nonce_bytes,
            &norm_method,
            response.status,
            &content_type,
            &req_body_hex,
            &resp_body_hex,
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
    {
        let mut sink = |bytes: &[u8]| -> Result<(), String> {
            hasher.update(bytes);
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
    let content_type = h.content_type.as_deref().unwrap_or("");
    write_attested_trailer(
        s,
        sk,
        spki,
        evidence_provider,
        m,
        &head,
        &nonce_bytes,
        &norm_method,
        h.status,
        content_type,
        &req_body_hex,
        &resp_body_hex,
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
    sk: Arc<SigningKey>,
    spki: Arc<Vec<u8>>,
    evidence_provider: Arc<dyn EvidenceProvider>,
    m: Metrics,
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
        let res = catch_unwind(AssertUnwindSafe(|| {
            handle(
                &mut s,
                &ctx.sk,
                &ctx.spki,
                ctx.evidence_provider.as_ref(),
                &ctx.m,
            )
        }));

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

fn build_evidence_provider() -> Arc<dyn EvidenceProvider> {
    let profile = env::var("TEE_PROFILE")
        .or_else(|_| env::var("POO_EVIDENCE_PROFILE"))
        .unwrap_or_else(|_| "nitro".to_string())
        .to_ascii_lowercase();
    match profile.as_str() {
        "nitro" => {
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
            panic!("unsupported TEE_PROFILE={other}; supported profiles: nitro, qingtian");
        }
    }
}

fn main() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let sk = Arc::new(SigningKey::from_bytes(&seed));
    let vk = sk.verifying_key().to_bytes();
    let mut spki_v = vec![
        0x30u8, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki_v.extend_from_slice(&vk);
    let spki = Arc::new(spki_v);

    let evidence_provider = build_evidence_provider();
    elog!("evidence profile: {}", evidence_provider.profile());
    let ctx = Arc::new(Ctx {
        sk,
        spki,
        evidence_provider,
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
    use std::io::{Cursor, Result as IoResult};

    struct ScriptedIo {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl ScriptedIo {
        fn new(read: Vec<u8>) -> Self {
            Self {
                read: Cursor::new(read),
                written: Vec::new(),
            }
        }
    }

    impl Read for ScriptedIo {
        fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
            self.read.read(buf)
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

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

    #[test]
    fn forward_proxy_url_parses_http_connect_and_socks5() {
        assert_eq!(
            parse_forward_proxy_url(Some("http://127.0.0.1:18080")).unwrap(),
            Some(ForwardProxyConfig {
                protocol: ForwardProxyProtocol::HttpConnect,
                port: Some(18080),
            })
        );
        assert_eq!(
            parse_forward_proxy_url(Some("socks5://localhost:18081")).unwrap(),
            Some(ForwardProxyConfig {
                protocol: ForwardProxyProtocol::Socks5,
                port: Some(18081),
            })
        );
        assert_eq!(
            parse_forward_proxy_url(Some("http-connect")).unwrap(),
            Some(ForwardProxyConfig {
                protocol: ForwardProxyProtocol::HttpConnect,
                port: None,
            })
        );
        assert!(parse_forward_proxy_url(Some("https://proxy.example:443")).is_err());
    }

    #[test]
    fn http_connect_proxy_writes_connect_request_and_accepts_2xx() {
        let mut io = ScriptedIo::new(b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec());

        http_connect_proxy(&mut io, "dashscope.aliyuncs.com", 443).unwrap();

        assert_eq!(
            String::from_utf8(io.written).unwrap(),
            "CONNECT dashscope.aliyuncs.com:443 HTTP/1.1\r\nhost: dashscope.aliyuncs.com:443\r\nproxy-connection: keep-alive\r\n\r\n"
        );
    }

    #[test]
    fn http_connect_proxy_rejects_non_2xx_status() {
        let mut io =
            ScriptedIo::new(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec());

        let err = http_connect_proxy(&mut io, "dashscope.aliyuncs.com", 443).unwrap_err();

        assert!(err.contains("407"));
    }

    #[test]
    fn socks5_connect_proxy_uses_no_auth_domain_connect() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x05, 0x00]);
        response.extend_from_slice(&[0x05, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
        let mut io = ScriptedIo::new(response);

        socks5_connect_proxy(&mut io, "dashscope.aliyuncs.com", 443).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x05, 0x01, 0x00]);
        expected.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, 21]);
        expected.extend_from_slice(b"dashscope.aliyuncs.com");
        expected.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(io.written, expected);
    }

    #[test]
    fn socks5_connect_proxy_rejects_failed_reply() {
        let mut response = Vec::new();
        response.extend_from_slice(&[0x05, 0x00]);
        response.extend_from_slice(&[0x05, 0x05, 0x00, 0x01]);
        let mut io = ScriptedIo::new(response);

        let err = socks5_connect_proxy(&mut io, "dashscope.aliyuncs.com", 443).unwrap_err();

        assert!(err.contains("reply code 5"));
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
