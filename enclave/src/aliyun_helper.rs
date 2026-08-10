use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const PROTOCOL_VERSION: u8 = 1;
const MAX_REQUEST_PAYLOAD: usize = 64 * 1024;
const MAX_RESPONSE_PAYLOAD: usize = 4 * 1024 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
pub struct ProofRequest<'a> {
    pub v: u8,
    pub nonce_b64: &'a str,
    pub upstream_host: &'a str,
    pub upstream_path: &'a str,
    pub http_method: &'a str,
    pub http_status: u16,
    pub resp_content_type: &'a str,
    pub request_body_sha256: &'a str,
    pub response_body_sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_claims: Option<&'a Value>,
}

impl<'a> ProofRequest<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nonce_b64: &'a str,
        upstream_host: &'a str,
        upstream_path: &'a str,
        http_method: &'a str,
        http_status: u16,
        resp_content_type: &'a str,
        request_body_sha256: &'a str,
        response_body_sha256: &'a str,
        field_claims: Option<&'a Value>,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            nonce_b64,
            upstream_host,
            upstream_path,
            http_method,
            http_status,
            resp_content_type,
            request_body_sha256,
            response_body_sha256,
            field_claims,
        }
    }
}

#[derive(Deserialize)]
struct HelperResponse {
    v: u8,
    ok: bool,
    proof: Option<Box<RawValue>>,
    error: Option<HelperError>,
}

#[derive(Deserialize)]
struct HelperError {
    code: String,
    message: String,
}

pub fn request_proof(socket_path: &str, request: &ProofRequest<'_>) -> Result<Vec<u8>, String> {
    let payload =
        serde_json::to_vec(request).map_err(|e| format!("aliyun helper request JSON: {e}"))?;
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connect aliyun proof helper: {e}"))?;
    stream.set_read_timeout(Some(HELPER_TIMEOUT)).ok();
    stream.set_write_timeout(Some(HELPER_TIMEOUT)).ok();
    write_frame(&mut stream, &payload, MAX_REQUEST_PAYLOAD)
        .map_err(|e| format!("write aliyun proof helper request: {e}"))?;
    let raw = read_frame(&mut stream, MAX_RESPONSE_PAYLOAD)
        .map_err(|e| format!("read aliyun proof helper response: {e}"))?;
    let response: HelperResponse =
        serde_json::from_slice(&raw).map_err(|e| format!("aliyun helper response JSON: {e}"))?;
    if response.v != PROTOCOL_VERSION {
        return Err(format!("aliyun helper response version {}", response.v));
    }
    if !response.ok {
        if let Some(err) = response.error {
            return Err(format!("aliyun helper {}: {}", err.code, err.message));
        }
        return Err("aliyun helper failed without error detail".into());
    }
    let proof = response
        .proof
        .ok_or_else(|| "aliyun helper success response missing proof".to_string())?;
    Ok(proof.get().as_bytes().to_vec())
}

fn read_frame<R: Read>(r: &mut R, max: usize) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n > max {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "helper response exceeds limit",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_frame<W: Write>(w: &mut W, payload: &[u8], max: usize) -> std::io::Result<()> {
    if payload.len() > max {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "helper request exceeds limit",
        ));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)
}

#[cfg(test)]
mod tests {
    use super::{request_proof, ProofRequest};
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    #[test]
    fn request_proof_returns_proof_payload() {
        let socket_path = std::env::temp_dir().join(format!(
            "apo-{}-{}.sock",
            std::process::id(),
            unique_suffix()
        ));
        let _ = fs::remove_file(&socket_path);
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("bind helper test socket: {e}"),
        };
        let proof = br#"{"profile":"aliyun-vtpm", "ok": true}"#;
        let expected = proof.to_vec();
        let handle = thread::spawn({
            move || {
                let (mut conn, _) = listener.accept().unwrap();
                let mut hdr = [0u8; 4];
                conn.read_exact(&mut hdr).unwrap();
                let n = u32::from_be_bytes(hdr) as usize;
                let mut req = vec![0u8; n];
                conn.read_exact(&mut req).unwrap();
                assert!(String::from_utf8_lossy(&req).contains("\"v\":1"));
                let resp = format!(
                    "{{\"v\":1,\"ok\":true,\"proof\":{}}}",
                    String::from_utf8_lossy(proof)
                );
                conn.write_all(&(resp.len() as u32).to_be_bytes()).unwrap();
                conn.write_all(resp.as_bytes()).unwrap();
            }
        });

        let req_hash = "00".repeat(32);
        let resp_hash = "11".repeat(32);
        let got = request_proof(
            socket_path.to_str().unwrap(),
            &ProofRequest::new(
                "bm9uY2U=",
                "api.example.com",
                "/v1/messages",
                "POST",
                200,
                "text/event-stream",
                &req_hash,
                &resp_hash,
                None,
            ),
        )
        .unwrap();
        handle.join().unwrap();
        let _ = fs::remove_file(&socket_path);
        assert_eq!(got, expected);
    }

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
