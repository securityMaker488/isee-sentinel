//! Opt-in transport. No network client is created by offline collection.
use crate::{AgentError, is_link, open_readonly_no_follow, safe_path, sha256_bytes, valid_asset_id};
use hmac::{Hmac, Mac};
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::Deserialize;
use sha2::Sha256;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const OBSERVATIONS_PATH: &str = "/agent/v1/observations";
pub const MEDIA_TYPE: &str = "application/vnd.sentinel.agent+json";
const MAX_CREDENTIAL_BYTES: u64 = 4096;
const MAX_ATTEMPTS: u32 = 3;

/// Intentionally does not implement Debug or Serialize.
pub struct AgentCredentials {
    agent_id: String,
    secret: Zeroizing<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialDocument {
    agent_id: String,
    secret: String,
}

impl Drop for CredentialDocument {
    fn drop(&mut self) { self.secret.zeroize(); }
}

impl AgentCredentials {
    pub fn load(path: &Path) -> Result<Self, AgentError> {
        safe_path(path).map_err(|_| AgentError("credential path must be a local file without links or traversal"))?;
        let file = open_readonly_no_follow(path).map_err(|_| AgentError("credential file is unavailable"))?;
        let before = file.metadata().map_err(|_| AgentError("credential metadata is unavailable"))?;
        if !before.is_file() || is_link(&before) || before.len() > MAX_CREDENTIAL_BYTES {
            return Err(AgentError("credential must be a regular file of at most 4 KiB"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // The running account must own the file; group/other permissions are forbidden.
            if before.uid() != unsafe { libc::geteuid() } || before.mode() & 0o077 != 0 {
                return Err(AgentError("credential file must belong to the current account with mode 0600 or 0400"));
            }
        }
        let mut data = Zeroizing::new(Vec::with_capacity(MAX_CREDENTIAL_BYTES as usize + 1));
        (&file).take(MAX_CREDENTIAL_BYTES + 1).read_to_end(&mut data)
            .map_err(|_| AgentError("credential file could not be read"))?;
        let after = file.metadata().map_err(|_| AgentError("credential metadata is unavailable"))?;
        if data.len() as u64 > MAX_CREDENTIAL_BYTES || before.len() != after.len()
            || before.modified().ok() != after.modified().ok() || after.len() != data.len() as u64
        {
            return Err(AgentError("credential file changed or exceeds its limit"));
        }
        let document: CredentialDocument = serde_json::from_slice(&data)
            .map_err(|_| AgentError("credential JSON must contain only agentId and secret"))?;
        if !valid_asset_id(&document.agent_id) {
            return Err(AgentError("credential agentId must be a canonical lowercase UUID"));
        }
        if document.secret.len() != 64 || !document.secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AgentError("credential secret must contain exactly 64 hexadecimal characters"));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        for (index, pair) in document.secret.as_bytes().chunks_exact(2).enumerate() {
            let high = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
            let low = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
            secret[index] = high * 16 + low;
        }
        Ok(Self { agent_id: document.agent_id.clone(), secret })
    }
}

pub struct Transport {
    client: Client,
    url: Url,
    credentials: AgentCredentials,
}

/// Require an origin, not an arbitrary route. Insecure HTTP is only an explicit local test option.
pub fn validate_endpoint(endpoint: &str, allow_loopback_http: bool) -> Result<Url, AgentError> {
    let invalid = AgentError("endpoint must be an HTTPS origin without credentials, path, query or fragment");
    if endpoint.trim() != endpoint || endpoint.chars().any(|ch| ch.is_control() || ch == '\\') {
        return Err(invalid);
    }
    let mut url = Url::parse(endpoint).map_err(|_| invalid.clone())?;
    let authority = endpoint.split_once("://").map(|(_, rest)| rest.split('/').next().unwrap_or(""))
        .ok_or_else(|| invalid.clone())?;
    if authority.contains('@') || url.host_str().is_none() || !url.username().is_empty()
        || url.password().is_some() || url.query().is_some() || url.fragment().is_some()
        || url.path() != "/"
    { return Err(invalid); }
    if url.scheme() == "http" {
        // Check original spelling too: do not accept numeric aliases like 127.1 or 2130706433.
        let original_host = authority.split(':').next().unwrap_or("");
        if !allow_loopback_http || !matches!(original_host, "127.0.0.1" | "localhost") {
            return Err(AgentError("HTTP requires --allow-loopback-http and literal 127.0.0.1 or localhost"));
        }
    } else if url.scheme() != "https" {
        return Err(invalid);
    }
    url.set_path(OBSERVATIONS_PATH);
    Ok(url)
}

pub fn signing_message(timestamp: &str, nonce: &str, body: &[u8]) -> String {
    format!("{timestamp}\n{nonce}\nPOST\n{OBSERVATIONS_PATH}\n{}", sha256_bytes(body))
}

fn signature(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts a 32-byte key");
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn check_cancelled(cancelled: &AtomicBool) -> Result<(), AgentError> {
    if cancelled.load(Ordering::SeqCst) { Err(AgentError("interrupted")) } else { Ok(()) }
}

pub fn wait_interruptible(duration: Duration, cancelled: &AtomicBool) -> Result<(), AgentError> {
    let start = Instant::now();
    while start.elapsed() < duration {
        check_cancelled(cancelled)?;
        std::thread::sleep(duration.saturating_sub(start.elapsed()).min(Duration::from_millis(100)));
    }
    check_cancelled(cancelled)
}

impl Transport {
    pub fn new(endpoint: &str, allow_loopback_http: bool, credentials: AgentCredentials) -> Result<Self, AgentError> {
        let url = validate_endpoint(endpoint, allow_loopback_http)?;
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy();
        if url.scheme() == "http" && url.host_str() == Some("localhost") {
            builder = builder.resolve("localhost", SocketAddr::new(Ipv4Addr::LOCALHOST.into(), url.port_or_known_default().unwrap_or(80)));
        }
        let client = builder.build().map_err(|_| AgentError("authenticated transport could not be initialized"))?;
        Ok(Self { client, url, credentials })
    }

    /// Retry the exact serialized observation with a fresh signed nonce per attempt.
    /// No response body is printed, interpreted as a command, or persisted.
    pub fn send(&self, body: &[u8], cancelled: &AtomicBool) -> Result<(), AgentError> {
        self.send_with_backoff(body, cancelled, Duration::from_secs(1))
    }

    fn send_with_backoff(&self, body: &[u8], cancelled: &AtomicBool, delay: Duration) -> Result<(), AgentError> {
        if body.len() > 16 * 1024 { return Err(AgentError("observation exceeds the transport size limit")); }
        for attempt in 0..MAX_ATTEMPTS {
            check_cancelled(cancelled)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
                .map_err(|_| AgentError("system clock is before Unix epoch"))?.as_secs().to_string();
            let nonce = Uuid::new_v4().to_string();
            let signature = signature(self.credentials.secret.as_ref(), signing_message(&timestamp, &nonce, body).as_bytes());
            let response = self.client.post(self.url.clone())
                .header(reqwest::header::CONTENT_TYPE, MEDIA_TYPE)
                .header("X-Sentinel-Agent", &self.credentials.agent_id)
                .header("X-Sentinel-Timestamp", timestamp)
                .header("X-Sentinel-Nonce", nonce)
                .header("X-Sentinel-Signature", signature)
                .body(body.to_vec()).send();
            check_cancelled(cancelled)?;
            match response {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => {
                    let status = response.status();
                    if !(status.is_server_error() || status.as_u16() == 408 || status.as_u16() == 429) {
                        return Err(AgentError("collector rejected the observation; check identity, scope, clock and endpoint"));
                    }
                }
                Err(_) => {} // Never emit request diagnostics, response content, or credentials.
            }
            if attempt + 1 < MAX_ATTEMPTS { wait_interruptible(delay * (1 << attempt), cancelled)?; }
        }
        Err(AgentError("observation delivery failed after 3 attempts"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    const AGENT: &str = "00000000-0000-4000-8000-000000000002";

    fn credentials() -> AgentCredentials { AgentCredentials { agent_id: AGENT.into(), secret: Zeroizing::new([0x0b; 32]) } }

    #[test]
    fn rejects_insecure_or_ambiguous_endpoints() {
        assert!(validate_endpoint("https://collector.example", false).is_ok());
        assert!(validate_endpoint("http://127.0.0.1:3001", true).is_ok());
        assert!(validate_endpoint("http://localhost:3001/", true).is_ok());
        for url in ["http://127.0.0.1", "http://localhost", "http://collector.example"] {
            assert!(validate_endpoint(url, false).is_err());
        }
        for url in ["http://127.1", "http://2130706433", "http://[::1]", "http://localhost.example", "http://10.0.0.1", "https://user:password@collector.example", "https://@collector.example", "https://collector.example/other", "https://collector.example/?query", "https://collector.example/#fragment", "ftp://collector.example", " https://collector.example", "https://collector.example\n"] {
            assert!(validate_endpoint(url, true).is_err(), "unexpected accepted URL: {url}");
        }
    }

    #[test]
    fn hmac_matches_rfc4231_and_exact_protocol_message() {
        assert_eq!(signature(&[0x0b; 20], b"Hi There"), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(signing_message("123", "nonce", b"abc"), "123\nnonce\nPOST\n/agent/v1/observations\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn credentials_are_strict_and_bounded() {
        let folder = std::env::temp_dir().join(format!("sentinel-credential-test-{}", Uuid::new_v4()));
        fs::create_dir(&folder).unwrap();
        let path = folder.join("credential.json");
        fs::write(&path, format!(r#"{{"agentId":"{AGENT}","secret":"{}"}}"#, "0b".repeat(32))).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(AgentCredentials::load(&path).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let loaded = AgentCredentials::load(&path).unwrap();
        assert_eq!(loaded.secret.as_ref(), &[0x0b; 32]);
        for data in ["{}".into(), format!(r#"{{"agentId":"{AGENT}","secret":"invalid"}}"#), format!(r#"{{"agentId":"{AGENT}","secret":"{}","extra":true}}"#, "00".repeat(32)), "x".repeat(4097), format!(r#"{{"agentId":"{AGENT}","agentId":"{AGENT}","secret":"{}"}}"#, "00".repeat(32))] {
            fs::write(&path, data).unwrap();
            assert!(AgentCredentials::load(&path).is_err());
        }
        fs::remove_dir_all(folder).unwrap();
    }

    fn local_requests(statuses: &[u16]) -> Vec<(String, std::collections::HashMap<String, String>, Vec<u8>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let statuses = statuses.to_vec();
        let all_success = statuses.last().unwrap() / 100 == 2;
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for status in statuses {
                let start = Instant::now();
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(start.elapsed() < Duration::from_secs(5), "expected local request did not arrive");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("local listener failed: {error}"),
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut reader = BufReader::new(stream);
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut headers = std::collections::HashMap::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" { break; }
                    let (key, value) = line.split_once(':').unwrap();
                    headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
                }
                let length: usize = headers["content-length"].parse().unwrap();
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let response = format!("HTTP/1.1 {status} Result\r\nContent-Length: 0\r\nConnection: close\r\nLocation: http://127.0.0.1:1/do-not-follow\r\n\r\n");
                reader.get_mut().write_all(response.as_bytes()).unwrap();
                requests.push((request_line, headers, body));
            }
            requests
        });
        let transport = Transport::new(&endpoint, true, credentials()).unwrap();
        let result = transport.send_with_backoff(br#"{"observationId":"test"}"#, &AtomicBool::new(false), Duration::ZERO);
        assert_eq!(result.is_ok(), all_success);
        server.join().unwrap()
    }

    #[test]
    fn signs_raw_request_retries_transient_failure_and_never_reuses_nonce() {
        let requests = local_requests(&[503, 429, 202]);
        let mut nonces = std::collections::HashSet::new();
        for (line, headers, body) in requests {
            assert_eq!(line, "POST /agent/v1/observations HTTP/1.1\r\n");
            assert_eq!(headers["content-type"], MEDIA_TYPE);
            assert_eq!(headers["x-sentinel-agent"], AGENT);
            let nonce = &headers["x-sentinel-nonce"];
            assert_eq!(Uuid::parse_str(nonce).unwrap().get_version_num(), 4);
            assert!(nonces.insert(nonce.clone()));
            let timestamp = &headers["x-sentinel-timestamp"];
            assert!(timestamp.parse::<u64>().is_ok());
            assert_eq!(headers["x-sentinel-signature"], signature(&[0x0b; 32], signing_message(timestamp, nonce, &body).as_bytes()));
            assert_eq!(body, br#"{"observationId":"test"}"#);
        }
    }

    #[test]
    fn bounded_retries_and_no_redirect_or_auth_retry() {
        assert_eq!(local_requests(&[503, 503, 503]).len(), 3);
        assert_eq!(local_requests(&[401]).len(), 1);
        assert_eq!(local_requests(&[302]).len(), 1);
    }

    #[test]
    fn cancellation_prevents_network_and_interrupts_wait() {
        let transport = Transport::new("http://127.0.0.1:1", true, credentials()).unwrap();
        let cancelled = AtomicBool::new(true);
        assert_eq!(transport.send(b"{}", &cancelled).unwrap_err().0, "interrupted");
        assert_eq!(wait_interruptible(Duration::from_secs(30), &cancelled).unwrap_err().0, "interrupted");
    }
}
