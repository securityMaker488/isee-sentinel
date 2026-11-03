#![deny(unsafe_code)]

// OS lifetime controls require narrowly scoped FFI; all other code remains safe.
#[allow(unsafe_code)]
mod lifetime;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_INPUT: u64 = 16 * 1024 * 1024;
pub const MAX_OUTPUT: usize = 2 * 1024 * 1024;
pub const MAX_REQUEST: u64 = 8192;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn valid() -> serde_json::Value {
        json!({"schemaVersion":1,"operation":"archive.inspect","jobId":"00000000-0000-0000-0000-000000000001",
            "file":std::env::temp_dir().join("synthetic.zip"),"format":"zip","inputSha256":"a".repeat(64),
            "maxInputBytes":MAX_INPUT,"maxOutputBytes":MAX_OUTPUT,"timeoutMs":45000})
    }
    #[test]
    fn accepts_only_supported_versioned_archive_contract() {
        for format in ["zip", "tar", "tar.gz"] {
            let mut request = valid();
            request["format"] = json!(format);
            assert!(parse_request(&serde_json::to_vec(&request).unwrap()).is_ok());
        }
    }
    #[test]
    fn rejects_commands_unknown_fields_and_budgets() {
        for (field, value) in [
            ("argv", json!(["anything"])),
            ("schemaVersion", json!(2)),
            ("operation", json!("shell")),
            ("file", json!("relative.zip")),
            ("jobId", json!("not-an-id")),
            ("format", json!("zip --other")),
            ("inputSha256", json!("A".repeat(64))),
            ("maxInputBytes", json!(MAX_INPUT + 1)),
            ("maxInputBytes", json!(0)),
            ("maxOutputBytes", json!(MAX_OUTPUT + 1)),
            ("timeoutMs", json!(45001)),
        ] {
            let mut request = valid();
            request[field] = value;
            assert!(
                parse_request(&serde_json::to_vec(&request).unwrap()).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn bounds_malformed_request_before_deserialization() {
        assert!(parse_request(&vec![b' '; MAX_REQUEST as usize + 1]).is_err());
        assert!(parse_request(b"{broken").is_err());
        assert!(parse_request(b"null").is_err());
    }
    #[test]
    fn streaming_hash_refuses_directory_and_overflow() {
        let path = std::env::temp_dir().join(format!(
            "sentinel-execution-hash-{}.fixture",
            std::process::id()
        ));
        fs::write(&path, b"synthetic").unwrap();
        assert!(bounded_hash(&path, 8).is_err());
        assert_eq!(
            bounded_hash(&path, 9).unwrap(),
            format!("{:x}", Sha256::digest(b"synthetic"))
        );
        assert!(bounded_hash(&std::env::temp_dir(), MAX_INPUT).is_err());
        fs::remove_file(path).unwrap();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub schema_version: u8,
    pub operation: String,
    pub job_id: String,
    pub file: PathBuf,
    pub format: String,
    pub input_sha256: String,
    pub max_input_bytes: u64,
    pub max_output_bytes: usize,
    pub timeout_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub schema_version: u8,
    pub engine: &'static str,
    pub engine_version: &'static str,
    pub containment: &'static str,
    pub job_id: String,
    pub status: &'static str,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub input_sha256: String,
    pub worker_sha256: String,
    pub stdout_sha256: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub output_truncated: bool,
}

#[derive(Serialize)]
pub struct Outcome {
    pub receipt: Receipt,
    pub stdout: Option<String>,
}

fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn parse_request(bytes: &[u8]) -> Result<Request, &'static str> {
    if bytes.len() as u64 > MAX_REQUEST {
        return Err("request_limit");
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| "invalid_request")?;
    validate_request(&request)?;
    Ok(request)
}

fn validate_request(request: &Request) -> Result<(), &'static str> {
    let uuid = request.job_id.len() == 36
        && request.job_id.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        });
    if request.schema_version != 1
        || request.operation != "archive.inspect"
        || !uuid
        || !request.file.is_absolute()
        || !hex(&request.input_sha256)
        || !["zip", "tar", "tar.gz"].contains(&request.format.as_str())
        || request.max_input_bytes == 0
        || request.max_input_bytes > MAX_INPUT
        || request.max_output_bytes == 0
        || request.max_output_bytes > MAX_OUTPUT
        || request.timeout_ms == 0
        || request.timeout_ms > 45000
    {
        return Err("invalid_request");
    }
    Ok(())
}

pub fn bounded_hash(path: &Path, limit: u64) -> Result<String, &'static str> {
    let meta = fs::symlink_metadata(path).map_err(|_| "input_unavailable")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit {
        return Err("input_rejected");
    }
    let mut file = File::open(path)
        .map_err(|_| "input_unavailable")?
        .take(limit + 1);
    let mut buffer = [0u8; 16384];
    let mut size = 0u64;
    let mut hash = Sha256::new();
    loop {
        let n = file.read(&mut buffer).map_err(|_| "input_unavailable")?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > limit {
            return Err("input_rejected");
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn capture<R: Read + Send + 'static>(
    reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut result = Vec::new();
        reader.take(limit as u64 + 1).read_to_end(&mut result)?;
        if result.len() > limit {
            overflow.store(true, Ordering::SeqCst);
        }
        Ok(result)
    })
}

/// Runs only a deployment-owned Python worker. This is not a sandbox for arbitrary
/// programs: the supported worker must not launch descendants or access the network.
/// Authorization remains with the API; closing its control pipe cancels this child.
/// Intended for the one-shot CLI: Windows lifetime protection assigns the calling
/// process to a job. Do not embed this function in the API or endpoint agent.
pub fn supervise(
    request: Request,
    python: &Path,
    worker: &Path,
    cancelled: Arc<AtomicBool>,
) -> Result<Outcome, &'static str> {
    validate_request(&request)?;
    let start = Instant::now();
    let input_hash = bounded_hash(&request.file, request.max_input_bytes)?;
    if input_hash != request.input_sha256 {
        return Err("input_integrity");
    }
    let worker_hash = bounded_hash(worker, 1024 * 1024)?;
    if !python.is_absolute() || !worker.is_absolute() || !python.is_file() {
        return Err("invalid_configuration");
    }
    if cancelled.load(Ordering::SeqCst) {
        return Err("cancelled");
    }
    let mut command = Command::new(python);
    command
        .args(["-I", "-B"])
        .arg(worker)
        .args(["--consent", "--file"])
        .arg(&request.file)
        .args(["--format", &request.format])
        .env_clear()
        .current_dir(worker.parent().ok_or("invalid_configuration")?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in ["SystemRoot", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW, no visible helper console.
    }
    let containment = lifetime::configure(&mut command, python)?;
    let mut child = command.spawn().map_err(|_| "spawn_failed")?;
    let overflow = Arc::new(AtomicBool::new(false));
    // These pipes are requested above and cannot be absent after a successful spawn.
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("pipe_failed");
    };
    let out = capture(stdout, request.max_output_bytes, overflow.clone());
    let err = capture(stderr, 65536, overflow.clone());
    let mut reason = "completed";
    let exit = loop {
        if cancelled.load(Ordering::SeqCst) {
            reason = "cancelled";
        } else if start.elapsed() >= Duration::from_millis(request.timeout_ms) {
            reason = "timed_out";
        } else if overflow.load(Ordering::SeqCst) {
            reason = "output_limit";
        }
        if reason != "completed" {
            // Never report cancellation until the child has actually been reaped.
            let _ = child.kill();
            break child.wait().map_err(|_| "wait_failed")?;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("wait_failed");
            }
        }
    };
    let stdout = out
        .join()
        .map_err(|_| "capture_failed")?
        .map_err(|_| "capture_failed")?;
    let stderr = err
        .join()
        .map_err(|_| "capture_failed")?
        .map_err(|_| "capture_failed")?;
    if reason == "completed" {
        if cancelled.load(Ordering::SeqCst) {
            reason = "cancelled";
        } else if overflow.load(Ordering::SeqCst) {
            reason = "output_limit";
        } else if !exit.success() {
            reason = "failed";
        } else if bounded_hash(&request.file, request.max_input_bytes)
            .ok()
            .as_deref()
            != Some(&input_hash)
            || bounded_hash(worker, 1024 * 1024).ok().as_deref() != Some(&worker_hash)
        {
            reason = "integrity_failed";
        }
    }
    let stdout_sha256 = format!("{:x}", Sha256::digest(&stdout));
    let stdout_bytes = stdout.len();
    let text = if reason == "completed" {
        match String::from_utf8(stdout) {
            Ok(text) => Some(text),
            Err(_) => {
                reason = "invalid_output";
                None
            }
        }
    } else {
        None
    };
    Ok(Outcome {
        receipt: Receipt {
            schema_version: 1,
            engine: "Sentinel Execution",
            engine_version: env!("CARGO_PKG_VERSION"),
            containment,
            job_id: request.job_id,
            status: reason,
            exit_code: exit.code(),
            duration_ms: start.elapsed().as_millis() as u64,
            input_sha256: input_hash,
            worker_sha256: worker_hash,
            stdout_sha256,
            stdout_bytes,
            stderr_bytes: stderr.len(),
            output_truncated: overflow.load(Ordering::SeqCst),
        },
        stdout: text,
    })
}
