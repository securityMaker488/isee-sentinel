use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod transport;

pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentError(pub &'static str);

impl std::fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for AgentError {}

#[derive(Debug, Clone)]
pub struct ObserveOptions {
    pub consent: bool,
    pub asset_id: String,
    pub file: PathBuf,
}

/// This schema is intentionally distinct from the application's SecurityEvent schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentObservation {
    pub schema_version: u8,
    pub observation_id: String,
    pub asset_id: String,
    pub observed_at_epoch_ms: u64,
    pub source: String,
    #[serde(rename = "type")]
    pub observation_type: String,
    pub synthetic: bool,
    pub host: HostMetadata,
    pub file: FileObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostMetadata {
    pub os: String,
    pub architecture: String,
    pub agent_process_id: u32,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileObservation {
    /// Basename only: no absolute path, user name, content, or hostname is collected.
    pub path_label: String,
    /// Hash of the canonical local absolute path, separating files with the same basename.
    pub path_id: String,
    pub bytes: u64,
    pub sha256: String,
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn valid_asset_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn safe_path(path: &Path) -> Result<String, AgentError> {
    if path.as_os_str().is_empty()
        || path.components().any(|part| matches!(part, Component::ParentDir))
    {
        return Err(AgentError("file path must be explicit and cannot contain parent traversal"));
    }
    let label = path.file_name().and_then(|value| value.to_str())
        .ok_or(AgentError("file must have a UTF-8 basename"))?;
    if label.is_empty() || label.len() > 240 || label.chars().any(|ch| ch.is_control() || matches!(ch, '/' | '\\' | ':')) {
        return Err(AgentError("invalid file basename"));
    }
    #[cfg(windows)]
    {
        // Reject UNC/device namespaces and NTFS alternate data streams; local drive paths are allowed.
        let text = path.to_string_lossy();
        if text.starts_with("\\\\") || text.starts_with("//")
            || text.char_indices().any(|(index, ch)| ch == ':' && index != 1)
        {
            return Err(AgentError("network, device and alternate-stream paths are not accepted"));
        }
    }
    // Check ancestors before opening. Final-component no-follow is also enforced on the opened handle.
    // An already compromised host can still race parent directories; this is not a hostile-host sandbox.
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) { continue; }
        let metadata = fs::symlink_metadata(&prefix).map_err(|_| AgentError("file path is unavailable"))?;
        if is_link(&metadata) { return Err(AgentError("symbolic links and reparse points are not accepted")); }
    }
    Ok(label.to_owned())
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    { metadata.file_type().is_symlink() }
}

fn open_readonly_no_follow(path: &Path) -> Result<File, AgentError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000).share_mode(0x00000001); // OPEN_REPARSE_POINT; FILE_SHARE_READ only.
    }
    #[cfg(not(any(unix, windows)))]
    return Err(AgentError("this platform has no supported no-follow adapter"));
    options.open(path).map_err(|_| AgentError("file could not be opened read-only"))
}

pub fn observe(options: &ObserveOptions) -> Result<AgentObservation, AgentError> {
    // Authorization is explicit local opt-in, not a replacement for server-side PolicyGate.
    if !options.consent { return Err(AgentError("explicit --consent is required")); }
    if !valid_asset_id(&options.asset_id) { return Err(AgentError("--asset-id must be a canonical lowercase UUID")); }
    let path_label = safe_path(&options.file)?;
    let canonical = fs::canonicalize(&options.file).map_err(|_| AgentError("file path is unavailable"))?;
    let canonical_text = canonical.to_str().ok_or(AgentError("file path must be UTF-8"))?;
    let path_id = sha256_bytes(canonical_text.as_bytes());
    let file = open_readonly_no_follow(&options.file)?;
    let before = file.metadata().map_err(|_| AgentError("file metadata is unavailable"))?;
    if !before.is_file() || is_link(&before) { return Err(AgentError("only regular files are accepted")); }
    if before.len() > MAX_FILE_BYTES { return Err(AgentError("file exceeds the 1 MiB limit")); }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&file).take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).map_err(|_| AgentError("file could not be read"))?;
    if bytes.len() as u64 > MAX_FILE_BYTES { return Err(AgentError("file exceeds the 1 MiB limit")); }
    let after = file.metadata().map_err(|_| AgentError("file metadata is unavailable"))?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() || after.len() != bytes.len() as u64 {
        return Err(AgentError("file changed during observation; retry with a stable file"));
    }
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| AgentError("system clock is before Unix epoch"))?;
    let observed_at_epoch_ms = u64::try_from(timestamp.as_millis()).map_err(|_| AgentError("system timestamp is out of range"))?;
    let file_hash = sha256_bytes(&bytes);
    let agent_process_id = std::process::id();
    let observation_id = sha256_bytes(format!("{}:{}:{}:{}:{}:{}", options.asset_id, timestamp.as_nanos(), agent_process_id, path_id, file_hash, uuid::Uuid::new_v4()).as_bytes());
    Ok(AgentObservation {
        schema_version: 1, observation_id, asset_id: options.asset_id.clone(), observed_at_epoch_ms,
        source: "sentinel-agent".into(), observation_type: "integrity.observation".into(), synthetic: false,
        host: HostMetadata { os: std::env::consts::OS.into(), architecture: std::env::consts::ARCH.into(),
            agent_process_id, agent_version: env!("CARGO_PKG_VERSION").into() },
        file: FileObservation { path_label, path_id, bytes: bytes.len() as u64, sha256: file_hash },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    const ASSET: &str = "00000000-0000-4000-8000-000000000001";

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("sentinel-agent-test-{}-{}", std::process::id(), NEXT_ID.fetch_add(1, Ordering::SeqCst)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn file(&self, name: &str, content: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, content).unwrap();
            path
        }
    }
    impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    fn opts(file: PathBuf) -> ObserveOptions { ObserveOptions { consent: true, asset_id: ASSET.into(), file } }

    #[test]
    fn sha256_matches_published_test_vectors() {
        assert_eq!(sha256_bytes(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_bytes(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    #[test]
    fn consent_and_asset_are_required_before_filesystem_access() {
        let mut options = opts(PathBuf::from("missing-file"));
        options.consent = false;
        assert!(observe(&options).unwrap_err().0.contains("consent"));
        options.consent = true;
        options.asset_id = "not-a-uuid".into();
        assert!(observe(&options).unwrap_err().0.contains("asset-id"));
    }
    #[test]
    fn observation_hashes_only_the_selected_file_without_disclosing_content_or_parent_path() {
        let fixture = Fixture::new();
        let selected = fixture.file("config.bin", b"private-input-content");
        let observation = observe(&opts(selected.clone())).unwrap();
        assert_eq!(observation.file.sha256, sha256_bytes(b"private-input-content"));
        assert_eq!(observation.file.path_label, "config.bin");
        assert_eq!(observation.file.bytes, 21);
        assert_eq!(observation.host.agent_process_id, std::process::id());
        assert_eq!(observation.host.os, std::env::consts::OS);
        assert!(!observation.synthetic);
        let json = serde_json::to_string(&observation).unwrap();
        assert!(!json.contains("private-input-content"));
        assert!(!json.contains("sentinel-agent-test"));
        assert_eq!(fs::read(selected).unwrap(), b"private-input-content");
        assert_eq!(serde_json::from_str::<AgentObservation>(&json).unwrap().schema_version, 1);
    }
    #[test]
    fn enforces_one_mebibyte_boundary_and_regular_files() {
        let fixture = Fixture::new();
        assert!(observe(&opts(fixture.file("boundary", &vec![0; MAX_FILE_BYTES as usize]))).is_ok());
        assert!(observe(&opts(fixture.file("too-large", &vec![0; MAX_FILE_BYTES as usize + 1]))).unwrap_err().0.contains("limit"));
        assert!(observe(&opts(fixture.0.clone())).is_err());
    }
    #[test]
    fn parent_traversal_is_rejected() {
        assert!(observe(&opts(PathBuf::from("somewhere/../file"))).unwrap_err().0.contains("traversal"));
    }
    #[test]
    fn path_ids_distinguish_same_basename_and_observations_are_unique() {
        let first = Fixture::new();
        let second = Fixture::new();
        let options = opts(first.file("config.txt", b"same"));
        let one = observe(&options).unwrap();
        let again = observe(&options).unwrap();
        let other = observe(&opts(second.file("config.txt", b"same"))).unwrap();
        assert_eq!(one.file.path_label, other.file.path_label);
        assert_eq!(one.file.path_id, again.file.path_id);
        assert_ne!(one.file.path_id, other.file.path_id);
        assert_ne!(one.observation_id, again.observation_id);
    }
    #[cfg(unix)]
    #[test]
    fn unix_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let target = fixture.file("target", b"target");
        let link = fixture.0.join("link");
        symlink(target, &link).unwrap();
        assert!(observe(&opts(link)).unwrap_err().0.contains("links"));
    }
    #[cfg(windows)]
    #[test]
    fn windows_network_device_and_alternate_stream_paths_are_rejected() {
        for path in ["\\\\server\\share\\file", "\\\\?\\C:\\file", "C:\\file:secret"] {
            assert!(observe(&opts(PathBuf::from(path))).is_err());
        }
    }
    #[test]
    fn uuid_validation_rejects_malformed_inputs() {
        assert!(valid_asset_id(ASSET));
        for id in ["", "asset-1", "000000000000-4000-8000-000000000001", "GGGGGGGG-0000-4000-8000-000000000001"] { assert!(!valid_asset_id(id)); }
    }
}
