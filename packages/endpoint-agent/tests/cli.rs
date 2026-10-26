use std::process::Command;

#[test]
fn cli_denies_missing_consent_without_observation_output() {
    let result = Command::new(env!("CARGO_BIN_EXE_sentinel-agent"))
        .args(["--asset-id", "00000000-0000-4000-8000-000000000001", "--file", "missing"])
        .output().unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("consent"));
}

#[test]
fn cli_help_does_not_observe_host() {
    let result = Command::new(env!("CARGO_BIN_EXE_sentinel-agent")).arg("--help").output().unwrap();
    assert!(result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("agentProcessId"));
}

#[test]
fn cli_rejects_unbounded_or_implicit_monitoring_and_partial_transport() {
    let base = ["--consent", "--asset-id", "00000000-0000-4000-8000-000000000001", "--file", "missing"];
    for (args, expected) in [
        (vec!["--iterations", "2"], "both --iterations"),
        (vec!["--interval-seconds", "10"], "both --iterations"),
        (vec!["--iterations", "0", "--interval-seconds", "10"], "between 1 and 10000"),
        (vec!["--iterations", "10001", "--interval-seconds", "10"], "between 1 and 10000"),
        (vec!["--iterations", "2", "--interval-seconds", "9"], "between 10 and 86400"),
        (vec!["--iterations", "2", "--interval-seconds", "86401"], "between 10 and 86400"),
        (vec!["--endpoint", "https://collector.example"], "both --endpoint"),
        (vec!["--credential-file", "missing"], "both --endpoint"),
        (vec!["--allow-loopback-http"], "requires --endpoint"),
        (vec!["--endpoint", "http://collector.example", "--credential-file", "missing"], "HTTP requires"),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_sentinel-agent")).args(base).args(args).output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains(expected));
    }
}

#[test]
fn explicit_monitor_finishes_after_two_distinct_observations() {
    let folder = std::env::temp_dir().join(format!("sentinel-loop-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&folder).unwrap();
    let file = folder.join("selected.txt");
    std::fs::write(&file, b"local integration fixture").unwrap();
    let start = std::time::Instant::now();
    let result = Command::new(env!("CARGO_BIN_EXE_sentinel-agent"))
        .args(["--consent", "--asset-id", "00000000-0000-4000-8000-000000000001", "--iterations", "2", "--interval-seconds", "10", "--file"])
        .arg(&file).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert!(start.elapsed() >= std::time::Duration::from_secs(10));
    let output = String::from_utf8(result.stdout).unwrap();
    let observations: Vec<serde_json::Value> = output.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(observations.len(), 2);
    assert_ne!(observations[0]["observationId"], observations[1]["observationId"]);
    assert_eq!(observations[0]["file"]["pathId"], observations[1]["file"]["pathId"]);
    assert!(observations[1]["observedAtEpochMs"].as_u64().unwrap() >= observations[0]["observedAtEpochMs"].as_u64().unwrap() + 10000);
    assert_eq!(std::fs::read(&file).unwrap(), b"local integration fixture");
    std::fs::remove_dir_all(folder).unwrap();
}
