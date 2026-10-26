use sentinel_endpoint_agent::{ObserveOptions, observe, valid_asset_id};
use sentinel_endpoint_agent::transport::{AgentCredentials, Transport, check_cancelled, validate_endpoint, wait_interruptible};
use std::path::PathBuf;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

const HELP: &str = "sentinel-agent --consent --asset-id <lowercase-uuid> --file <explicit-local-file>
  [--endpoint <https-origin> --credential-file <private-json-file>]
  [--iterations <1..10000> --interval-seconds <10..86400>]
  [--allow-loopback-http]
Reads one selected regular file up to 1 MiB per observation. Default: one offline JSON line.
Network sending is opt-in. HTTP requires the explicit flag and literal localhost or 127.0.0.1.
Monitoring is finite and requires both iterations and interval. Ctrl-C stops the run.
No service installation, command execution, file changes, or discovery scans.";

fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let mut consent = false;
    let mut asset_id = None;
    let mut file = None;
    let mut endpoint = None;
    let mut credential_file = None;
    let mut iterations = None;
    let mut interval = None;
    let mut allow_loopback_http = false;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "-h") => {
                println!("{HELP}");
                return Ok(());
            }
            Some("--consent") if !consent => consent = true,
            Some("--asset-id") if asset_id.is_none() => asset_id = Some(args.next().and_then(|value| value.into_string().ok()).ok_or("--asset-id requires a value")?),
            Some("--file") if file.is_none() => file = Some(PathBuf::from(args.next().ok_or("--file requires a value")?)),
            Some("--endpoint") if endpoint.is_none() => endpoint = Some(args.next().and_then(|value| value.into_string().ok()).ok_or("--endpoint requires a value")?),
            Some("--credential-file") if credential_file.is_none() => credential_file = Some(PathBuf::from(args.next().ok_or("--credential-file requires a value")?)),
            Some("--allow-loopback-http") if !allow_loopback_http => allow_loopback_http = true,
            Some("--iterations") if iterations.is_none() => {
                let value = args.next().and_then(|value| value.into_string().ok()).ok_or("--iterations requires a value")?;
                iterations = Some(value.parse::<u32>().map_err(|_| "--iterations must be between 1 and 10000")?);
            }
            Some("--interval-seconds") if interval.is_none() => {
                let value = args.next().and_then(|value| value.into_string().ok()).ok_or("--interval-seconds requires a value")?;
                interval = Some(value.parse::<u64>().map_err(|_| "--interval-seconds must be between 10 and 86400")?);
            }
            _ => return Err("unknown or repeated argument; use --help".into()),
        }
    }
    if !consent { return Err("explicit --consent is required".into()); }
    let options = ObserveOptions { consent, asset_id: asset_id.ok_or("--asset-id is required")?, file: file.ok_or("--file is required")? };
    if !valid_asset_id(&options.asset_id) { return Err("--asset-id must be a canonical lowercase UUID".into()); }
    if iterations.is_some() != interval.is_some() {
        return Err("monitoring requires both --iterations and --interval-seconds".into());
    }
    if iterations.is_some_and(|value| !(1..=10000).contains(&value)) {
        return Err("--iterations must be between 1 and 10000".into());
    }
    if interval.is_some_and(|value| !(10..=86400).contains(&value)) {
        return Err("--interval-seconds must be between 10 and 86400".into());
    }
    if endpoint.is_some() != credential_file.is_some() {
        return Err("sending requires both --endpoint and --credential-file".into());
    }
    if allow_loopback_http && endpoint.is_none() {
        return Err("--allow-loopback-http requires --endpoint".into());
    }
    let transport = if let (Some(endpoint), Some(credential_file)) = (endpoint, credential_file) {
        validate_endpoint(&endpoint, allow_loopback_http).map_err(|error| error.to_string())?;
        let credentials = AgentCredentials::load(&credential_file).map_err(|error| error.to_string())?;
        Some(Transport::new(&endpoint, allow_loopback_http, credentials).map_err(|error| error.to_string())?)
    } else { None };
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal_cancelled = Arc::clone(&cancelled);
    ctrlc::set_handler(move || signal_cancelled.store(true, Ordering::SeqCst))
        .map_err(|_| "interrupt handler could not be initialized")?;
    let iterations = iterations.unwrap_or(1);
    for index in 0..iterations {
        check_cancelled(&cancelled).map_err(|error| error.to_string())?;
        let observation = observe(&options).map_err(|error| error.to_string())?;
        let json = serde_json::to_string(&observation).map_err(|_| "observation serialization failed")?;
        if let Some(transport) = &transport {
            transport.send(json.as_bytes(), &cancelled).map_err(|error| error.to_string())?;
        }
        println!("{json}");
        if index + 1 < iterations {
            wait_interruptible(Duration::from_secs(interval.unwrap_or(10)), &cancelled).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("sentinel-agent: {error}");
        std::process::exit(if error == "interrupted" { 130 } else { 2 });
    }
}
