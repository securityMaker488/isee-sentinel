#![forbid(unsafe_code)]
use sentinel_execution_engine::{MAX_REQUEST, parse_request, supervise};
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Duration;

fn run() -> Result<bool, &'static str> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 || args[0] != "--python" || args[2] != "--worker" {
        return Err("invalid_configuration");
    }
    let python = PathBuf::from(&args[1]);
    let worker = PathBuf::from(&args[3]);
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut reader = io::BufReader::new(io::stdin());
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take(MAX_REQUEST + 1)
            .read_until(b'\n', &mut line);
        let request = if read.is_ok() && line.last() == Some(&b'\n') {
            parse_request(&line)
        } else {
            Err("invalid_request")
        };
        if sender.send(request).is_err() {
            return;
        }
        // Any further byte or EOF revokes this one-shot execution lease.
        let mut byte = [0u8; 1];
        let _ = reader.read(&mut byte);
        flag.store(true, Ordering::SeqCst);
    });
    let request = receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| "request_timeout")??;
    let result = supervise(request, &python, &worker, cancelled)?;
    let success = result.receipt.status == "completed";
    serde_json::to_writer(io::stdout().lock(), &result).map_err(|_| "output_failed")?;
    io::stdout().flush().map_err(|_| "output_failed")?;
    Ok(success)
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(3),
        Err(code) => {
            eprintln!("{code}");
            std::process::exit(2);
        }
    }
}
