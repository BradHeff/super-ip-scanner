//! Headless driver for the REAL scan engine (`engine::start`), used to verify the
//! event-funnel fix and chase the production crash.
//!
//! `tauri::ipc::Channel::new` constructs without a webview, so we can feed `run_scan`
//! a counting closure and exercise the full streaming path — mpsc funnel, the single
//! consumer's coalescing/batching, `HostBatch` serialization, panic isolation, and the
//! final `Finished` — against the real network. Build in release and loop it.
//!
//!   cargo build --release --example scan_repro
//!   sudo setcap cap_net_raw+ep <target-dir>/release/examples/scan_repro
//!   <target-dir>/release/examples/scan_repro 172.20.4.0/24 172.20.4.12

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tauri::ipc::{Channel, InvokeResponseBody};
use tokio::sync::Notify;

use super_ip_scanner_lib::scanner::engine::{self, ScanEvent, ScanOptions};

#[tokio::main]
async fn main() {
    let target = std::env::args().nth(1).unwrap_or_else(|| "172.20.4.0/24".into());
    let source = std::env::args().nth(2).unwrap_or_else(|| "172.20.4.12".into());

    let batches = Arc::new(AtomicUsize::new(0));
    let hosts = Arc::new(AtomicUsize::new(0));
    let progress = Arc::new(AtomicUsize::new(0));
    let finished_scanned = Arc::new(AtomicUsize::new(0));
    let finished_alive = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(Notify::new());

    let channel: Channel<ScanEvent> = {
        let (batches, hosts, progress) = (batches.clone(), hosts.clone(), progress.clone());
        let (fs, fa, done) = (finished_scanned.clone(), finished_alive.clone(), done.clone());
        Channel::new(move |body: InvokeResponseBody| {
            // The engine serializes each ScanEvent to JSON before it reaches us.
            let json = match body {
                InvokeResponseBody::Json(s) => s,
                InvokeResponseBody::Raw(b) => String::from_utf8_lossy(&b).into_owned(),
            };
            let v: serde_json::Value = serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
            match v.get("type").and_then(|t| t.as_str()) {
                Some("hostBatch") => {
                    batches.fetch_add(1, Ordering::Relaxed);
                    let n = v.get("hosts").and_then(|h| h.as_array()).map(|a| a.len()).unwrap_or(0);
                    hosts.fetch_add(n, Ordering::Relaxed);
                }
                Some("progress") => {
                    progress.fetch_add(1, Ordering::Relaxed);
                }
                Some("finished") => {
                    fs.store(v.get("scanned").and_then(|x| x.as_u64()).unwrap_or(0) as usize, Ordering::Relaxed);
                    fa.store(v.get("alive").and_then(|x| x.as_u64()).unwrap_or(0) as usize, Ordering::Relaxed);
                    done.notify_one();
                }
                Some("error") => {
                    eprintln!("[repro] engine error: {}", v.get("message").and_then(|m| m.as_str()).unwrap_or("?"));
                    done.notify_one();
                }
                _ => {}
            }
            Ok(())
        })
    };

    let opts = ScanOptions {
        target: target.clone(),
        source_ip: Some(source),
        concurrency: 256,
        probe_timeout_ms: 1000,
        use_arp: true,
        use_icmp: true,
        use_tcp_probe: true,
        resolve_hostnames: true,
        tcp_ports: vec![],
    };

    eprintln!("[repro] starting real engine scan of {target}");
    let _handle = engine::start(opts, channel).expect("engine start");

    // Wait for Finished (or a generous safety timeout).
    let timed_out = tokio::time::timeout(Duration::from_secs(120), done.notified()).await.is_err();
    if timed_out {
        eprintln!("[repro] TIMED OUT waiting for Finished");
        std::process::exit(2);
    }

    let h = hosts.load(Ordering::Relaxed);
    let b = batches.load(Ordering::Relaxed);
    let p = progress.load(Ordering::Relaxed);
    let fs = finished_scanned.load(Ordering::Relaxed);
    let fa = finished_alive.load(Ordering::Relaxed);
    eprintln!(
        "[repro] FINISHED — hosts_streamed={h} in {b} batches, {p} progress msgs, finished(scanned={fs}, alive={fa})"
    );

    // Correctness checks: every scanned host must arrive exactly once via a batch.
    if h != fs {
        eprintln!("[repro] MISMATCH: streamed {h} hosts but Finished says scanned={fs}");
        std::process::exit(3);
    }
}
