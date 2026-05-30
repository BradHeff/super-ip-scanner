use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{AppHandle, State};

use crate::scanner::{
    engine::{self, ScanEvent, ScanOptions},
    network, types::{HostResult, NetIface},
};
use crate::AppState;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DetectedSubnet {
    pub iface_name: String,
    pub cidr: String,
    pub gateway: Option<String>,
}

#[tauri::command]
pub fn list_interfaces() -> Result<Vec<NetIface>, String> {
    network::list_interfaces().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn detect_local_subnet() -> Result<Vec<DetectedSubnet>, String> {
    network::detect_local_subnets().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn start_scan(
    state: State<'_, AppState>,
    options: ScanOptions,
    on_event: Channel<ScanEvent>,
) -> Result<(), String> {
    let mut guard = state.scan_handle.lock().await;
    if let Some(handle) = guard.take() {
        handle.cancel();
    }
    let handle = engine::start(options, on_event).map_err(|e| e.to_string())?;
    *guard = Some(handle);
    Ok(())
}

#[tauri::command]
pub async fn stop_scan(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.scan_handle.lock().await;
    if let Some(handle) = guard.take() {
        handle.cancel();
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportRequest {
    pub path: PathBuf,
    pub format: String, // "csv" | "json"
    pub hosts: Vec<HostResult>,
}

#[tauri::command]
pub async fn export_results(_app: AppHandle, req: ExportRequest) -> Result<(), String> {
    match req.format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&req.hosts).map_err(|e| e.to_string())?;
            tokio::fs::write(&req.path, json).await.map_err(|e| e.to_string())
        }
        "csv" => {
            let mut wtr = csv::Writer::from_path(&req.path).map_err(|e| e.to_string())?;
            wtr.write_record([
                "IP", "Status", "Hostname", "MAC", "Vendor", "RTT (ms)", "Open Ports",
            ])
            .map_err(|e| e.to_string())?;
            for h in &req.hosts {
                wtr.write_record([
                    h.ip.clone(),
                    format!("{:?}", h.status),
                    h.hostname.clone().unwrap_or_default(),
                    h.mac.clone().unwrap_or_default(),
                    h.vendor.clone().unwrap_or_default(),
                    h.rtt_ms.map(|v| format!("{v:.1}")).unwrap_or_default(),
                    h.open_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ])
                .map_err(|e| e.to_string())?;
            }
            wtr.flush().map_err(|e| e.to_string())
        }
        other => Err(format!("unknown format: {other}")),
    }
}
