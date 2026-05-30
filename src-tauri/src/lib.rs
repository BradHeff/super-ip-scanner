mod commands;
mod scanner;

use tauri::Manager;
use tokio::sync::Mutex;

pub struct AppState {
    pub scan_handle: Mutex<Option<scanner::engine::ScanHandle>>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // WebKitGTK on some Wayland compositors crashes at startup with
    // `Gdk-Message: Error 71 (Protocol error) dispatching to Wayland display`.
    // Disabling the DMABUF renderer and (under Wayland) falling back to the X11
    // backend via XWayland avoids it. Done before GTK initializes; only sets
    // each var if the user hasn't overridden it, so `GDK_BACKEND=wayland` still wins.
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
        if std::env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() {
            std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        }
        if std::env::var_os("WAYLAND_DISPLAY").is_some()
            && std::env::var_os("GDK_BACKEND").is_none()
        {
            std::env::set_var("GDK_BACKEND", "x11");
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,super_ip_scanner_lib=debug".into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_os::init())
        .setup(|app| {
            app.manage(AppState {
                scan_handle: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_interfaces,
            commands::detect_local_subnet,
            commands::start_scan,
            commands::stop_scan,
            commands::export_results,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
