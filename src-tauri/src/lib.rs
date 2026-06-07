mod commands;
pub mod scanner;

use tauri::Manager;
use tokio::sync::Mutex;

pub struct AppState {
    pub scan_handle: Mutex<Option<scanner::engine::ScanHandle>>,
}

/// Raise the soft open-file limit to the hard limit.
///
/// Graphical sessions (lightdm/GNOME under X11) commonly start apps with a soft
/// `RLIMIT_NOFILE` of 1024 even though the hard limit is large (e.g. 524288). A scan
/// at high concurrency opens thousands of sockets at once; once the soft limit is hit,
/// the WebKitGTK renderer can no longer create its shared-memory buffers
/// (`Failed to create shared memory: Too many open files`) and the window goes black.
/// Bumping the soft limit to the hard limit before the webview spawns gives both the
/// scan and the webview (and its child processes, which inherit this) ample headroom.
#[cfg(unix)]
pub fn raise_fd_limit() {
    unsafe {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        if lim.rlim_cur < lim.rlim_max {
            let target = lim.rlim_max;
            lim.rlim_cur = target;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) == 0 {
                tracing::info!("raised RLIMIT_NOFILE soft limit to {target}");
            } else {
                tracing::warn!("could not raise RLIMIT_NOFILE soft limit");
            }
        }
    }
}

#[cfg(not(unix))]
pub fn raise_fd_limit() {}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Must happen before the webview (and its child processes) spawn so they inherit
    // the raised limit.
    raise_fd_limit();

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
