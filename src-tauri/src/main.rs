#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

// ---------- std ----------
use std::{
    convert::Infallible,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    fs,
};

// ---------- deps ----------
use dashmap::DashMap;
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server, StatusCode,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use url::Url;

// tauri v2
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconBuilder; // <— no click handlers; menu opens on both buttons
use tauri::{AppHandle, Emitter, Listener, Manager, Window};

// plugins (v2)
use tauri_plugin_dialog;
use tauri_plugin_opener;
use tauri_plugin_shell;
use tauri_plugin_single_instance;

static MAIN_WINDOW_NAME: &str = "main";

// ---------- commands ----------
#[tauri::command]
async fn save_file(path: String, contents: Vec<u8>) -> Result<(), String> {
    use std::fs::File;
    use std::io::Write;

    println!("Saving file to: {}", path);
    let mut file = File::create(&path).map_err(|e| e.to_string())?;
    file.write_all(&contents).map_err(|e| e.to_string())?;
    println!("File saved successfully");
    Ok(())
}

#[derive(Serialize)]
struct ProxyFetchResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

#[tauri::command]
async fn proxy_fetch_manifest(url: String) -> Result<ProxyFetchResponse, String> {
    let parsed = Url::parse(&url).map_err(|e| format!("invalid url: {e}"))?;
    if parsed.scheme() != "https" {
        return Err("only https scheme is allowed".into());
    }
    let path = parsed.path().to_ascii_lowercase();
    if !(path.ends_with("/manifest.json") || path == "/manifest.json") {
        return Err("only manifest.json paths are allowed".into());
    }

    let client = Client::builder()
        .user_agent("metanet-desktop/1.0 (+https://github.com/bsv-blockchain/metanet-desktop)")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(parsed)
        .header(reqwest::header::ACCEPT, "application/json, */*;q=0.8")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();
    let mut headers_vec: Vec<(String, String)> = Vec::new();
    for (k, v) in resp.headers().iter() {
        headers_vec.push((k.as_str().to_string(), v.to_str().unwrap_or("").to_string()));
    }

    let body = resp.text().await.map_err(|e| e.to_string())?;

    Ok(ProxyFetchResponse {
        status,
        headers: headers_vec,
        body,
    })
}

#[tauri::command]
async fn download(app_handle: AppHandle, filename: String, content: Vec<u8>) -> Result<(), String> {
    let downloads_dir = app_handle.path().download_dir().map_err(|e| e.to_string())?;
    let path = PathBuf::from(downloads_dir);

    let path_obj = Path::new(&filename);
    let stem = path_obj.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = path_obj.extension().and_then(|e| e.to_str()).unwrap_or("");

    // initial path
    let mut final_path = path.clone();
    final_path.push(&filename);

    // de-dupe
    let mut counter = 1;
    while final_path.exists() {
        let new_filename = if ext.is_empty() {
            format!("{} ({})", stem, counter)
        } else {
            format!("{} ({}).{}", stem, counter, ext)
        };
        final_path = path.clone();
        final_path.push(new_filename);
        counter += 1;
    }

    fs::write(&final_path, content).map_err(|e| e.to_string())
}

// ---------- focus helpers ----------
#[cfg(target_os = "macos")]
use once_cell::sync::Lazy;
#[cfg(target_os = "macos")]
use std::sync::Mutex;
#[cfg(target_os = "macos")]
static PREV_BUNDLE_ID: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

#[tauri::command]
fn is_focused(window: Window) -> bool {
    match window.is_focused() {
        Ok(f) => f,
        Err(_) => false,
    }
}

#[tauri::command]
fn request_focus(window: Window) {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("osascript")
            .arg("-e")
            .arg("tell application \"System Events\" to get the bundle identifier of the first process whose frontmost is true")
            .output()
        {
            if output.status.success() {
                if let Ok(bundle_id) = String::from_utf8(output.stdout) {
                    let mut prev = PREV_BUNDLE_ID.lock().unwrap();
                    *prev = Some(bundle_id.trim().to_string());
                }
            }
        }
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.request_user_attention(Some(tauri::UserAttentionType::Informational));
        for _ in 0..3 {
            if window.is_focused().ok() == Some(true) { break; }
            let _ = window.set_focus();
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    #[cfg(target_os = "windows")]
    {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        let _ = window.set_always_on_top(true);
        let _ = window.set_always_on_top(false);
    }

    #[cfg(target_os = "linux")]
    {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        std::thread::sleep(std::time::Duration::from_millis(30));
        if window.is_focused().ok() != Some(true) {
            let _ = window.set_focus();
        }
    }
}

#[tauri::command]
fn relinquish_focus(window: Window) {
    #[cfg(target_os = "linux")]
    { let _ = window.minimize(); }

    #[cfg(target_os = "windows")]
    { let _ = window.minimize(); }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let prev_bundle_id = { PREV_BUNDLE_ID.lock().unwrap().clone() };
        if let Some(id) = prev_bundle_id {
            if !id.is_empty() && id != "com.apple.finder" {
                let script = format!("tell application id \"{}\" to activate", id);
                let _ = Command::new("osascript").arg("-e").arg(&script).output();
            }
        }
        let _ = window.is_focused();
    }
}

// ---------- HTTP relay data ----------
#[derive(Serialize)]
struct HttpRequestEvent {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
    request_id: u64,
}

#[derive(Deserialize, Debug)]
struct TsResponse {
    request_id: u64,
    status: u16,
    body: String,
}

type PendingMap = DashMap<u64, oneshot::Sender<TsResponse>>;

// ---------- tray helper ----------
fn install_tray(app: &tauri::App) -> tauri::Result<()> {
    // menu
    let show_item = MenuItemBuilder::with_id("show", "Show").build(app)?;
    let hide_item = MenuItemBuilder::with_id("hide", "Hide").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

    let tray_menu = MenuBuilder::new(app)
        .item(&show_item)
        .item(&hide_item)
        .separator()
        .item(&quit_item)
        .build()?;

    // icon + handlers
    let app_handle = app.handle();
    let mut tray_builder = TrayIconBuilder::new()
        .menu(&tray_menu)
        .show_menu_on_left_click(true) // left-click opens menu (right-click already does)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window(MAIN_WINDOW_NAME) {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                }
            }
            "hide" => {
                if let Some(w) = app.get_webview_window(MAIN_WINDOW_NAME) {
                    let _ = w.hide();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        });

    if let Some(icon) = app_handle.default_window_icon().cloned() {
        tray_builder = tray_builder.icon(icon);
    }

    tray_builder.build(app)?;
    Ok(())
}

// ---------- main ----------
fn main() {
    let app = tauri::Builder::default()
        // Catch second launches from shortcuts/Dock and bring the hidden window forward
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window(MAIN_WINDOW_NAME) {
                #[cfg(target_os = "windows")]
                {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                    // Nudge focus on Windows
                    let _ = w.set_always_on_top(true);
                    let _ = w.set_always_on_top(false);
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                }
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // main window
            let main_window: tauri::WebviewWindow =
                app.get_webview_window(MAIN_WINDOW_NAME).expect("main window not found");

            // Close → hide (keep running in background)
            {
                let main_window_for_event = main_window.clone();
                main_window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = main_window_for_event.hide();
                    }
                });
            }

            // Tray (cross-platform)
            install_tray(app)?;

            // Optional macOS niceties: show on Dock activate/reopen/focus
            #[cfg(target_os = "macos")]
            {
                let app_handle_activate_outer = app.handle().clone();
                let app_handle_activate_inner = app_handle_activate_outer.clone();
                app_handle_activate_outer.listen("tauri://activate", move |_| {
                    if let Some(w) = app_handle_activate_inner.get_webview_window(MAIN_WINDOW_NAME) {
                        let _ = w.show();
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                });

                let app_handle_reopen_outer = app.handle().clone();
                let app_handle_reopen_inner = app_handle_reopen_outer.clone();
                app_handle_reopen_outer.listen("tauri://reopen", move |_| {
                    if let Some(w) = app_handle_reopen_inner.get_webview_window(MAIN_WINDOW_NAME) {
                        let _ = w.show();
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                });

                let app_handle_focus_outer = app.handle().clone();
                let app_handle_focus_inner = app_handle_focus_outer.clone();
                app_handle_focus_outer.listen("tauri://focus", move |_| {
                    if let Some(w) = app_handle_focus_inner.get_webview_window(MAIN_WINDOW_NAME) {
                        let _ = w.show();
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                });
            }

            // ---------- HTTP relay setup ----------
            let pending_requests: Arc<PendingMap> = Arc::new(DashMap::new());
            let request_counter = Arc::new(AtomicU64::new(1));

            {
                let pending_requests = pending_requests.clone();
                main_window.listen("ts-response", move |event| {
                    let payload = event.payload();
                    if !payload.is_empty() {
                        match serde_json::from_str::<TsResponse>(payload) {
                            Ok(ts_response) => {
                                if let Some((req_id, tx)) = pending_requests.remove(&ts_response.request_id) {
                                    let _ = tx.send(ts_response);
                                } else {
                                    eprintln!("Received ts-response for unknown request_id");
                                }
                            }
                            Err(err) => eprintln!("Failed to parse ts-response payload: {:?}", err),
                        }
                    } else {
                        eprintln!("ts-response event did not include a payload");
                    }
                });
            }

            // spawn Tokio for Hyper
            let main_window_clone = main_window.clone();
            let pending_requests_clone = pending_requests.clone();
            let request_counter_clone = request_counter.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create Tokio runtime");

                rt.block_on(async move {
                    let addr: SocketAddr = "127.0.0.1:3321".parse().expect("Invalid socket address");
                    println!("HTTP server listening on http://{}", addr);

                    match Server::try_bind(&addr) {
                        Ok(builder) => {
                            let make_svc = make_service_fn(move |_conn| {
                                let pending_requests = pending_requests_clone.clone();
                                let main_window = main_window_clone.clone();
                                let request_counter = request_counter_clone.clone();

                                async move {
                                    Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                                        let pending_requests = pending_requests.clone();
                                        let main_window = main_window.clone();
                                        let request_counter = request_counter.clone();

                                        async move {
                                            // CORS preflight
                                            if req.method() == hyper::Method::OPTIONS {
                                                let mut res = Response::new(Body::empty());
                                                res.headers_mut().insert("Access-Control-Allow-Origin", "*".parse().unwrap());
                                                res.headers_mut().insert("Access-Control-Allow-Headers", "*".parse().unwrap());
                                                res.headers_mut().insert("Access-Control-Allow-Methods", "*".parse().unwrap());
                                                res.headers_mut().insert("Access-Control-Expose-Headers", "*".parse().unwrap());
                                                res.headers_mut().insert("Access-Control-Allow-Private-Network", "true".parse().unwrap());
                                                return Ok::<_, Infallible>(res);
                                            }

                                            let request_id = request_counter.fetch_add(1, Ordering::Relaxed);

                                            let method = req.method().clone();
                                            let uri = req.uri().clone();
                                            let headers = req.headers().iter()
                                                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                                                .collect::<Vec<(String, String)>>();

                                            let whole_body = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                                            let body_str = String::from_utf8_lossy(&whole_body).to_string();

                                            let (tx, rx) = oneshot::channel::<TsResponse>();
                                            pending_requests.insert(request_id, tx);

                                            let event_payload = HttpRequestEvent {
                                                method: method.to_string(),
                                                path: uri.to_string(),
                                                headers,
                                                body: body_str,
                                                request_id,
                                            };

                                            let event_json = match serde_json::to_string(&event_payload) {
                                                Ok(json) => json,
                                                Err(e) => {
                                                    eprintln!("Failed to serialize HTTP event: {:?}", e);
                                                    let mut res = Response::new(Body::from("Internal Server Error"));
                                                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                    res.headers_mut().insert("Access-Control-Allow-Origin", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Allow-Headers", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Allow-Methods", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Expose-Headers", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Allow-Private-Network", "true".parse().unwrap());
                                                    pending_requests.remove(&request_id);
                                                    return Ok::<_, Infallible>(res);
                                                }
                                            };

                                            if let Err(err) = main_window.emit("http-request", event_json) {
                                                eprintln!("Failed to emit http-request event: {:?}", err);
                                                pending_requests.remove(&request_id);
                                                let mut res = Response::new(Body::from("Internal Server Error"));
                                                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                res.headers_mut().insert("Access-Control-Allow-Origin", "*".parse().unwrap());
                                                res.headers_mut().insert("Access-Control-Allow-Headers", "*".parse().unwrap());
                                                res.headers_mut().insert("Access-Control-Allow-Methods", "*".parse().unwrap());
                                                res.headers_mut().insert("Access-Control-Expose-Headers", "*".parse().unwrap());
                                                res.headers_mut().insert("Access-Control-Allow-Private-Network", "true".parse().unwrap());
                                                return Ok::<_, Infallible>(res);
                                            }

                                            match rx.await {
                                                Ok(ts_response) => {
                                                    let mut res = Response::new(Body::from(ts_response.body));
                                                    *res.status_mut() = StatusCode::from_u16(ts_response.status).unwrap_or(StatusCode::OK);
                                                    res.headers_mut().insert("Access-Control-Allow-Origin", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Allow-Headers", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Allow-Methods", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Expose-Headers", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Allow-Private-Network", "true".parse().unwrap());
                                                    Ok::<_, Infallible>(res)
                                                }
                                                Err(err) => {
                                                    eprintln!("Error awaiting frontend response for request {}: {:?}", request_id, err);
                                                    let mut res = Response::new(Body::from("Gateway Timeout"));
                                                    *res.status_mut() = StatusCode::GATEWAY_TIMEOUT;
                                                    res.headers_mut().insert("Access-Control-Allow-Origin", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Allow-Headers", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Allow-Methods", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Expose-Headers", "*".parse().unwrap());
                                                    res.headers_mut().insert("Access-Control-Allow-Private-Network", "true".parse().unwrap());
                                                    Ok::<_, Infallible>(res)
                                                }
                                            }
                                        }
                                    }))
                                }
                            });

                            let server = builder.serve(make_svc);
                            if let Err(e) = server.await {
                                eprintln!("Server error: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to bind server: {}", e);
                            std::process::exit(1);
                        }
                    }
                });
            });

            // show on first launch (comment these to start-in-tray)
            let _ = main_window.show();
            let _ = main_window.unminimize();
            let _ = main_window.set_focus();

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            is_focused,
            request_focus,
            relinquish_focus,
            download,
            save_file,
            proxy_fetch_manifest
        ])
        .build(tauri::generate_context!())
        .expect("Error while building Tauri application");

    app.run(|_, _| {});
}
