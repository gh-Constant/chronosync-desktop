mod supabase;
mod session_storage;
mod icon_manager;
mod color_convert;

use anyhow::Result;
use chrono::{DateTime, Utc};
use dotenv::dotenv;
use eframe::{egui, Frame, NativeOptions};
use log::{error, info};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    os::windows::ffi::OsStringExt,
    sync::Arc,
    time::{Duration, Instant},
    thread,
    process::Command,
    io,
};
use tokio::time::sleep;
use uuid::Uuid;
use winapi::{
    shared::{minwindef::DWORD, windef::HWND},
    um::{
        processthreadsapi::{GetCurrentProcessId, OpenProcess},
        psapi::GetModuleFileNameExW,
        winnt::PROCESS_QUERY_INFORMATION,
        winuser::{GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId},
    },
};
use crossbeam_channel::{bounded, Sender};
use webbrowser;
use winreg::{enums::*, RegKey};
use portpicker;
use tiny_http;

use crate::supabase::{Session, SupabaseClient, Provider};
use crate::session_storage::SessionStorage;
use crate::icon_manager::IconManager;

#[derive(Debug, Serialize, Deserialize)]
struct AppUsageData {
    user_id: Uuid,
    package_name: String,
    app_name: String,
    time_in_foreground: u64,
    timestamp: DateTime<Utc>,
    os: String,
}

#[derive(Debug)]
struct ChronoSyncApp {
    session: Option<Session>,
    last_window: Option<WindowInfo>,
    last_window_time: Instant,
    window_monitor: Arc<Mutex<WindowMonitor>>,
    login_email: String,
    login_password: String,
    error_message: Option<String>,
    login_tx: crossbeam_channel::Sender<LoginResult>,
    login_rx: crossbeam_channel::Receiver<LoginResult>,
    session_storage: SessionStorage,
}

#[derive(Debug)]
enum LoginResult {
    Success(Session),
    Error(String),
    OAuthStart(String),
}

#[derive(Debug, Clone)]
struct WindowInfo {
    hwnd: HWND,
    title: String,
    package_name: String,
}

// Make WindowInfo Send + Sync since HWND is just a pointer
unsafe impl Send for WindowInfo {}
unsafe impl Sync for WindowInfo {}

#[derive(Debug)]
struct WindowMonitor {
    last_window: Option<WindowInfo>,
    last_window_time: Instant,
    session: Option<Session>,
    app_usage_times: std::collections::HashMap<String, u64>,
    last_update_time: Instant,
}

impl WindowMonitor {
    fn new() -> Self {
        Self {
            last_window: None,
            last_window_time: Instant::now(),
            session: None,
            app_usage_times: std::collections::HashMap::new(),
            last_update_time: Instant::now(),
        }
    }

    fn set_session(&mut self, session: Option<Session>) {
        self.session = session;
        if let Some(session) = &self.session {
            self.app_usage_times.clear();
            self.last_update_time = Instant::now();
        }

    }

    unsafe fn get_window_title(hwnd: HWND) -> Result<String> {
        let mut buffer = [0u16; 512];
        let len = GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32);
        if len == 0 {
            return Ok(String::from("Unknown"));
        }
        let os_string = OsString::from_wide(&buffer[..len as usize]);
        Ok(os_string.to_string_lossy().into_owned())
    }

    unsafe fn get_package_name(hwnd: HWND) -> Result<String> {
        let mut buffer = [0u16; 512];
        let mut process_id: DWORD = 0;
        GetWindowThreadProcessId(hwnd, &mut process_id);
        
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, process_id);
        if process_handle.is_null() {
            return Ok(String::from("Unknown"));
        }

        let len = GetModuleFileNameExW(
            process_handle,
            0 as _,
            buffer.as_mut_ptr(),
            buffer.len() as DWORD,
        );
        if len == 0 {
            return Ok(String::from("Unknown"));
        }
        let os_string = OsString::from_wide(&buffer[..len as usize]);
        Ok(os_string.to_string_lossy().into_owned())
    }

    async fn check_active_window(&mut self) -> Option<AppUsageData> {
        if self.session.is_none() {
            return None;
        }

        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.is_null() {
                return None;
            }

            let title = Self::get_window_title(hwnd).unwrap_or_else(|_| String::from("Unknown"));
            let package_name = Self::get_package_name(hwnd).unwrap_or_else(|_| String::from("Unknown"));
            
            let current_window = WindowInfo {
                hwnd,
                title: title.clone(),
                package_name: package_name.clone(),
            };

            let now = Instant::now();
            let elapsed = now.duration_since(self.last_update_time);

            // Update time for current window
            if let Some(ref last) = self.last_window {
                if last.hwnd == hwnd {
                    let total_time = self.app_usage_times
                        .entry(package_name.clone())
                        .or_insert(0);
                    *total_time += elapsed.as_millis() as u64;
                }
            }

            // Create usage data if window changed or enough time has passed
            let usage_data = if let Some(ref last) = self.last_window {
                if last.hwnd != hwnd || elapsed.as_secs() >= 5 {
                    let total_time = *self.app_usage_times
                        .get(&last.package_name)
                        .unwrap_or(&0);

                    // Upload icon separately from usage data
                    if let Ok(supabase) = crate::supabase::SupabaseClient::get() {
                        if let Ok(Some(_)) = IconManager::extract_and_upload_icon(&last.package_name).await {
                            info!("Icon uploaded successfully for {}", last.package_name);
                        }
                    }

                    Some(AppUsageData {
                        user_id: self.session.as_ref().unwrap().user_id,
                        package_name: last.package_name.clone(),
                        app_name: last.title.clone(),
                        time_in_foreground: total_time,
                        timestamp: Utc::now(),
                        os: String::from("Windows"),
                    })
                } else {
                    None
                }
            } else {
                None
            };

            // Update state
            self.last_window = Some(current_window);
            self.last_update_time = now;

            usage_data
        }
    }
}

fn find_free_port() -> Option<u16> {
    portpicker::pick_unused_port()
}

impl ChronoSyncApp {
    fn register_protocol_handler() -> Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = format!("Software\\Classes\\chronosync");
        let (key, _) = hkcu.create_subkey(&path)?;
        key.set_value("", &"URL:Chronosync Protocol")?;
        key.set_value("URL Protocol", &"")?;

        let (cmd_key, _) = key.create_subkey("shell\\open\\command")?;
        let exe_path = std::env::current_exe()?;
        cmd_key.set_value("", &format!("\"{}\" \"%1\"", exe_path.display()))?;

        Ok(())
    }

    fn handle_oauth_callback(url: &str) -> Result<Session> {
        let url = url::Url::parse(url)?;
        let fragments: std::collections::HashMap<_, _> = url.fragment()
            .unwrap_or("")
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.split('=');
                Some((parts.next()?, parts.next()?))
            })
            .collect();

        let access_token = fragments.get("access_token")
            .ok_or_else(|| anyhow::anyhow!("No access token in callback"))?;
        
        let user_id = Uuid::parse_str(
            fragments.get("sub")
                .ok_or_else(|| anyhow::anyhow!("No user ID in callback"))?,
        )?;

        Ok(Session {
            access_token: access_token.to_string(),
            user_id,
        })
    }

    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Register protocol handler
        if let Err(e) = Self::register_protocol_handler() {
            error!("Failed to register protocol handler: {}", e);
        }

        // Initialize Supabase client
        let supabase_url = std::env::var("SUPABASE_URL")
            .expect("SUPABASE_URL must be set");
        let supabase_key = std::env::var("SUPABASE_ANON_KEY")
            .expect("SUPABASE_ANON_KEY must be set");

        if let Err(e) = SupabaseClient::initialize(supabase_url, supabase_key) {
            error!("Failed to initialize Supabase client: {}", e);
        }

        let window_monitor = Arc::new(Mutex::new(WindowMonitor::new()));
        let monitor_clone = window_monitor.clone();
        
        // Create channel for window monitoring
        let (tx, rx) = bounded(100);

        // Start the window monitoring task
        let monitor_clone2 = monitor_clone.clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                while let Ok(usage_data) = rx.recv() {
                    if let Ok(supabase) = SupabaseClient::get() {
                        if let Some(session) = &monitor_clone2.lock().session {
                            if let Err(e) = supabase.insert_app_usage(session, &usage_data).await {
                                error!("Failed to insert app usage: {}", e);
                            }
                        }
                    }
                }
            });
        });

        // Start window checking task
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                loop {
                    if let Some(usage_data) = monitor_clone.lock().check_active_window().await {
                        info!("Window changed: {:?}", usage_data);
                        if let Err(e) = tx.send(usage_data) {
                            error!("Failed to send usage data: {}", e);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            });
        });

        let (login_tx, login_rx) = bounded(1);
        let session_storage = SessionStorage::new();
        
        // Try to load saved session
        let session = session_storage.load_session().ok().flatten();
        if let Some(session) = &session {
            window_monitor.lock().set_session(Some(session.clone()));
        }

        Self {
            session,
            last_window: None,
            last_window_time: Instant::now(),
            window_monitor,
            login_email: String::new(),
            login_password: String::new(),
            error_message: None,
            login_tx,
            login_rx,
            session_storage,
        }
    }

    fn handle_login(&mut self) {
        let email = self.login_email.clone();
        let password = self.login_password.clone();
        let window_monitor = self.window_monitor.clone();
        let login_tx = self.login_tx.clone();
        let session_storage = self.session_storage.clone();

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let result = if let Ok(supabase) = SupabaseClient::get() {
                    match supabase.sign_in(&email, &password).await {
                        Ok(session) => {
                            window_monitor.lock().set_session(Some(session.clone()));
                            if let Err(e) = session_storage.save_session(&session) {
                                error!("Failed to save session: {}", e);
                            }
                            LoginResult::Success(session)
                        },
                        Err(e) => LoginResult::Error(format!("Login failed: {}", e)),
                    }
                } else {
                    LoginResult::Error("Supabase client not initialized".to_string())
                };
                let _ = login_tx.send(result);
            });
        });
    }

    fn handle_logout(&mut self) {
        self.session = None;
        self.window_monitor.lock().set_session(None);
        if let Err(e) = self.session_storage.clear_session() {
            error!("Failed to clear session: {}", e);
        }
    }

    fn handle_oauth_login(&mut self, provider: Provider) {
        let login_tx = self.login_tx.clone();
        let window_monitor = self.window_monitor.clone();

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                if let Ok(supabase) = SupabaseClient::get() {
                    // Find a free port for our temporary server
                    if let Some(port) = find_free_port() {
                        let callback_url = format!("http://localhost:{}/callback", port);
                        
                        match supabase.sign_in_with_oauth(provider, &callback_url).await {
                            Ok(url) => {
                                // Start local server to handle callback
                                let server = tiny_http::Server::http(format!("127.0.0.1:{}", port))
                                    .expect("Failed to start local server");

                                // Open browser with OAuth URL
                                if let Err(e) = webbrowser::open(&url) {
                                    let _ = login_tx.send(LoginResult::Error(format!("Failed to open browser: {}", e)));
                                    return;
                                }

                                // Wait for callback
                                let request = server.incoming_requests().next();
                                info!("Waiting for callback request...");
                                if let Some(mut request) = request {
                                    let url_str = format!("http://localhost{}", request.url());
                                    info!("Received callback URL: {}", url_str);
                                    let parsed_url = url::Url::parse(&url_str).unwrap();
                                    
                                    // Log request details
                                    info!("Request method: {}", request.method());
                                    info!("Request path: {}", request.url());
                                    info!("Request headers: {:?}", request.headers());
                                    info!("Query string: {:?}", parsed_url.query());
                                    info!("URL fragments: {:?}", parsed_url.fragment());
                                    
                                    // Read and log the request body first
                                    let mut content = String::new();
                                    if let Ok(_) = request.as_reader().read_to_string(&mut content) {
                                        info!("Request body: {}", content);
                                    } else {
                                        error!("Failed to read request body");
                                    }

                                    // Send success response to browser
                                    let response = tiny_http::Response::from_string("Login successful! You can close this window.")
                                        .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..]).unwrap());
                                    if let Err(e) = request.respond(response) {
                                        error!("Failed to send response to browser: {}", e);
                                    }
                                    
                                    // Try to find code in request body
                                    if content.contains("code=") {
                                        let code = content.split("code=").nth(1)
                                            .and_then(|s| s.split('&').next());
                                        if let Some(code) = code {
                                            info!("Found authorization code in request body: {}", code);
                                            match supabase.exchange_code_for_session(code).await {
                                                Ok(session) => {
                                                    info!("Successfully exchanged code for session");
                                                    window_monitor.lock().set_session(Some(session.clone()));
                                                    let _ = login_tx.send(LoginResult::Success(session));
                                                    return;
                                                }
                                                Err(e) => {
                                                    error!("Failed to exchange code from body: {}", e);
                                                }
                                            }
                                        }
                                    }

                                    // Try to find code in query parameters
                                    let query_pairs: std::collections::HashMap<_, _> = parsed_url.query_pairs().collect();
                                    info!("Query parameters: {:?}", query_pairs);

                                    if let Some(code) = query_pairs.get("code") {
                                        info!("Found authorization code in query parameters: {}", code);
                                        match supabase.exchange_code_for_session(code).await {
                                            Ok(session) => {
                                                info!("Successfully exchanged code for session");
                                                window_monitor.lock().set_session(Some(session.clone()));
                                                let _ = login_tx.send(LoginResult::Success(session));
                                                return;
                                            }
                                            Err(e) => {
                                                error!("Failed to exchange code from query: {}", e);
                                            }
                                        }
                                    }

                                    // Try to find code in URL fragment
                                    if let Some(fragment) = parsed_url.fragment() {
                                        info!("Checking URL fragment: {}", fragment);
                                        let fragment_pairs: std::collections::HashMap<_, _> = fragment
                                            .split('&')
                                            .filter_map(|pair| {
                                                let mut parts = pair.split('=');
                                                Some((parts.next()?, parts.next()?))
                                            })
                                            .collect();
                                        
                                        if let Some(code) = fragment_pairs.get("code") {
                                            info!("Found authorization code in URL fragment: {}", code);
                                            match supabase.exchange_code_for_session(code).await {
                                                Ok(session) => {
                                                    info!("Successfully exchanged code for session");
                                                    window_monitor.lock().set_session(Some(session.clone()));
                                                    let _ = login_tx.send(LoginResult::Success(session));
                                                    return;
                                                }
                                                Err(e) => {
                                                    error!("Failed to exchange code from fragment: {}", e);
                                                }
                                            }
                                        }
                                    }

                                    error!("No authorization code found in any location");
                                    error!("Available locations checked:");
                                    error!("- Query parameters: {:?}", query_pairs.keys().collect::<Vec<_>>());
                                    error!("- URL fragment: {:?}", parsed_url.fragment());
                                    error!("- Request body length: {}", content.len());
                                    let _ = login_tx.send(LoginResult::Error("No authorization code found in callback".to_string()));
                                } else {
                                    error!("No callback request received");
                                    let _ = login_tx.send(LoginResult::Error("No callback request received".to_string()));
                                }
                            }
                            Err(e) => {
                                let _ = login_tx.send(LoginResult::Error(format!("Failed to start OAuth: {}", e)));
                            }
                        }
                    } else {
                        let _ = login_tx.send(LoginResult::Error("Failed to find free port".to_string()));
                    }
                } else {
                    let _ = login_tx.send(LoginResult::Error("Supabase client not initialized".to_string()));
                }
            });
        });
    }
}

// Make ChronoSyncApp Send + Sync for async operations
unsafe impl Send for ChronoSyncApp {}
unsafe impl Sync for ChronoSyncApp {}

impl eframe::App for ChronoSyncApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // Try to receive login result
        if let Ok(result) = self.login_rx.try_recv() {
            match result {
                LoginResult::Success(session) => {
                    self.session = Some(session);
                    self.login_email.clear();
                    self.login_password.clear();
                    self.error_message = None;
                }
                LoginResult::Error(error) => {
                    self.error_message = Some(error);
                }
                LoginResult::OAuthStart(url) => {
                    self.error_message = Some(format!("OAuth login started. Please complete the login process in the browser. URL: {}", url));
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("ChronoSync");
            
            if let Some(session) = &self.session {
                ui.label(format!("Logged in as: {}", session.user_id));
                if ui.button("Logout").clicked() {
                    self.handle_logout();
                }
            } else {
                ui.label("Please log in to start tracking");
                
                ui.horizontal(|ui| {
                    ui.label("Email:");
                    ui.text_edit_singleline(&mut self.login_email);
                });
                
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(egui::TextEdit::singleline(&mut self.login_password)
                        .password(true));
                });

                ui.horizontal(|ui| {
                    if ui.button("Login").clicked() {
                        self.handle_login();
                    }
                    if ui.button("Login with Google").clicked() {
                        self.handle_oauth_login(Provider::Google);
                    }
                    if ui.button("Login with Apple").clicked() {
                        self.handle_oauth_login(Provider::Apple);
                    }
                });

                if let Some(error) = &self.error_message {
                    ui.colored_label(egui::Color32::RED, error);
                }
            }

            if let Some(window) = &self.last_window {
                ui.separator();
                ui.label(format!("Current window: {}", window.title));
                ui.label(format!("Package: {}", window.package_name));
            }
        });

        // Request repaint to keep UI responsive
        ctx.request_repaint();
    }
}

fn main() -> Result<()> {
    dotenv().ok();
    env_logger::init();

    // Check if we're being called with a protocol handler URL
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1].starts_with("chronosync://") {
        // Handle the OAuth callback
        if let Ok(session) = ChronoSyncApp::handle_oauth_callback(&args[1]) {
            // Store the session somewhere (e.g., in a file)
            // Then exit - the main app instance will pick up the session
            return Ok(());
        }
    }
    
    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([320.0, 240.0]),
        ..Default::default()
    };

    eframe::run_native(
        "ChronoSync",
        options,
        Box::new(|cc| Box::new(ChronoSyncApp::new(cc))),
    ).map_err(|e| anyhow::anyhow!("Failed to run application: {}", e))?;

    Ok(())
}
