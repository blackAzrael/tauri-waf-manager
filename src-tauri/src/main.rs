// src-tauri/src/main.rs - Tauri 2.8.4版本
use tauri::{State, AppHandle, Manager};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use std::path::PathBuf;
use std::fs;


// WAF配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub rate_limiting: RateLimitConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_port: u16,
    pub backend_host: String,
    pub backend_port: u16,
    pub workers: u8,
    pub enable_ssl: bool,
    pub ssl_cert_path: Option<String>,
    pub ssl_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub blocked_ips: Vec<String>,
    pub blocked_countries: Vec<String>,
    pub whitelist_ips: Vec<String>,
    pub sql_injection_rules: Vec<String>,
    pub xss_rules: Vec<String>,
    pub custom_rules: Vec<CustomRule>,
    pub max_request_size: u64,
    pub enable_geo_blocking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub action: String, // block, allow, log
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub whitelist_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: String,
    pub max_file_size: u64,
    pub enable_access_log: bool,
    pub enable_security_log: bool,
}

// 应用状态管理
#[derive(Debug)]
pub struct AppState {
    pub config: Arc<Mutex<WafConfig>>,
    pub server_status: Arc<Mutex<ServerStatus>>,
    pub log_sender: Arc<Mutex<Option<broadcast::Sender<String>>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerStatus {
    pub running: bool,
    pub start_time: Option<i64>,
    pub requests_processed: u64,
    pub blocked_requests: u64,
    pub uptime_seconds: u64,
}

impl Default for WafConfig {
    fn default() -> Self {
        WafConfig {
            server: ServerConfig {
                listen_port: 6188,
                backend_host: "127.0.0.1".to_string(),
                backend_port: 8080,
                workers: 4,
                enable_ssl: false,
                ssl_cert_path: None,
                ssl_key_path: None,
            },
            security: SecurityConfig {
                blocked_ips: vec![],
                blocked_countries: vec![],
                whitelist_ips: vec!["127.0.0.1".to_string()],
                sql_injection_rules: vec![
                    r"(?i)(union|select|insert|update|delete|drop|exec|script)".to_string(),
                    r"(?i)(\|\||&&|;|'|\*|\+|%|<|>)".to_string(),
                ],
                xss_rules: vec![
                    r"(?i)<script[^>]*>".to_string(),
                    r"(?i)javascript:".to_string(),
                    r"(?i)on\w+\s*=".to_string(),
                ],
                custom_rules: vec![],
                max_request_size: 10_000_000,
                enable_geo_blocking: false,
            },
            rate_limiting: RateLimitConfig {
                enabled: true,
                requests_per_minute: 100,
                burst_size: 10,
                whitelist_ips: vec!["127.0.0.1".to_string()],
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: "waf.log".to_string(),
                max_file_size: 100_000_000,
                enable_access_log: true,
                enable_security_log: true,
            },
        }
    }
}

impl Default for ServerStatus {
    fn default() -> Self {
        ServerStatus {
            running: false,
            start_time: None,
            requests_processed: 0,
            blocked_requests: 0,
            uptime_seconds: 0,
        }
    }
}

// Tauri 2.x 路径处理
fn get_config_path(app_handle: &AppHandle) -> Result<PathBuf, String> {
    let path_resolver = app_handle.path();

    // 尝试获取应用数据目录
    match path_resolver.app_data_dir() {
        Ok(mut path) => {
            // 确保目录存在
            if let Err(e) = fs::create_dir_all(&path) {
                return Err(format!("Failed to create app data directory: {}", e));
            }
            path.push("waf_config.json");
            Ok(path)
        }
        Err(e) => {
            eprintln!("Failed to get app data directory: {}", e);
            // 使用后备路径
            get_fallback_config_path()
        }
    }
}

fn get_fallback_config_path() -> Result<PathBuf, String> {
    let mut path = std::env::current_dir()
        .map_err(|e| format!("Failed to get current directory: {}", e))?;

    path.push("config");
    if let Err(e) = fs::create_dir_all(&path) {
        return Err(format!("Failed to create config directory: {}", e));
    }

    path.push("waf_config.json");
    Ok(path)
}

// Tauri 2.x 命令实现
#[tauri::command]
async fn get_config(state: State<'_, AppState>) -> Result<WafConfig, String> {
    let config = state.config.lock()
        .map_err(|e| format!("Failed to lock config: {}", e))?;
    Ok(config.clone())
}

#[tauri::command]
async fn save_config(
    config: WafConfig,
    state: State<'_, AppState>,
    app_handle: AppHandle
) -> Result<(), String> {
    // 保存到状态
    {
        let mut current_config = state.config.lock()
            .map_err(|e| format!("Failed to lock config: {}", e))?;
        *current_config = config.clone();
    }

    // 持久化到文件
    let config_path = get_config_path(&app_handle)?;
    let config_json = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    fs::write(&config_path, config_json)
        .map_err(|e| format!("Failed to write config to {:?}: {}", config_path, e))?;

    println!("Config saved to: {:?}", config_path);
    Ok(())
}

#[tauri::command]
async fn start_server(state: State<'_, AppState>) -> Result<(), String> {
    println!("WAF Manager start_server successfully ");
    let config = {
        let config_guard = state.config.lock()
            .map_err(|e| format!("Failed to lock config: {}", e))?;
        config_guard.clone()
    };

    // 更新服务器状态
    {
        let mut status = state.server_status.lock()
            .map_err(|e| format!("Failed to lock server status: {}", e))?;
        status.running = true;
        status.start_time = Some(chrono::Utc::now().timestamp());
        status.requests_processed = 0;
        status.blocked_requests = 0;
    }

    // 启动Pingora服务器（异步任务）
    tokio::spawn(async move {
        println!("Starting WAF server on port {}", config.server.listen_port);
        // 在实际实现中，这里会启动Pingora服务器
        // start_pingora_server(config).await;
    });

    Ok(())
}

#[tauri::command]
async fn stop_server(state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut status = state.server_status.lock()
            .map_err(|e| format!("Failed to lock server status: {}", e))?;
        status.running = false;
        status.start_time = None;
    }

    println!("Stopping WAF server");
    Ok(())
}

#[tauri::command]
async fn get_server_status(state: State<'_, AppState>) -> Result<ServerStatus, String> {
    println!("WAF server status: {:?}", state.server_status.lock());
    let status = state.server_status.lock()
        .map_err(|e| format!("Failed to lock server status: {}", e))?;
    Ok(status.clone())
}

#[tauri::command]
async fn add_custom_rule(rule: CustomRule, state: State<'_, AppState>) -> Result<(), String> {
    let mut config = state.config.lock()
        .map_err(|e| format!("Failed to lock config: {}", e))?;
    config.security.custom_rules.push(rule);
    Ok(())
}

#[tauri::command]
async fn remove_custom_rule(rule_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut config = state.config.lock()
        .map_err(|e| format!("Failed to lock config: {}", e))?;
    config.security.custom_rules.retain(|r| r.id != rule_id);
    Ok(())
}

#[tauri::command]
async fn validate_regex(pattern: String) -> Result<bool, String> {
    match regex::Regex::new(&pattern) {
        Ok(_) => Ok(true),
        Err(e) => Err(format!("Invalid regex: {}", e)),
    }
}

#[tauri::command]
async fn get_logs(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let config = state.config.lock()
        .map_err(|e| format!("Failed to lock config: {}", e))?;
    let log_path = &config.logging.file_path;

    match fs::read_to_string(log_path) {
        Ok(content) => {
            let lines: Vec<String> = content
                .lines()
                .rev()
                .take(100)
                .map(|s| s.to_string())
                .collect();
            Ok(lines)
        }
        Err(_) => Ok(vec!["No logs available".to_string()]),
    }
}

#[tauri::command]
async fn test_backend_connection(host: String, port: u16) -> Result<bool, String> {
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    let address = format!("{}:{}", host, port);
    println!("Connecting to {:?}", address);

    match timeout(Duration::from_secs(5), TcpStream::connect(&address)).await {
        Ok(Ok(_)) => {
            println!("Successfully connected to backend: {}", address);
            Ok(true)
        }
        Ok(Err(e)) => Err(format!("Connection failed: {}", e)),
        Err(_) => Err("Connection timeout".to_string()),
    }
}

fn load_config_from_file(app_handle: &AppHandle) -> WafConfig {
    match get_config_path(app_handle) {
        Ok(config_path) => {
            match fs::read_to_string(&config_path) {
                Ok(config_content) => {
                    match serde_json::from_str::<WafConfig>(&config_content) {
                        Ok(config) => {
                            println!("Config loaded from: {:?}", config_path);
                            config
                        }
                        Err(e) => {
                            eprintln!("Failed to parse config file {:?}: {}", config_path, e);
                            WafConfig::default()
                        }
                    }
                }
                Err(_) => {
                    println!("Config file not found, using defaults. Path: {:?}", config_path);
                    WafConfig::default()
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to get config path: {}", e);
            WafConfig::default()
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::init();

    tauri::Builder::default()
        // .plugin(tauri_plugin_shell::init())
        // .plugin(tauri_plugin_fs::init())
        // .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // 获取AppHandle
            let app_handle = app.handle();

            // 加载配置
            let config = load_config_from_file(app_handle);

            // 创建应用状态
            let app_state = AppState {
                config: Arc::new(Mutex::new(config)),
                server_status: Arc::new(Mutex::new(ServerStatus::default())),
                log_sender: Arc::new(Mutex::new(None)),
            };

            app.manage(app_state);

            println!("WAF Manager initialized successfully with 11111 Tauri 2.x");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_config,
            save_config,
            start_server,
            stop_server,
            get_server_status,
            add_custom_rule,
            remove_custom_rule,
            validate_regex,
            get_logs,
            test_backend_connection
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// 主函数（Tauri 2.x样式）
fn main() {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WafConfig::default();
        assert_eq!(config.server.listen_port, 6188);
        assert_eq!(config.server.backend_port, 8080);
        assert!(config.rate_limiting.enabled);
    }

    #[tokio::test]
    async fn test_validate_regex() {
        assert!(validate_regex(r"\d+".to_string()).await.unwrap());
        assert!(validate_regex(r"[invalid".to_string()).await.is_err());
    }

    #[test]
    fn test_fallback_config_path() {
        let result = get_fallback_config_path();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.ends_with("waf_config.json"));
    }
}