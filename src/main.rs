use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::thread;
use std::io;
use std::time::Instant;
use std::sync::Arc;

use log::{info, error, warn, debug};

// 条件编译 TLS 支持
#[cfg(feature = "tls")]
use rustls::{ServerConfig, Certificate, PrivateKey};
#[cfg(feature = "tls")]
use rustls_pemfile::{certs, pkcs8_private_keys};
#[cfg(feature = "tls")]
use std::fs::File;
#[cfg(feature = "tls")]
use std::io::BufReader;

fn main() -> io::Result<()> {
    // 初始化日志
    init_logging();

    // 解析命令行参数
    let (ip, port) = parse_args();
    let bind_addr = format!("{}:{}", ip, port);
    
    let listener = TcpListener::bind(&bind_addr)?;
    
    info!("代理服务器运行在 {}", bind_addr);
    info!("同时支持 HTTP 和 HTTPS 代理协议");
    info!("使用方法:");
    info!("  HTTP代理:  curl --proxy http://{}:{} https://example.com", ip, port);
    info!("  HTTPS代理: curl --proxy https://{}:{} https://example.com -k", ip, port);
    info!("按 Ctrl+C 停止服务器");

    // 加载 TLS 配置（如果启用）
    #[cfg(feature = "tls")]
    let tls_config = load_tls_config().ok();
    
    #[cfg(not(feature = "tls"))]
    let tls_config: Option<Arc<ServerConfig>> = None;

    let mut connection_id = 0;
    for stream in listener.incoming() {
        connection_id += 1;
        let current_id = connection_id;
        let tls_config_clone = tls_config.clone();
        
        match stream {
            Ok(stream) => {
                let client_addr = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());
                info!("[连接 #{}] 新客户端连接: {}", current_id, client_addr);
                
                thread::spawn(move || {
                    let start_time = Instant::now();
                    let result = handle_connection(stream, current_id, client_addr, tls_config_clone);
                    let duration = start_time.elapsed();
                    
                    match result {
                        Ok(_) => {
                            info!("[连接 #{}] 客户端 {} 处理完成，耗时: {:?}", 
                                  current_id, client_addr, duration);
                        }
                        Err(e) => {
                            error!("[连接 #{}] 客户端 {} 处理错误: {}, 耗时: {:?}", 
                                   current_id, client_addr, e, duration);
                        }
                    }
                });
            }
            Err(e) => {
                error!("[连接 #{}] 接受连接失败: {}", current_id, e);
            }
        }
    }
    Ok(())
}

// 初始化日志系统
fn init_logging() {
    #[cfg(feature = "logging")]
    {
        use env_logger::Builder;
        let log_file = std::fs::File::create("proxy.log").expect("无法创建日志文件");
        Builder::new()
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .filter(None, log::LevelFilter::Info)
            .init();
        info!("日志文件: proxy.log");
    }
    
    #[cfg(not(feature = "logging"))]
    {
        // 不启用日志功能时，使用简单输出
        println!("日志功能未启用，请使用 --features logging 编译");
    }
}

// 解析命令行参数
fn parse_args() -> (String, u16) {
    let args: Vec<String> = env::args().collect();
    let mut ip = "127.0.0.1".to_string();
    let mut port = 8080;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ip" | "-i" if i + 1 < args.len() => {
                ip = args[i + 1].clone();
                i += 2;
            }
            "--port" | "-p" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse::<u16>() {
                    port = p;
                } else {
                    eprintln!("警告: 无效的端口号 {}，使用默认端口 8080", args[i + 1]);
                }
                i += 2;
            }
            arg => {
                if let Ok(p) = arg.parse::<u16>() {
                    port = p;
                    i += 1;
                } else {
                    eprintln!("警告: 未知参数 {}，使用默认配置", arg);
                    i += 1;
                }
            }
        }
    }
    
    if ip.parse::<std::net::IpAddr>().is_err() {
        eprintln!("警告: 无效的 IP 地址 {}，使用 127.0.0.1", ip);
        ip = "127.0.0.1".to_string();
    }
    
    info!("监听地址: {}:{}", ip, port);
    (ip, port)
}

// 处理连接 - 协议检测
fn handle_connection(
    mut stream: TcpStream,
    connection_id: usize,
    client_addr: SocketAddr,
    tls_config: Option<Arc<ServerConfig>>,
) -> io::Result<()> {
    let mut peek_buf = [0; 1];
    match stream.peek(&mut peek_buf) {
        Ok(0) => {
            warn!("[连接 #{}] 客户端 {} 连接已关闭", connection_id, client_addr);
            return Ok(());
        }
        Ok(_) => {
            #[cfg(feature = "tls")]
            {
                if peek_buf[0] == 0x16 && tls_config.is_some() {
                    info!("[连接 #{}] 检测到 TLS 连接 (HTTPS 代理)", connection_id);
                    return handle_tls_proxy(stream, connection_id, client_addr, tls_config.unwrap());
                }
            }
            info!("[连接 #{}] 检测到明文连接 (HTTP 代理)", connection_id);
            handle_http_proxy(stream, connection_id, client_addr)
        }
        Err(e) => {
            error!("[连接 #{}] 无法检测协议: {}", connection_id, e);
            Err(e)
        }
    }
}

// ==================== HTTP 代理处理（明文） ====================

fn handle_http_proxy(
    mut stream: TcpStream,
    connection_id: usize,
    client_addr: SocketAddr,
) -> io::Result<()> {
    let mut buffer = [0; 8192];
    let bytes_read = stream.read(&mut buffer)?;
    
    if bytes_read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    
    if parts.len() < 3 {
        warn!("[连接 #{}] 请求格式错误: {}", connection_id, first_line);
        return Ok(());
    }

    let method = parts[0];
    let url = parts[1];
    let version = parts[2];

    info!("[连接 #{}] {} {} {} {}", connection_id, client_addr, method, url, version);

    if method == "CONNECT" {
        info!("[连接 #{}] 处理 HTTPS CONNECT 请求: {}", connection_id, url);
        return handle_connect(stream, url, connection_id, client_addr);
    }

    handle_http_request(stream, method, url, version, &buffer[..bytes_read], connection_id, client_addr)
}

// ==================== TLS 代理处理（HTTPS 代理） ====================

#[cfg(feature = "tls")]
fn handle_tls_proxy(
    stream: TcpStream,
    connection_id: usize,
    client_addr: SocketAddr,
    config: Arc<ServerConfig>,
) -> io::Result<()> {
    use tokio::runtime::Runtime;
    use tokio_rustls::TlsAcceptor;
    
    info!("[连接 #{}] 开始 TLS 握手", connection_id);
    
    let rt = Runtime::new().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    rt.block_on(async {
        let acceptor = TlsAcceptor::from(config);
        let stream = tokio::net::TcpStream::from_std(stream)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        let tls_stream = match acceptor.accept(stream).await {
            Ok(s) => {
                info!("[连接 #{}] TLS 握手成功", connection_id);
                s
            }
            Err(e) => {
                error!("[连接 #{}] TLS 握手失败: {}", connection_id, e);
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };
        
        // 修复1: 使用 into_inner() 代替 into_std()
        let io_stream = tls_stream.into_inner();
        let std_stream = io_stream.into_std().await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        handle_http_proxy(std_stream, connection_id, client_addr)
    })
}

#[cfg(not(feature = "tls"))]
fn handle_tls_proxy(
    _stream: TcpStream,
    connection_id: usize,
    _client_addr: SocketAddr,
    _config: Arc<ServerConfig>,
) -> io::Result<()> {
    error!("[连接 #{}] TLS 支持未编译，请启用 'tls' feature", connection_id);
    Err(io::Error::new(io::ErrorKind::Unsupported, "TLS not enabled"))
}

// ==================== TLS 配置加载 ====================

#[cfg(feature = "tls")]
fn load_tls_config() -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let cert_path = env::var("PROXY_CERT").unwrap_or_else(|_| "cert.pem".to_string());
    let key_path = env::var("PROXY_KEY").unwrap_or_else(|_| "key.pem".to_string());
    
    info!("加载证书: {}, 私钥: {}", cert_path, key_path);
    
    let certs = load_certs(&cert_path)?;
    let key = load_private_key(&key_path)?;
    
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    
    Ok(Arc::new(config))
}

#[cfg(feature = "tls")]
fn load_certs(path: &str) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    // 修复2: 使用 ? 操作符需要正确的错误类型
    let cert_reader = certs(&mut reader)?;
    Ok(cert_reader.into_iter().map(Certificate).collect())
}

#[cfg(feature = "tls")]
fn load_private_key(path: &str) -> Result<PrivateKey, Box<dyn std::error::Error>> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    // 修复3: 使用 ? 操作符需要正确的错误类型
    let mut keys = pkcs8_private_keys(&mut reader)?;
    if keys.is_empty() {
        return Err("没有找到私钥".into());
    }
    Ok(PrivateKey(keys.remove(0)))
}

// ==================== CONNECT 方法处理（HTTPS 隧道） ====================

fn handle_connect(
    mut client_stream: TcpStream,
    url: &str,
    connection_id: usize,
    client_addr: SocketAddr,
) -> io::Result<()> {
    let addr_parts: Vec<&str> = url.split(':').collect();
    if addr_parts.len() != 2 {
        error!("[连接 #{}] 无效的 CONNECT 地址: {}", connection_id, url);
        return Ok(());
    }

    let host = addr_parts[0];
    let port: u16 = addr_parts[1].parse().unwrap_or(443);
    let target_addr = format!("{}:{}", host, port);

    info!("[连接 #{}] 连接到目标服务器: {}", connection_id, target_addr);

    let mut target_stream = match TcpStream::connect(&target_addr) {
        Ok(stream) => {
            info!("[连接 #{}] 成功连接到目标服务器: {}", connection_id, target_addr);
            stream
        }
        Err(e) => {
            error!("[连接 #{}] 连接目标服务器失败 {}: {}", connection_id, target_addr, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client_stream.write(response.as_bytes())?;
            return Ok(());
        }
    };

    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    client_stream.write(response.as_bytes())?;
    info!("[连接 #{}] 隧道已建立 ({} -> {})", connection_id, client_addr, target_addr);

    let mut client_clone = client_stream.try_clone()?;
    let mut target_clone = target_stream.try_clone()?;
    
    let handle1 = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0; 8192];
        let mut total_bytes = 0;
        loop {
            match client_clone.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    total_bytes += n;
                    if let Err(e) = target_clone.write_all(&buffer[..n]) {
                        debug!("[连接 #{}] 向目标写入数据失败: {}", connection_id, e);
                        break;
                    }
                }
                Err(e) => {
                    debug!("[连接 #{}] 从客户端读取数据失败: {}", connection_id, e);
                    break;
                }
            }
        }
        info!("[连接 #{}] 客户端 -> 目标 总流量: {} 字节", connection_id, total_bytes);
        Ok(())
    });

    let handle2 = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0; 8192];
        let mut total_bytes = 0;
        loop {
            match target_stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    total_bytes += n;
                    if let Err(e) = client_stream.write_all(&buffer[..n]) {
                        debug!("[连接 #{}] 向客户端写入数据失败: {}", connection_id, e);
                        break;
                    }
                }
                Err(e) => {
                    debug!("[连接 #{}] 从目标读取数据失败: {}", connection_id, e);
                    break;
                }
            }
        }
        info!("[连接 #{}] 目标 -> 客户端 总流量: {} 字节", connection_id, total_bytes);
        Ok(())
    });

    let _ = handle1.join();
    let _ = handle2.join();

    info!("[连接 #{}] 隧道已关闭", connection_id);
    Ok(())
}

// ==================== 标准 HTTP 请求处理 ====================

fn handle_http_request(
    mut client_stream: TcpStream,
    method: &str,
    url: &str,
    version: &str,
    request_data: &[u8],
    connection_id: usize,
    client_addr: SocketAddr,
) -> io::Result<()> {
    let (host, port, path) = parse_url(url);
    info!("[连接 #{}] 解析目标: {}:{}{}", connection_id, host, port, path);

    let request_line = format!("{} {} {}\r\n", method, path, version);
    
    let request_str = String::from_utf8_lossy(request_data);
    let headers: Vec<&str> = request_str
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter(|line| !line.to_lowercase().starts_with("proxy-"))
        .collect();

    let target_addr = format!("{}:{}", host, port);
    let mut target_stream = match TcpStream::connect(&target_addr) {
        Ok(stream) => {
            info!("[连接 #{}] 成功连接到 {}:{}", connection_id, host, port);
            stream
        }
        Err(e) => {
            error!("[连接 #{}] 连接目标 {} 失败: {}", connection_id, target_addr, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client_stream.write(response.as_bytes())?;
            return Ok(());
        }
    };

    target_stream.write(request_line.as_bytes())?;
    for header in &headers {
        target_stream.write(header.as_bytes())?;
        target_stream.write(b"\r\n")?;
    }
    target_stream.write(b"\r\n")?;

    if let Some(body_start) = request_str.find("\r\n\r\n") {
        let body = &request_data[body_start + 4..];
        if !body.is_empty() {
            debug!("[连接 #{}] 转发请求体: {} 字节", connection_id, body.len());
            target_stream.write(body)?;
        }
    }

    info!("[连接 #{}] 请求转发完成 (Headers: {})", connection_id, headers.len());

    // 修复4: 使用独立的 buffer 来避免借用冲突
    let mut response_buffer = [0; 8192];
    let mut total_bytes = 0;
    let mut response_status = "unknown";
    
    loop {
        match target_stream.read(&mut response_buffer) {
            Ok(0) => break,
            Ok(n) => {
                if total_bytes == 0 {
                    if let Ok(response_str) = std::str::from_utf8(&response_buffer[..n]) {
                        if let Some(status_line) = response_str.lines().next() {
                            response_status = status_line;
                            info!("[连接 #{}] 响应状态: {}", connection_id, status_line);
                        }
                    }
                }
                total_bytes += n;
                client_stream.write_all(&response_buffer[..n])?;
            }
            Err(e) => {
                error!("[连接 #{}] 从目标读取响应错误: {}", connection_id, e);
                break;
            }
        }
    }

    info!("[连接 #{}] 响应转发完成 ({} 字节, {})", 
          connection_id, total_bytes, response_status);
    Ok(())
}

// ==================== URL 解析 ====================

fn parse_url(url: &str) -> (String, u16, String) {
    if url.starts_with("http://") {
        let url_without_protocol = &url[7..];
        if let Some(path_pos) = url_without_protocol.find('/') {
            let host_part = &url_without_protocol[..path_pos];
            let path = &url_without_protocol[path_pos..];
            
            if let Some(port_pos) = host_part.find(':') {
                let host = host_part[..port_pos].to_string();
                let port: u16 = host_part[port_pos + 1..].parse().unwrap_or(80);
                return (host, port, path.to_string());
            } else {
                return (host_part.to_string(), 80, path.to_string());
            }
        } else {
            return (url_without_protocol.to_string(), 80, "/".to_string());
        }
    }
    
    if url.starts_with('/') {
        return ("localhost".to_string(), 80, url.to_string());
    }
    
    if let Some(path_pos) = url.find('/') {
        let host_part = &url[..path_pos];
        let path = &url[path_pos..];
        
        if let Some(port_pos) = host_part.find(':') {
            let host = host_part[..port_pos].to_string();
            let port: u16 = host_part[port_pos + 1..].parse().unwrap_or(80);
            return (host, port, path.to_string());
        } else {
            return (host_part.to_string(), 80, path.to_string());
        }
    }
    
    if let Some(port_pos) = url.find(':') {
        let host = url[..port_pos].to_string();
        let port: u16 = url[port_pos + 1..].parse().unwrap_or(80);
        return (host, port, "/".to_string());
    }
    
    (url.to_string(), 80, "/".to_string())
}