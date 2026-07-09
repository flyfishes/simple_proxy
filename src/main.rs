use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::thread;
use std::io;
use std::time::Instant;
use std::sync::Arc;

use log::{info, error, warn, debug};

// 使用同步的 native-tls
#[cfg(feature = "tls")]
use native_tls::{TlsAcceptor, TlsStream, Identity};
#[cfg(feature = "tls")]
use std::fs::File;
#[cfg(feature = "tls")]
use std::io::BufReader;

fn main() -> io::Result<()> {
    // 初始化日志
    // 解析命令行参数
    let (ip, port, log_level) = parse_args();
    init_logging(log_level);
    
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
    let tls_acceptor = load_tls_config().ok();
    
    #[cfg(not(feature = "tls"))]
    let tls_acceptor: Option<Arc<TlsAcceptor>> = None;

    let mut connection_id = 0;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                connection_id += 1;
                let current_id = connection_id;
                let tls_acceptor_clone = tls_acceptor.clone();
                let client_addr = stream.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                
                info!("[连接 #{}] 新客户端连接: {}", current_id, client_addr);
                
                thread::spawn(move || {
                    let start_time = Instant::now();
                    let result = handle_connection(stream, current_id, client_addr, tls_acceptor_clone);
                    let duration = start_time.elapsed();
                    
                    match result {
                        Ok(_) => {
                            debug!("[连接 #{}] 客户端 {} 处理完成，耗时: {:?}", 
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
                error!("接受连接失败: {}", e);
            }
        }
    }
    Ok(())
}

// 初始化日志系统
fn init_logging(level: log::LevelFilter) {
    #[cfg(feature = "logging")]
    {
        use env_logger::Builder;
        let log_file = std::fs::File::create("simple_proxy.log").expect("无法创建日志文件");
        Builder::new()
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .filter(None, level)
            .init();
        info!("日志文件: simple_proxy.log");
    }
    
    #[cfg(not(feature = "logging"))]
    {
        println!("日志功能未启用，请使用 --features logging 编译");
    }
}

// 解析命令行参数
// 解析命令行参数，增加日志级别返回值
fn parse_args() -> (String, u16, log::LevelFilter) {
    let args: Vec<String> = env::args().collect();
    let mut ip = "127.0.0.1".to_string();
    let mut port = 8080;
    let mut log_level = log::LevelFilter::Info; // 默认是 Info 模式
    
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
            // 🌟 新增：检测 --debug 或 -d 参数
            "--debug" | "-d" => {
                log_level = log::LevelFilter::Debug;
                i += 1;
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
    
    (ip, port, log_level)
}

// 处理连接 - 协议检测
fn handle_connection(
    stream: TcpStream,
    connection_id: usize,
    client_addr: SocketAddr,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> io::Result<()> {
    let mut peek_buf = [0; 1];
    match stream.peek(&mut peek_buf) {
        Ok(0) => {
            warn!("[连接 #{}] 客户端 {} 连接已关闭", connection_id, client_addr);
            Ok(())
        }
        Ok(_) => {
            #[cfg(feature = "tls")]
            {
                if peek_buf[0] == 0x16 && tls_acceptor.is_some() {
                    debug!("[连接 #{}] 检测到 TLS 连接 (HTTPS 代理)", connection_id);
                    return handle_tls_proxy(stream, connection_id, client_addr, tls_acceptor.unwrap());
                }
            }
            debug!("[连接 #{}] 检测到明文连接 (HTTP 代理)", connection_id);
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

    debug!("[连接 #{}] {} {} {} {}", connection_id, client_addr, method, url, version);

    if method == "CONNECT" {
        debug!("[连接 #{}] 处理 HTTPS CONNECT 请求: {}", connection_id, url);
        return handle_connect(stream, url, connection_id, client_addr);
    }

    handle_http_request(stream, method, url, version, &buffer[..bytes_read], connection_id)
}

// ==================== TLS 代理处理（HTTPS 代理）- 同步版本 ====================

#[cfg(feature = "tls")]
fn handle_tls_proxy(
    stream: TcpStream,
    connection_id: usize,
    client_addr: SocketAddr,
    acceptor: Arc<TlsAcceptor>,
) -> io::Result<()> {
    debug!("[连接 #{}] 开始 TLS 握手", connection_id);
    
    let tls_stream = match acceptor.accept(stream) {
        Ok(s) => {
            debug!("[连接 #{}] TLS 握手成功", connection_id);
            s
        }
        Err(e) => {
            error!("[连接 #{}] TLS 握手失败: {}", connection_id, e);
            return Err(io::Error::new(io::ErrorKind::Other, e));
        }
    };
    
    handle_tls_http_proxy(tls_stream, connection_id, client_addr)
}

#[cfg(not(feature = "tls"))]
fn handle_tls_proxy(
    _stream: TcpStream,
    connection_id: usize,
    _client_addr: SocketAddr,
    _acceptor: Arc<TlsAcceptor>,
) -> io::Result<()> {
    error!("[连接 #{}] TLS 支持未编译，请启用 'tls' feature", connection_id);
    Err(io::Error::new(io::ErrorKind::Unsupported, "TLS not enabled"))
}

// ==================== TLS HTTP 代理处理 ====================
// ==================== TLS HTTP 代理处理（全面修复版） ====================

#[cfg(feature = "tls")]
fn handle_tls_http_proxy(
    mut stream: TlsStream<TcpStream>,
    connection_id: usize,
    client_addr: SocketAddr,
) -> io::Result<()> {
    let mut buffer = [0; 8192];
    let bytes_read = stream.read(&mut buffer)?;
    
    if bytes_read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let mut lines = request.lines();
    
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    
    if parts.len() < 3 {
        warn!("[连接 #{}] 请求格式错误: {}", connection_id, first_line);
        return Ok(());
    }

    let method = parts[0];
    let original_url = parts[1];
    let version = parts[2];

    // 1. 提取真实的 Host 请求头（无论如何都以此为高优先级准则）
    let mut host_header = None;
    for line in lines {
        if line.is_empty() { break; } // 请求头结束
        if line.to_lowercase().starts_with("host:") {
            if let Some(h) = line.split(':').nth(1) {
                host_header = Some(h.trim().to_string());
            }
            break;
        }
    }

    // 2. 智能重构真实的 URL
    let mut url = original_url.to_string();
    if let Some(host) = host_header {
        if original_url.starts_with('/') {
            // 情况 A: 标准相对路径，如 /index.html
            url = format!("https://{}{}", host, original_url);
        } else if original_url.starts_with("http://") || original_url.starts_with("https://") {
            // 情况 B: 畸形绝对路径（如 https://127.0.0.1/），强制将其 host 部分清洗替换为真实的 Host 头
            let remainder = if original_url.starts_with("https://") {
                &original_url[8..]
            } else {
                &original_url[7..]
            };
            // 剥离出路径部分（如 / ）
            let path_part = if let Some(slash_pos) = remainder.find('/') {
                &remainder[slash_pos..]
            } else {
                "/"
            };
            // 强制用真实的 Host 头重组 URL
            url = format!("https://{}{}", host, path_part);
        }
    } else if original_url.starts_with('/') {
        // 兜底：既是相对路径又没给 Host 头
        warn!("[连接 #{}] TLS 请求未找到 Host 头部，且为相对路径", connection_id);
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        let _ = stream.write(response.as_bytes());
        return Ok(());
    }

    // 此时打印出来的 url 将会是正确的 https://www.abcd.com/
    info!("[连接 #{}] from {} {} {} {}", connection_id, client_addr, method, url, version);

    if method == "CONNECT" {
        warn!("[连接 #{}] CONNECT 方法在 TLS 代理中不常见", connection_id);
        return Ok(());
    }

    // 转发请求
    handle_tls_http_request(stream, method, &url, version, &buffer[..bytes_read], connection_id)
}

// ==================== TLS HTTP 请求处理 ====================

#[cfg(feature = "tls")]
fn handle_tls_http_request(
    mut client_stream: TlsStream<TcpStream>,
    method: &str,
    url: &str,
    version: &str,
    request_data: &[u8],
    connection_id: usize,
) -> io::Result<()> {
    let (host, port, path) = parse_url(url);
    debug!("[连接 #{}] 解析目标tls: {}:{}{}", connection_id, host, port, path);

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
            debug!("[连接 #{}] 成功连接到 {}:{}", connection_id, host, port);
            stream
        }
        Err(e) => {
            error!("[连接 #{}] 连接目标 {} 失败: {}", connection_id, target_addr, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            let _ = client_stream.write(response.as_bytes());
            return Ok(());
        }
    };

    target_stream.write_all(request_line.as_bytes())?;
    for header in &headers {
        target_stream.write_all(header.as_bytes())?;
        target_stream.write_all(b"\r\n")?;
    }
    target_stream.write_all(b"\r\n")?;

    if let Some(body_start) = request_str.find("\r\n\r\n") {
        let body = &request_data[body_start + 4..];
        if !body.is_empty() {
            target_stream.write_all(body)?;
        }
    }

    let mut buffer = [0; 8192];
    let mut total_bytes = 0;
    
    loop {
        match target_stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                total_bytes += n;
                client_stream.write_all(&buffer[..n])?;
            }
            Err(e) => {
                error!("[连接 #{}] 从目标读取响应错误: {}", connection_id, e);
                break;
            }
        }
    }

    debug!("[连接 #{}] 响应转发完成 ({} 字节)", connection_id, total_bytes);
    Ok(())
}

// ==================== TLS 配置加载 ====================

#[cfg(feature = "tls")]
fn load_tls_config() -> Result<Arc<TlsAcceptor>, Box<dyn std::error::Error>> {
    let cert_path = env::var("PROXY_CERT").unwrap_or_else(|_| "cert.pem".to_string());
    let key_path = env::var("PROXY_KEY").unwrap_or_else(|_| "key.pem".to_string());
    
    info!("加载证书: {}, 私钥: {}", cert_path, key_path);
    
    // 直接将文件读取为 Vec<u8> 字节数组
    let cert_data = std::fs::read(cert_path)?;
    let key_data = std::fs::read(key_path)?;
    
    // 传入 &[u8] 类型的切片
    let identity = Identity::from_pkcs8(&cert_data, &key_data)?;
    
    let acceptor = TlsAcceptor::new(identity)?;
    Ok(Arc::new(acceptor))
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
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        let _ = client_stream.write(response.as_bytes());
        return Ok(());
    }

    let host = addr_parts[0];
    // 修复点 1: 安全解析端口，防止非法格式输入导致 unwrap() Panic
    let port: u16 = addr_parts[1].parse().unwrap_or(443); 
    let target_addr = format!("{}:{}", host, port);

    info!("[连接 #{}] 连接到目标服务器: {}", connection_id, target_addr);

    let mut target_stream = match TcpStream::connect(&target_addr) {
        Ok(stream) => {
            debug!("[连接 #{}] 成功连接到目标服务器: {}", connection_id, target_addr);
            stream
        }
        Err(e) => {
            error!("[连接 #{}] 连接目标服务器失败 {}: {}", connection_id, target_addr, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            let _ = client_stream.write(response.as_bytes());
            return Ok(());
        }
    };

    client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    debug!("[连接 #{}] 隧道已建立 ({} -> {})", connection_id, client_addr, target_addr);

    // 深度修复点 2: 解决双向转发下的线程死锁与半关闭泄露问题
    let mut client_clone = client_stream.try_clone()?;
    let mut target_clone = target_stream.try_clone()?;
    
    // 克隆一个引用专用于在一个线程退出后跨线程激活另一个阻塞的 Socket
    let client_shutdown_trigger = client_stream.try_clone()?;

    let handle1 = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0; 8192];
        loop {
            match client_clone.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if target_clone.write_all(&buffer[..n]).is_err() { break; }
                }
                Err(_) => break,
            }
        }
        // 客户端读断开时，立即通知对端触发另一侧 read 退出，防止死锁
        let _ = client_shutdown_trigger.shutdown(std::net::Shutdown::Both);
        Ok(())
    });

    let mut buffer = [0; 8192];
    loop {
        match target_stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if client_stream.write_all(&buffer[..n]).is_err() { break; }
            }
            Err(_) => break,
        }
    }

    // 彻底释放并回收双向的系统底层 Socket 描述符资源
    let _ = client_stream.shutdown(std::net::Shutdown::Both);
    let _ = handle1.join();

    debug!("[连接 #{}] 隧道已关闭", connection_id);
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
) -> io::Result<()> {
    let (host, port, path) = parse_url(url);
    debug!("[连接 #{}] 解析目标HTTP: {}:{}{}", connection_id, host, port, path);

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
            debug!("[连接 #{}] 成功连接到 {}:{}", connection_id, host, port);
            stream
        }
        Err(e) => {
            error!("[连接 #{}] 连接目标 {} 失败: {}", connection_id, target_addr, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            let _ = client_stream.write(response.as_bytes());
            return Ok(());
        }
    };

    target_stream.write_all(request_line.as_bytes())?;
    for header in &headers {
        target_stream.write_all(header.as_bytes())?;
        target_stream.write_all(b"\r\n")?;
    }
    target_stream.write_all(b"\r\n")?;

    if let Some(body_start) = request_str.find("\r\n\r\n") {
        let body = &request_data[body_start + 4..];
        if !body.is_empty() {
            target_stream.write_all(body)?;
        }
    }

    let mut buffer = [0; 8192];
    let mut total_bytes = 0;
    
    loop {
        match target_stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                total_bytes += n;
                client_stream.write_all(&buffer[..n])?;
            }
            Err(e) => {
                error!("[连接 #{}] 从目标读取响应错误: {}", connection_id, e);
                break;
            }
        }
    }

    debug!("[连接 #{}] 响应转发完成 ({} 字节)", connection_id, total_bytes);
    Ok(())
}

// ==================== URL 解析（修复版 - 支持 https://） ====================

fn parse_url(url: &str) -> (String, u16, String) {
    let mut remaining = url;
    let mut is_https = false;

    // 1. 剥离并识别协议头
    if remaining.starts_with("http://") {
        remaining = &remaining[7..];
    } else if remaining.starts_with("https://") {
        remaining = &remaining[8..];
        is_https = true;
    }

    // 2. 剥离并识别路径 (Path)
    let (host_port_part, path_part) = if let Some(path_pos) = remaining.find('/') {
        (&remaining[..path_pos], &remaining[path_pos..])
    } else {
        (remaining, "/")
    };

    // 3. 处理纯相对路径的特殊情况 (例如直接输入了 "/index.html")
    if host_port_part.is_empty() && path_part.starts_with('/') {
        warn!("解析目标url: {}. host_port_part is_empty, path_part: {}", url, path_part);
        return ("localhost".to_string(), 80, path_part.to_string());
    }

    // 4. 剥离并识别 Host 与 Port
    let mut host = host_port_part.to_string();
    
    // 默认端口策略：根据协议决定默认端口
    let mut port = if is_https { 443 } else { 80 };

    // 检查 host_port_part 中是否包含端口号冒号
    // 注意：如果是中括号包裹的 IPv6 地址 (如 [::1]:8080)，最右边的冒号才是端口分隔符
    if let Some(colon_pos) = host_port_part.rfind(':') {
        // 排除 IPv6 地址中没有端口的内部冒号情况 (例如 [::1])
        if !host_port_part.ends_with(']') {
            let port_str = &host_port_part[colon_pos + 1..];
            if let Ok(p) = port_str.parse::<u16>() {
                port = p;
                host = host_port_part[..colon_pos].to_string();
            }
        }
    }

    // 去除 IPv6 地址的外层中括号 (如 [::1] -> ::1)
    if host.starts_with('[') && host.ends_with(']') {
        host = host[1..host.len() - 1].to_string();
    }

    // 如果 host 最终为空，兜底为 localhost
    if host.is_empty() {
        host = "localhost".to_string();
    }

    info!("解析目标url: {} {}:{} {}", url, host, port, path_part.to_string());
    (host, port, path_part.to_string())
}
