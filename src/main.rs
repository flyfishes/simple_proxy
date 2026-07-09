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
    
    // 🌟 【调试关键点】强制打印解密后的原始报文，检查 Host 到底长什么样
    debug!("[连接 #{}] TLS 解密后的原始请求报文:\n---BEGIN---\n{}\n---END---", connection_id, request);

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

    // 🌟 加固的 Host 提取逻辑：重新获取 lines 迭代器，避免迭代器状态冲突
    let mut host_header = None;
    for line in request.lines().skip(1) {
        if line.is_empty() { break; } // 请求头结束
        
        let trimmed_line = line.trim();
        if trimmed_line.to_lowercase().starts_with("host:") {
            // 切割 "Host:" 或 "host:" 之后的部分
            if let Some(h) = trimmed_line.get(5..) {
                host_header = Some(h.trim().to_string());
            }
            break;
        }
    }

    // 智能重构 URL
    let mut url = original_url.to_string();
    if let Some(ref host) = host_header {
        if original_url.starts_with('/') {
            // 情况 A: 标准相对路径 /index.html
            url = format!("https://{}{}", host, original_url);
        } else if original_url.starts_with("http://") || original_url.starts_with("https://") {
            // 情况 B: 针对 curl 发送的带错误代理IP的绝对路径 (https://127.0.0.1/)
            // 提取域名后面的路径部分
            let remainder = if original_url.starts_with("https://") {
                &original_url[8..]
            } else {
                &original_url[7..]
            };
            
            let path_part = if let Some(slash_pos) = remainder.find('/') {
                &remainder[slash_pos..]
            } else {
                "/"
            };
            // 强制将 Host 替换为请求头里的真实目标域名
            url = format!("https://{}{}", host, path_part);
        }
    } else {
        // 如果实在是找不到 Host 请求头，但 original_url 里面包含了非 127.0.0.1 的域名，交由原本的 url 处理
        // 如果 original_url 是 127.0.0.1 且没有 Host 头，才报 400
        if original_url.starts_with('/') || original_url.contains("127.0.0.1") {
            warn!("[连接 #{}] TLS 请求中未找到有效的 Host 头部，且无法推导目标", connection_id);
            let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            let _ = stream.write(response.as_bytes());
            return Ok(());
        }
    }

    info!("[连接 #{}] {} {} {} {}", connection_id, client_addr, method, url, version);

    if method == "CONNECT" {
        warn!("[连接 #{}] CONNECT 方法在 TLS 代理中不常见", connection_id);
        return Ok(());
    }

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
// ==================== CONNECT 方法处理（精确半关闭解耦版） ====================

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
    let port: u16 = addr_parts[1].parse().unwrap_or(443); 
    let target_addr = format!("{}:{}", host, port);

    debug!("[连接 #{}] 正在尝试建立 TCP 远端连接: {}", connection_id, target_addr);

    let mut target_stream = match TcpStream::connect(&target_addr) {
        Ok(stream) => {
            debug!("[连接 #{}] 成功连接到目标远端服务器: {}", connection_id, target_addr);
            stream
        }
        Err(e) => {
            error!("[连接 #{}] 连接目标服务器失败 {}: {}", connection_id, target_addr, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            let _ = client_stream.write(response.as_bytes());
            return Ok(());
        }
    };

    // 告诉客户端，代理隧道已经打通，可以开始传输加密的 TLS 数据流了
    client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    client_stream.flush()?;
    debug!("[连接 #{}] 200 响应已回传，隧道正式建立 ({} <-> {})", connection_id, client_addr, target_addr);

    // 克隆 Socket 句柄用于双工多线程
    let mut client_read = client_stream.try_clone()?;
    let mut target_write = target_stream.try_clone()?;
    
    let mut target_read = target_stream.try_clone()?;
    let mut client_write = client_stream.try_clone()?;

    // 【方向 A】：客户端 -> 目标服务器
    let handle_upstream = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0; 8192];
        loop {
            match client_read.read(&mut buffer) {
                Ok(0) => break, // 客户端停止发送数据
                Ok(n) => {
                    if target_write.write_all(&buffer[..n]).is_err() { break; }
                    let _ = target_write.flush();
                }
                Err(_) => break,
            }
        }
        // ⭐ 精确半关闭：仅仅告诉远端服务器“客户端不会再写数据了”
        let _ = target_write.shutdown(std::net::Shutdown::Write);
        Ok(())
    });

    // 【方向 B】：目标服务器 -> 客户端
    let handle_downstream = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0; 8192];
        loop {
            match target_read.read(&mut buffer) {
                Ok(0) => break, // 远端服务器响应结束
                Ok(n) => {
                    if client_write.write_all(&buffer[..n]).is_err() { break; }
                    let _ = client_write.flush();
                }
                Err(_) => break,
            }
        }
        // ⭐ 精确半关闭：仅仅告诉客户端“远端响应已经全部发完”，给 Schannel 留出发送 close_notify 的时间
        let _ = client_write.shutdown(std::net::Shutdown::Write);
        Ok(())
    });

    // 等待双向传输线程平稳安全结束
    let _ = handle_upstream.join();
    let _ = handle_downstream.join();

    debug!("[连接 #{}] 隧道双向数据流传输安全结束，关闭连接", connection_id);
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
