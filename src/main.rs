use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use log::{debug, error, info, warn};

// 条件编译 TLS 支持
#[cfg(feature = "tls")]
use pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(feature = "tls")]
use rustls_pemfile::{certs, pkcs8_private_keys};
#[cfg(feature = "tls")]
use std::fs::File;
#[cfg(feature = "tls")]
use std::io::BufReader;
#[cfg(feature = "tls")]
use tokio_rustls::rustls::ServerConfig;

#[tokio::main]
async fn main() -> io::Result<()> {
    // 初始化日志
    init_logging();

    // 解析命令行参数
    let (ip, port) = parse_args();
    let bind_addr = format!("{}:{}", ip, port);

    let listener = TcpListener::bind(&bind_addr).await?;

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
    let tls_config: Option<Arc<()>> = None;

    let mut connection_id = 0;
    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                connection_id += 1;
                let current_id = connection_id;
                let tls_config_clone = tls_config.clone();

                info!("[连接 #{}] 新客户端连接: {}", current_id, client_addr);

                // 异步派生任务处理连接
                tokio::spawn(async move {
                    let start_time = Instant::now();
                    let result = handle_connection(stream, current_id, client_addr, tls_config_clone).await;
                    let duration = start_time.elapsed();

                    match result {
                        Ok(_) => {
                            info!("[连接 #{}] 客户端 {} 处理完成，耗时: {:?}", current_id, client_addr, duration);
                        }
                        Err(e) => {
                            error!("[连接 #{}] 客户端 {} 处理错误: {}, 耗时: {:?}", current_id, client_addr, e, duration);
                        }
                    }
                });
            }
            Err(e) => {
                error!("接受连接失败: {}", e);
            }
        }
    }
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

    (ip, port)
}

// 处理连接 - 协议检测
#[cfg(feature = "tls")]
async fn handle_connection(
    stream: TcpStream,
    connection_id: usize,
    client_addr: SocketAddr,
    tls_config: Option<Arc<ServerConfig>>,
) -> io::Result<()> {
    let mut peek_buf = [0; 1];
    match stream.peek(&mut peek_buf).await {
        Ok(0) => {
            warn!("[连接 #{}] 客户端 {} 连接已关闭", connection_id, client_addr);
            Ok(())
        }
        Ok(_) => {
            if peek_buf[0] == 0x16 && tls_config.is_some() {
                info!("[连接 #{}] 检测到 TLS 连接 (HTTPS 代理)", connection_id);
                return handle_tls_proxy(stream, connection_id, client_addr, tls_config.unwrap()).await;
            }
            info!("[连接 #{}] 检测到明文连接 (HTTP 代理)", connection_id);
            handle_http_proxy(stream, connection_id, client_addr).await
        }
        Err(e) => {
            error!("[连接 #{}] 无法检测协议: {}", connection_id, e);
            Err(e)
        }
    }
}

#[cfg(not(feature = "tls"))]
async fn handle_connection(
    stream: TcpStream,
    connection_id: usize,
    client_addr: SocketAddr,
    _tls_config: Option<Arc<()>>,
) -> io::Result<()> {
    info!("[连接 #{}] 检测到明文连接 (HTTP 代理)", connection_id);
    handle_http_proxy(stream, connection_id, client_addr).await
}

// ==================== HTTP 代理处理（明文） ====================

async fn handle_http_proxy<S>(
    mut stream: S,
    connection_id: usize,
    client_addr: SocketAddr,
) -> io::Result<()>
where
    S: io::AsyncRead + io::AsyncWrite + Unpin,
{
    let mut buffer = [0; 8192];
    let bytes_read = stream.read(&mut buffer).await?;

    if bytes_read == 0 {
        return Ok(());
    }

    // 安全解析：先找 \r\n\r\n 规避二进制 Body 导致的 UTF-8 索引 Panic 风险
    let header_end = buffer[..bytes_read]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(bytes_read);

    let request_str = String::from_utf8_lossy(&buffer[..header_end]);
    let first_line = request_str.lines().next().unwrap_or("");
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
        return handle_connect(stream, url, connection_id, client_addr).await;
    }

    handle_http_request(stream, method, url, version, &buffer[..bytes_read], header_end, connection_id).await
}

// ==================== TLS 代理处理（HTTPS 代理） ====================

#[cfg(feature = "tls")]
async fn handle_tls_proxy(
    stream: TcpStream,
    connection_id: usize,
    client_addr: SocketAddr,
    config: Arc<ServerConfig>,
) -> io::Result<()> {
    use tokio_rustls::TlsAcceptor;

    info!("[连接 #{}] 开始 TLS 握手", connection_id);
    let acceptor = TlsAcceptor::from(config);

    match acceptor.accept(stream).await {
        Ok(tls_stream) => {
            info!("[连接 #{}] TLS 握手成功", connection_id);
            // 泛型支持：将握手后的 TLS Stream 传给 HTTP 处理器
            handle_http_proxy(tls_stream, connection_id, client_addr).await
        }
        Err(e) => {
            error!("[连接 #{}] TLS 握手失败: {}", connection_id, e);
            Err(e)
        }
    }
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
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

#[cfg(feature = "tls")]
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let cert_reader: Vec<_> = certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(cert_reader)
}

#[cfg(feature = "tls")]
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    let mut keys: Vec<_> = pkcs8_private_keys(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        return Err("没有找到私钥".into());
    }
    Ok(PrivateKeyDer::Pkcs8(keys.remove(0)))
}

// ==================== CONNECT 方法处理（HTTPS 隧道） ====================

async fn handle_connect<S>(
    mut client_stream: S,
    url: &str,
    connection_id: usize,
    client_addr: SocketAddr,
) -> io::Result<()>
where
    S: io::AsyncRead + io::AsyncWrite + Unpin,
{
    let addr_parts: Vec<&str> = url.split(':').collect();
    if addr_parts.len() != 2 {
        error!("[连接 #{}] 无效的 CONNECT 地址: {}", connection_id, url);
        return Ok(());
    }

    let host = addr_parts[0];
    let port: u16 = addr_parts[1].parse().unwrap_or(443);
    let target_addr = format!("{}:{}", host, port);

    info!("[连接 #{}] 连接到目标服务器: {}", connection_id, target_addr);

    let target_stream = match TcpStream::connect(&target_addr).await {
        Ok(stream) => {
            info!("[连接 #{}] 成功连接到目标服务器: {}", connection_id, target_addr);
            stream
        }
        Err(e) => {
            error!("[连接 #{}] 连接目标服务器失败 {}: {}", connection_id, target_addr, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client_stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }
    };

    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    client_stream.write_all(response.as_bytes()).await?;
    info!("[连接 #{}] 隧道已建立 ({} -> {})", connection_id, client_addr, target_addr);

    // 将双向流分离为读和写两部分，执行高速异步转发
    let (mut client_reader, mut client_writer) = io::split(client_stream);
    let (mut target_reader, mut target_writer) = io::split(target_stream);

    let client_to_target = async {
        let res = io::copy(&mut client_reader, &mut target_writer).await;
        let _ = target_writer.shutdown().await;
        res
    };

    let target_to_client = async {
        let res = io::copy(&mut target_reader, &mut client_writer).await;
        let _ = client_writer.shutdown().await;
        res
    };

    // 并发流双向拷贝
    let (res1, res2) = tokio::join!(client_to_target, target_to_client);
    if let Err(e) = res1 { debug!("[连接 #{}] 客户端 -> 目标 转发结束: {}", connection_id, e); }
    if let Err(e) = res2 { debug!("[连接 #{}] 目标 -> 客户端 转发结束: {}", connection_id, e); }

    info!("[连接 #{}] 隧道已关闭", connection_id);
    Ok(())
}

// ==================== 标准 HTTP 请求处理 ====================

async fn handle_http_request<S>(
    mut client_stream: S,
    method: &str,
    url: &str,
    version: &str,
    request_data: &[u8],
    header_end: usize,
    connection_id: usize,
) -> io::Result<()>
where
    S: io::AsyncRead + io::AsyncWrite + Unpin,
{
    let (host, port, path) = parse_url(url);
    info!("[连接 #{}] 解析目标: {}:{}{}", connection_id, host, port, path);

    let request_line = format!("{} {} {}\r\n", method, path, version);
    
    let header_str = String::from_utf8_lossy(&request_data[..header_end]);
    let headers: Vec<&str> = header_str
        .lines()
        .skip(1)
        .filter(|line| !line.to_lowercase().starts_with("proxy-"))
        .collect();

    let target_addr = format!("{}:{}", host, port);
    let mut target_stream = match TcpStream::connect(&target_addr).await {
        Ok(stream) => {
            info!("[连接 #{}] 成功连接到 {}:{}", connection_id, host, port);
            stream
        }
        Err(e) => {
            error!("[连接 #{}] 连接目标 {} 失败: {}", connection_id, target_addr, e);
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client_stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }
    };

    // 写入请求头
    target_stream.write_all(request_line.as_bytes()).await?;
    for header in &headers {
        target_stream.write_all(header.as_bytes()).await?;
        target_stream.write_all(b"\r\n").await?;
    }
    target_stream.write_all(b"\r\n").await?;

    // 写入请求体（如果存在）
    if header_end + 4 < request_data.len() {
        let body = &request_data[header_end + 4..];
        if !body.is_empty() {
            target_stream.write_all(body).await?;
        }
    }

    info!("[连接 #{}] 请求转发完成，等待响应...", connection_id);

    // 将响应从目标服务器抽干并写回客户端
    let (mut target_reader, mut target_writer) = io::split(target_stream);
    let (mut client_reader, mut client_writer) = io::split(client_stream);

    // 转发响应数据
    let bytes_copied = io::copy(&mut target_reader, &mut client_writer).await?;
    let _ = client_writer.shutdown().await;
    let _ = target_writer.shutdown().await;

    info!("[连接 #{}] 响应转发完成 (共 {} 字节)", connection_id, bytes_copied);
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