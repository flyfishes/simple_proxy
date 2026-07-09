use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::io;
use env_logger::Builder;
use log::{info, LevelFilter};
use std::fs::File;
use rustls::{ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::sync::Arc;

fn main() -> io::Result<()> {
    // 获取端口配置
    let log_file = File::create("simple_proxy.log").expect("无法创建日志文件");
    Builder::new()
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .filter(None, LevelFilter::Info)  // 设置日志级别
        .init();
    
    let port = get_port();
    // 检查是否启用 HTTPS 代理
    let enable_tls = env::var("PROXY_TLS").is_ok();
    
    if enable_tls {
        info!("启动 HTTPS 代理服务器（TLS 加密）");
        run_https_proxy(port)?;
    } else {
        info!("启动 HTTP 代理服务器（明文）");
        run_http_proxy(port)?;
    }
    /** 
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind_addr)?;
    info!("代理服务器运行在 {}", bind_addr);
    info!("按 Ctrl+C 停止服务器");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let client_addr = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());
                info!("Client Connect: {}", client_addr);
                thread::spawn(|| {
                    if let Err(e) = handle_client(stream) {
                        info!("处理客户端错误: {}", e);
                    }
                });
            }
            Err(e) => {
                info!("连接失败: {}", e);
            }
        }
    }
    **/
    Ok(())
}

fn get_port() -> u16 {
    // 优先使用命令行参数
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        if let Ok(port) = args[1].parse::<u16>() {
            if port > 0 && port <= 65535 {
                info!("使用命令行参数端口: {}", port);
                return port;
            }
        }
    }

    // 其次使用环境变量
    if let Ok(port_str) = env::var("PROXY_PORT") {
        if let Ok(port) = port_str.parse::<u16>() {
            if port > 0 && port <= 65535 {
                info!("使用环境变量 PROXY_PORT={} 端口", port);
                return port;
            }
        }
    }

    // 默认端口
    info!("使用默认端口: 8080");
    8080
}
fn run_http_proxy(port: u16) -> io::Result<()> {
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind_addr)?;
    info!("HTTP 代理服务器运行在 {}", bind_addr);
    info!("使用: curl --proxy http://localhost:{} https://abc.com", port);

    let mut connection_id = 0;
    for stream in listener.incoming() {
        connection_id += 1;
        let current_id = connection_id;
        
        match stream {
            Ok(stream) => {
                let client_addr = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());
                info!("[连接 #{}] 新客户端连接: {}", current_id, client_addr);
                
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, current_id, client_addr) {
                        error!("[连接 #{}] 处理错误: {}", current_id, e);
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

fn run_https_proxy(port: u16) -> io::Result<()> {
    // 加载证书和私钥（需要先生成）
    let cert_file = env::var("PROXY_CERT").unwrap_or_else(|_| "cert.pem".to_string());
    let key_file = env::var("PROXY_KEY").unwrap_or_else(|_| "key.pem".to_string());
    
    let certs = load_certs(&cert_file).expect("加载证书失败");
    let key = load_private_key(&key_file).expect("加载私钥失败");
    
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    let config = Arc::new(config);
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind_addr)?;
    
    info!("HTTPS 代理服务器运行在 {}", bind_addr);
    info!("使用: curl --proxy https://localhost:{} https://abc.com -k", port);
    
    // 创建 TLS 接受器
    use tokio_rustls::TlsAcceptor;
    let acceptor = TlsAcceptor::from(config);
    
    // ... 使用 tokio 处理 TLS 连接
    // 为了简单起见，这里使用同步方式（需要额外处理）
    
    Ok(())
}

fn load_certs(path: &str) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
    let certfile = File::open(path)?;
    let mut reader = std::io::BufReader::new(certfile);
    let certs = certs(&mut reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKey, Box<dyn std::error::Error>> {
    let keyfile = File::open(path)?;
    let mut reader = std::io::BufReader::new(keyfile);
    let keys = pkcs8_private_keys(&mut reader).unwrap();
    Ok(PrivateKey(keys[0].clone()))
}

fn handle_client(mut client_stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 4096];
    let bytes_read = client_stream.read(&mut buffer)?;
    
    if bytes_read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    
    // 解析请求行
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    
    if parts.len() < 3 {
        return Ok(());
    }

    let method = parts[0];
    let url = parts[1];
    let version = parts[2];

    // 处理CONNECT方法 (HTTPS)
    if method == "CONNECT" {
        return handle_connect(client_stream, url, version);
    }

    // 处理HTTP请求
    handle_http(client_stream, method, url, version, &buffer[..bytes_read])
}

fn handle_connect(mut client_stream: TcpStream, url: &str, _version: &str) -> io::Result<()> {
    // 解析目标地址和端口
    let addr_parts: Vec<&str> = url.split(':').collect();
    if addr_parts.len() != 2 {
        return Ok(());
    }

    let host = addr_parts[0];
    let port: u16 = addr_parts[1].parse().unwrap_or(443);

    // 连接到目标服务器
    let target_addr = format!("{}:{}", host, port);
    let mut target_stream = match TcpStream::connect(&target_addr) {
        Ok(stream) => stream,
        Err(_) => {
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client_stream.write(response.as_bytes())?;
            return Ok(());
        }
    };

    // 发送200连接建立响应
    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    client_stream.write(response.as_bytes())?;

    // 双向转发数据
    let mut client_clone = client_stream.try_clone()?;
    let mut target_clone = target_stream.try_clone()?;

    // 从客户端到目标
    let handle1 = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0; 4096];
        loop {
            match client_clone.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    target_clone.write_all(&buffer[..n])?;
                }
                Err(_) => break,
            }
        }
        Ok(())
    });

    // 从目标到客户端
    let handle2 = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0; 4096];
        loop {
            match target_stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    client_stream.write_all(&buffer[..n])?;
                }
                Err(_) => break,
            }
        }
        Ok(())
    });

    let _ = handle1.join();
    let _ = handle2.join();

    Ok(())
}

fn handle_http(
    mut client_stream: TcpStream,
    method: &str,
    url: &str,
    version: &str,
    request_data: &[u8],
) -> io::Result<()> {
    // 解析URL
    let (host, port, path) = parse_url(url);

    // 构建转发请求
    let request_line = format!("{} {} {}\r\n", method, path, version);
    
    // 获取原始请求的headers
    let request_str = String::from_utf8_lossy(request_data);
    let headers: Vec<&str> = request_str
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter(|line| !line.to_lowercase().starts_with("proxy-"))
        .collect();

    // 连接到目标服务器
    let target_addr = format!("{}:{}", host, port);
    let mut target_stream = match TcpStream::connect(&target_addr) {
        Ok(stream) => stream,
        Err(_) => {
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client_stream.write(response.as_bytes())?;
            return Ok(());
        }
    };

    // 发送请求到目标服务器
    target_stream.write(request_line.as_bytes())?;
    for header in headers {
        target_stream.write(header.as_bytes())?;
        target_stream.write(b"\r\n")?;
    }
    target_stream.write(b"\r\n")?;

    // 如果有请求体（POST等），转发
    if let Some(body_start) = request_str.find("\r\n\r\n") {
        let body = &request_data[body_start + 4..];
        if !body.is_empty() {
            target_stream.write(body)?;
        }
    }

    // 读取响应并转发给客户端
    let mut buffer = [0; 4096];
    loop {
        match target_stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                client_stream.write_all(&buffer[..n])?;
            }
            Err(_) => break,
        }
    }

    Ok(())
}

fn parse_url(url: &str) -> (String, u16, String) {
    // 处理完整URL
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
    
    // 处理相对路径
    if url.starts_with('/') {
        return ("localhost".to_string(), 80, url.to_string());
    }
    
    // 处理host:port/path格式
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
    
    // 只有host:port
    if let Some(port_pos) = url.find(':') {
        let host = url[..port_pos].to_string();
        let port: u16 = url[port_pos + 1..].parse().unwrap_or(80);
        return (host, port, "/".to_string());
    }
    
    (url.to_string(), 80, "/".to_string())
}