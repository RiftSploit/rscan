/// HTTP/HTTPS 协议探测器

use super::*;

const HTTP_PROBE: &[u8] = b"GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";

/// 探测 HTTP 服务
pub async fn detect_http(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // 发送 HTTP 请求
    if let Err(_) = stream.write_all(HTTP_PROBE).await {
        return None;
    }

    // 读取响应
    let response = match read_banner_with_timeout(&mut stream, 2048, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // 解析 HTTP 响应
    if !response.starts_with("HTTP/") {
        return None;
    }

    // 提取状态码
    let status_code = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // 提取 Server 头
    let server = extract_header(&response, "Server:").unwrap_or_else(|| "Unknown".to_string());

    // 提取标题
    let title = extract_html_title(&response);

    // 计算置信度
    let confidence = if server != "Unknown" {
        0.95
    } else {
        0.8
    };

    let mut info = ProtocolInfo::new("http", confidence)
        .with_version("HTTP/1.x")
        .with_details(&format!("Server: {}, Status: {}", server, status_code));

    if let Some(t) = title {
        info.details = Some(format!("{} Title: {}", info.details.unwrap_or_default(), t));
    }

    Some(info)
}

/// 探测 HTTPS/TLS
pub async fn detect_tls(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    // TLS ClientHello (简化版)
    const TLS_CLIENT_HELLO: &[u8] = &[
        0x16,       // Handshake
        0x03, 0x01, // TLS 1.0
        0x00, 0x6e, // 长度
        0x01,       // ClientHello
        0x00, 0x00, 0x6a, 0x03, 0x03, // TLS 1.2
        // Random (32 bytes)
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x00,       // Session ID length
        0x00, 0x14, // Cipher suites length
        0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, // Cipher suites
        0x01,       // Compression methods
        0x00,       // NULL compression
    ];

    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // 发送 ClientHello
    if let Err(_) = stream.write_all(TLS_CLIENT_HELLO).await {
        return None;
    }

    // 读取响应
    let response = match read_bytes_with_timeout(&mut stream, 1024, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // TLS ServerHello 以 0x16 开头 (Handshake)
    if response.len() < 5 || response[0] != 0x16 {
        return None;
    }

    // 提取 TLS 版本
    let tls_version = match (response[1], response[2]) {
        (0x03, 0x01) => "TLS 1.0",
        (0x03, 0x02) => "TLS 1.1",
        (0x03, 0x03) => "TLS 1.2",
        (0x03, 0x04) => "TLS 1.3",
        _ => "Unknown",
    };

    Some(
        ProtocolInfo::new("tls", 0.95)
            .with_version(tls_version)
            .with_details("TLS ServerHello"),
    )
}

/// 提取 HTTP 头
fn extract_header(response: &str, header: &str) -> Option<String> {
    response
        .lines()
        .find(|line| line.to_lowercase().starts_with(&header.to_lowercase()))
        .and_then(|line| line.splitn(2, ':').nth(1))
    .map(|value| value.trim().to_string())
}

/// 提取 HTML 标题
fn extract_html_title(response: &str) -> Option<String> {
    let html_part = response.rsplitn(2, "\r\n\r\n").next().unwrap_or(response);
    
    if let Some(start) = html_part.find("<title>") {
        if let Some(end) = html_part.find("</title>") {
            if end > start {
                return Some(html_part[start + 7..end].trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_header() {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(extract_header(response, "Server:"), Some("nginx/1.18.0".to_string()));
        assert_eq!(extract_header(response, "server:"), Some("nginx/1.18.0".to_string()));
        assert_eq!(extract_header(response, "Missing:"), None);
    }

    #[test]
    fn test_extract_html_title() {
        let response = "HTTP/1.1 200 OK\r\n\r\n<html><head><title>Test Page</title></head></html>";
        assert_eq!(extract_html_title(response), Some("Test Page".to_string()));
    }
}
