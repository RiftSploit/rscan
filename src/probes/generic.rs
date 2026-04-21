/// 通用探测器和回退逻辑

use super::*;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// 通用横幅抓取
pub async fn banner_grab(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // 尝试读取横幅
    let banner = match read_banner_with_timeout(&mut stream, 512, ctx.timeout).await {
        Some(b) if !b.is_empty() => b,
        _ => return None,
    };

    // 尝试识别横幅中的协议特征
    if let Some(info) = identify_from_banner(&banner) {
        return Some(info);
    }

    // 无法识别，返回通用信息
    Some(
        ProtocolInfo::new("unknown", 0.5)
            .with_details(&banner.chars().take(100).collect::<String>()),
    )
}

/// 从横幅中识别协议
fn identify_from_banner(banner: &str) -> Option<ProtocolInfo> {
    // SSH
    if banner.starts_with("SSH-") {
        return Some(ProtocolInfo::new("ssh", 1.0)
            .with_version(banner.trim())
            .with_details("Detected from banner"));
    }

    // FTP
    if banner.starts_with("220") && banner.contains("FTP") {
        return Some(ProtocolInfo::new("ftp", 0.95)
            .with_details(banner.trim()));
    }

    // SMTP
    if banner.starts_with("220") && (banner.contains("SMTP") || banner.contains("ESMTP")) {
        return Some(ProtocolInfo::new("smtp", 0.95)
            .with_details(banner.trim()));
    }

    // POP3
    if banner.starts_with("+OK") && banner.contains("POP3") {
        return Some(ProtocolInfo::new("pop3", 0.95));
    }

    // IMAP
    if banner.contains("* OK") && banner.contains("IMAP") {
        return Some(ProtocolInfo::new("imap", 0.95));
    }

    // VNC/RFB
    if banner.starts_with("RFB") {
        return Some(ProtocolInfo::new("vnc", 0.95)
            .with_version(banner.lines().next().unwrap_or("").trim()));
    }

    // MySQL
    if banner.contains("mysql_native_password") || banner.contains("MySQL") {
        return Some(ProtocolInfo::new("mysql", 0.95));
    }

    // PostgreSQL
    if banner.contains("PostgreSQL") {
        return Some(ProtocolInfo::new("postgresql", 0.95));
    }

    None
}

/// 原始 TCP 回显探测
pub async fn raw_tcp_echo(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // 发送测试数据
    const TEST_DATA: &[u8] = b"Hello\r\n";
    if let Err(_) = stream.write_all(TEST_DATA).await {
        return None;
    }

    // 读取回显
    let response = match read_banner_with_timeout(&mut stream, 256, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // 如果有响应但不匹配任何已知协议
    Some(
        ProtocolInfo::new("raw-tcp", 0.3)
            .with_details(&format!("Response: {}", response.chars().take(50).collect::<String>())),
    )
}

/// RMI/JRMI 探测
pub async fn detect_rmi(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // JRMI 握手前缀（简化探测包）
    const JRMI_PROBE: &[u8] = b"JRMI\x00\x02K";
    if stream.write_all(JRMI_PROBE).await.is_err() {
        return None;
    }

    let response = match read_bytes_with_timeout(&mut stream, 256, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    if response.starts_with(b"JRMI") {
        return Some(
            ProtocolInfo::new("rmi", 0.9)
                .with_details("Detected from JRMI handshake"),
        );
    }

    // 部分 RMI 端点返回二进制传输层响应，不含可读 JRMI/RMI 文本
    if matches!(response.first(), Some(0x4e | 0x4f | 0x51)) {
        return Some(
            ProtocolInfo::new("rmi", 0.75)
                .with_details("Detected from binary RMI transport response"),
        );
    }

    let text = String::from_utf8_lossy(&response);
    if text.contains("JRMI") || text.contains("RMI") {
        return Some(
            ProtocolInfo::new("rmi", 0.8)
                .with_details("Detected from RMI text signature"),
        );
    }

    None
}

/// IDAP 探测（弱特征，更多依赖返回横幅关键词）
pub async fn detect_idap(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    const IDAP_PROBE: &[u8] = b"\n";
    if stream.write_all(IDAP_PROBE).await.is_err() {
        return None;
    }

    let response = match read_banner_with_timeout(&mut stream, 512, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    let lower = response.to_lowercase();
    if lower.contains("idap") || lower.contains("oracle internet directory") {
        return Some(
            ProtocolInfo::new("idap", 0.75)
                .with_details("Detected from service banner"),
        );
    }

    None
}

/// DNS(TCP) 探测
pub async fn detect_dns(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // TCP DNS 查询（前置 2 字节长度）
    const DNS_QUERY_TCP: &[u8] = &[
        0x00, 0x1d, // length
        0x12, 0x34, // id
        0x01, 0x00, // flags: standard query
        0x00, 0x01, // qdcount
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,       // root
        0x00, 0x01, // type A
        0x00, 0x01, // class IN
    ];

    if stream.write_all(DNS_QUERY_TCP).await.is_err() {
        return None;
    }

    let response = read_bytes_with_timeout(&mut stream, 512, ctx.timeout).await?;
    if response.len() < 14 {
        return None;
    }

    let payload = &response[2..];
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }

    Some(
        ProtocolInfo::new("dns", 0.9)
            .with_details("Detected from DNS-over-TCP response"),
    )
}

/// LDAP 探测（基于简单 BindRequest/BindResponse）
pub async fn detect_ldap(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    const LDAP_BIND_REQUEST: &[u8] = &[
        0x30, 0x0c, // LDAPMessage SEQUENCE
        0x02, 0x01, 0x01, // messageID = 1
        0x60, 0x07, // BindRequest [APPLICATION 0]
        0x02, 0x01, 0x03, // version = 3
        0x04, 0x00, // name = ""
        0x80, 0x00, // simple auth = ""
    ];

    if stream.write_all(LDAP_BIND_REQUEST).await.is_err() {
        return None;
    }

    let response = read_bytes_with_timeout(&mut stream, 512, ctx.timeout).await?;
    if response.len() < 6 || response[0] != 0x30 {
        return None;
    }

    if response.iter().any(|b| *b == 0x61) {
        return Some(
            ProtocolInfo::new("ldap", 0.9)
                .with_details("Detected from LDAP BindResponse"),
        );
    }

    None
}

/// FTP data 通道弱探测（适用于被动模式数据端口）
pub async fn detect_ftp_data(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    let mut buf = [0u8; 8];
    let read_result = timeout(Duration::from_millis(200), stream.read(&mut buf)).await;
    match read_result {
        // FTP 数据通道常见行为：连接建立后短时间无banner
        Err(_) => Some(
            ProtocolInfo::new("ftp-data", 0.55)
                .with_details("Heuristic: passive FTP data channel behavior"),
        ),
        Ok(Ok(0)) => None,
        Ok(Ok(_)) => Some(
            ProtocolInfo::new("ftp-data", 0.6)
                .with_details("Heuristic: FTP data channel with payload"),
        ),
        Ok(Err(_)) => None,
    }
}

/// 通用探测入口
pub async fn generic_probe(ctx: &ProbeContext) -> ProtocolInfo {
    use crate::probes::http::{detect_http, detect_tls};

    // 1. HTTP 探测
    if let Some(info) = detect_http(ctx).await {
        return info;
    }

    // 2. TLS 探测
    if let Some(info) = detect_tls(ctx).await {
        return info;
    }

    // 3. 横幅抓取
    if let Some(info) = banner_grab(ctx).await {
        return info;
    }

    // 4. TCP/UDP 双协议托底
    if udp_probe(ctx).await {
        return ProtocolInfo::new("open", 0.35).with_version("tcp+udp");
    }

    ProtocolInfo::new("open", 0.3).with_version("tcp")
}

async fn udp_probe(ctx: &ProbeContext) -> bool {
    let bind_addr = if ctx.socket.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(_) => return false,
    };

    if socket.send_to(b"PING", ctx.socket).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 256];
    matches!(
        timeout(ctx.timeout, socket.recv_from(&mut buf)).await,
        Ok(Ok((n, _))) if n > 0
    )
}
