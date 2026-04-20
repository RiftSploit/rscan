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

    let response = match read_banner_with_timeout(&mut stream, 256, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    if response.contains("JRMI") || response.contains("RMI") {
        return Some(
            ProtocolInfo::new("rmi", 0.9)
                .with_details("Detected from JRMI handshake"),
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
