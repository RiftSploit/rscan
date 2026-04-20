/// MQTT 协议探测器

use super::*;

// MQTT 3.1.1 CONNECT 包
const MQTT_CONNECT: &[u8] = &[
    0x10,           // CONNECT 控制包类型
    0x16,           // 剩余长度 (22 字节)
    0x00, 0x04,     // 协议名长度
    b'M', b'Q', b'T', b'T',  // "MQTT"
    0x04,           // 协议级别 (v3.1.1)
    0x02,           // 连接标志 (Clean Session)
    0x00, 0x3c,     // 保持连接时间 (60 秒)
    0x00, 0x00,     // 客户端 ID 长度 (0 = 空)
];

/// 探测 MQTT 服务
pub async fn detect_mqtt(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // 发送 MQTT CONNECT 包
    if let Err(_) = stream.write_all(MQTT_CONNECT).await {
        return None;
    }

    // 读取响应
    let response = match read_banner_with_timeout(&mut stream, 256, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // MQTT CONNACK 固定头: 0x20 0x02，并至少包含 4 字节
    if response.len() < 4 || response.as_bytes()[0] != 0x20 || response.as_bytes()[1] != 0x02 {
        return None;
    }

    // 解析返回码 (byte 3)
    let return_code = response.as_bytes()[3];
    let status = match return_code {
        0x00 => "Connection Accepted",
        0x01 => "Unacceptable Protocol Version",
        0x02 => "Identifier Rejected",
        0x03 => "Server Unavailable",
        0x04 => "Bad Credentials",
        0x05 => "Not Authorized",
        _ => "Unknown",
    };

    let confidence = if return_code == 0x00 { 0.95 } else { 0.9 };

    Some(
        ProtocolInfo::new("mqtt", confidence)
            .with_version("3.1.1")
            .with_details(status),
    )
}

/// 探测 MQTT-TLS (需要先 TLS 握手)
pub async fn detect_mqtt_tls(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    use super::http::detect_tls;

    // 先尝试 TLS 探测
    if let Some(tls_info) = detect_tls(ctx).await {
        // TLS 成功后，再尝试 MQTT CONNECT
        // 注意: 这需要更复杂的 TLS 连接处理，当前简化处理
        Some(
            ProtocolInfo::new("mqtt-tls", 0.9)
                .with_version(tls_info.version.as_deref().unwrap_or("Unknown"))
                .with_details("TLS + MQTT"),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mqtt_connect_packet() {
        assert_eq!(MQTT_CONNECT[0], 0x10);  // CONNECT
        assert_eq!(MQTT_CONNECT[4], b'M');  // MQTT 协议名
        assert_eq!(MQTT_CONNECT[8], 0x04);  // 协议级别
    }
}
