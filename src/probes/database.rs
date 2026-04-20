/// 数据库协议探测器 (MySQL, Redis, MongoDB, PostgreSQL, Memcached, Elasticsearch)

use super::*;

// ============== MySQL ==============

/// 探测 MySQL 服务
pub async fn detect_mysql(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // MySQL 服务器会主动发送握手包，我们只需要读取
    let response = match read_banner_with_timeout(&mut stream, 1024, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // MySQL 握手包包含 mysql_native_password 或 MySQL 字样
    if !response.contains("mysql_native_password") &&
       !response.contains("MySQL") &&
       !response.contains("mariadb") {
        return None;
    }

    // 提取版本 (简化)
    let version = "Unknown".to_string();
    let auth_plugin = if response.contains("mysql_native_password") {
        "mysql_native_password"
    } else {
        "Unknown"
    };

    Some(
        ProtocolInfo::new("mysql", 0.95)
            .with_version(&version)
            .with_details(&format!("Auth: {}", auth_plugin)),
    )
}

// ============== Redis ==============

const REDIS_PING: &[u8] = b"*1\r\n$4\r\nPING\r\n";

/// 探测 Redis 服务
pub async fn detect_redis(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // 发送 PING 命令
    if let Err(_) = stream.write_all(REDIS_PING).await {
        return None;
    }

    // 读取响应
    let response = match read_banner_with_timeout(&mut stream, 256, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // Redis 响应: +PONG 或 -ERR 或 -NOAUTH
    if !response.starts_with("+PONG") && !response.starts_with("-ERR") && !response.starts_with("-NOAUTH") {
        return None;
    }

    let authenticated = !response.starts_with("-NOAUTH");
    
    Some(
        ProtocolInfo::new("redis", 0.95)
            .with_details(&format!("Auth: {}", if authenticated { "No" } else { "Required" })),
    )
}

// ============== MongoDB ==============

/// 探测 MongoDB 服务
pub async fn detect_mongodb(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // MongoDB isMaster 命令 (OP_MSG 格式)
    // 简化版：发送 isMaster 查询
    const ISMASTER_CMD: &[u8] = &[
        0x19, 0x00, 0x00, 0x00,  // 消息长度 (25)
        0x01, 0x00, 0x00, 0x00,  // requestID
        0x00, 0x00, 0x00, 0x00,  // responseTo
        0xd4, 0x07, 0x00, 0x00,  // OP_MSG (2012)
        0x00,                    // flags
        0x00,                    // checksum (可选)
        0x13, 0x00, 0x00, 0x00,  // document length
        0x02, 0x69, 0x73, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,  // "ismaster"
        0x01, 0x00, 0x00, 0x00,  // true
        0x00,                    // document end
    ];

    if let Err(_) = stream.write_all(ISMASTER_CMD).await {
        return None;
    }

    let response = match read_banner_with_timeout(&mut stream, 1024, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // MongoDB 响应包含 "ismaster" 或 "MongoDB"
    if response.contains("MongoDB") || response.contains("ismaster") {
        Some(ProtocolInfo::new("mongodb", 0.95))
    } else {
        None
    }
}

// ============== Memcached ==============

const MEMCACHED_STATS: &[u8] = b"stats\r\n";

/// 探测 Memcached 服务
pub async fn detect_memcached(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    if let Err(_) = stream.write_all(MEMCACHED_STATS).await {
        return None;
    }

    let response = match read_banner_with_timeout(&mut stream, 1024, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // Memcached 响应: STAT pid xxx
    if response.contains("STAT pid") && response.contains("END") {
        Some(ProtocolInfo::new("memcached", 0.95))
    } else {
        None
    }
}

// ============== PostgreSQL ==============

/// 探测 PostgreSQL 服务
pub async fn detect_postgresql(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // PostgreSQL StartupMessage (SSLRequest)
    const PG_SSL_REQUEST: &[u8] = &[
        0x00, 0x00, 0x00, 0x08,  // 消息长度 (8)
        0x04, 0xd2, 0x16, 0x2f,  // SSLRequest 代码
    ];

    if let Err(_) = stream.write_all(PG_SSL_REQUEST).await {
        return None;
    }

    let response = match read_banner_with_timeout(&mut stream, 256, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // PostgreSQL SSLRequest 的典型响应是单字节 'S' 或 'N'。
    // ErrorResponse 以 'E' 开头并包含后续内容。
    let bytes = response.as_bytes();
    if bytes.len() == 1 && (bytes[0] == b'S' || bytes[0] == b'N') {
        return Some(ProtocolInfo::new("postgresql", 0.95));
    }

    if !bytes.is_empty() && bytes[0] == b'E' {
        return Some(ProtocolInfo::new("postgresql", 0.9));
    }

    None
}

// ============== Elasticsearch ==============

/// 探测 Elasticsearch 服务
pub async fn detect_elasticsearch(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    const HTTP_GET: &[u8] = b"GET / HTTP/1.0\r\n\r\n";

    if let Err(_) = stream.write_all(HTTP_GET).await {
        return None;
    }

    let response = match read_banner_with_timeout(&mut stream, 2048, ctx.timeout).await {
        Some(r) => r,
        None => return None,
    };

    // Elasticsearch 响应包含 "cluster_name" 和 "tagline"
    if response.contains("\"cluster_name\"") || response.contains("\"tagline\"") {
        Some(ProtocolInfo::new("elasticsearch", 0.98))
    } else {
        None
    }
}
