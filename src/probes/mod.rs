/// 探针公共接口和数据结构

use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 协议信息
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    /// 协议名称
    pub name: String,
    /// 版本信息
    pub version: Option<String>,
    /// 额外详情
    pub details: Option<String>,
    /// 置信度 (0.0 - 1.0)
    pub confidence: f64,
}

impl ProtocolInfo {
    pub fn new(name: &str, confidence: f64) -> Self {
        Self {
            name: name.to_string(),
            version: None,
            details: None,
            confidence,
        }
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }
}

/// 探针特征
pub struct ProbeContext {
    pub socket: SocketAddr,
    pub timeout: Duration,
    pub connect_retries: usize,
}

impl ProbeContext {
    pub fn new(socket: SocketAddr, timeout: Duration, connect_retries: usize) -> Self {
        Self {
            socket,
            timeout,
            connect_retries,
        }
    }

    /// 建立 TCP 连接
    pub async fn connect(&self) -> Result<TcpStream, std::io::Error> {
        TcpStream::connect(self.socket).await
    }

    /// 带超时的连接
    pub async fn connect_with_timeout(&self) -> Result<TcpStream, std::io::Error> {
        let mut last_err: Option<std::io::Error> = None;
        for _ in 0..=self.connect_retries {
            match timeout(self.timeout, self.connect()).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(err)) => {
                    last_err = Some(err);
                }
                Err(_) => {
                    last_err = Some(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "connect failed")
        }))
    }
}

/// 探针类型（用于区域匹配）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeType {
    Http,
    Tls,
    Ssh,
    Ftp,
    Smtp,
    Snmp,
    Smb,
    Dns,
    Mysql,
    PostgreSQL,
    Redis,
    Memcached,
    MongoDB,
    Elasticsearch,
    Mqtt,
    RabbitMQ,
    InfluxDB,
    Zookeeper,
    GenericBanner,
    RawTcp,
}

/// 读取横幅（Banner Grab）
pub async fn read_banner(stream: &mut TcpStream, max_bytes: usize) -> Result<String, std::io::Error> {
    let bytes = read_bytes(stream, max_bytes).await?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

pub async fn read_bytes(stream: &mut TcpStream, max_bytes: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = vec![0u8; max_bytes];
    let n = stream.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

/// 带超时的读取横幅
pub async fn read_banner_with_timeout(
    stream: &mut TcpStream,
    max_bytes: usize,
    duration: Duration,
) -> Option<String> {
    match timeout(duration, read_banner(stream, max_bytes)).await {
        Ok(Ok(banner)) => Some(banner),
        _ => None,
    }
}

pub async fn read_bytes_with_timeout(
    stream: &mut TcpStream,
    max_bytes: usize,
    duration: Duration,
) -> Option<Vec<u8>> {
    match timeout(duration, read_bytes(stream, max_bytes)).await {
        Ok(Ok(bytes)) => Some(bytes),
        _ => None,
    }
}

/// 发送探测并读取响应
pub async fn probe_and_read(
    stream: &mut TcpStream,
    probe: &[u8],
    max_bytes: usize,
    duration: Duration,
) -> Option<String> {
    // 发送探测请求
    if let Err(_) = stream.write_all(probe).await {
        return None;
    }

    // 读取响应
    read_banner_with_timeout(stream, max_bytes, duration).await
}

// 导出所有探测器模块
pub mod http;
pub mod ssh;
pub mod database;
pub mod mqtt;
pub mod generic;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_info() {
        let info = ProtocolInfo::new("http", 0.95)
            .with_version("1.1")
            .with_details("nginx/1.18.0");
        
        assert_eq!(info.name, "http");
        assert_eq!(info.version, Some("1.1".to_string()));
        assert_eq!(info.details, Some("nginx/1.18.0".to_string()));
        assert_eq!(info.confidence, 0.95);
    }
}

