/// 协议检测主入口
/// 实现三阶段识别策略：
/// 1. 端口精确匹配
/// 2. 端口区域匹配
/// 3. 通用探测兜底

use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashSet;
use tokio::time::Duration;
use tokio::task::JoinSet;
use crate::probes::*;
use crate::port_map::*;

/// 协议检测器
pub struct ProtocolDetector {
    timeout: Duration,
    connect_retries: usize,
}

impl ProtocolDetector {
    pub fn new(timeout: Duration, connect_retries: usize) -> Self {
        Self {
            timeout,
            connect_retries,
        }
    }

    /// 检测单个端口的协议
    pub async fn detect(&self, socket: SocketAddr) -> ProtocolInfo {
        let ctx = ProbeContext::new(socket, self.timeout, self.connect_retries);
        let port = socket.port();

        let stages = Self::build_probe_stages(port);
        for (idx, stage) in stages.into_iter().enumerate() {
            let max_in_flight = if idx == 0 { 4 } else if port <= 10_000 { 8 } else { 6 };
            if let Some(info) = self.concurrent_probe_limited(&ctx, stage, max_in_flight).await {
                return info;
            }
        }

        // 阶段3: 通用探测 - 托底方案
        generic::generic_probe(&ctx).await
    }

    fn build_probe_stages(port: u16) -> Vec<Vec<&'static str>> {
        let mut stages = Vec::new();

        if has_exact_mapping(port) {
            stages.push(Self::prioritize_for_port(port, get_protocols_for_port(port)));
        }

        if let Some(probes) = get_special_range_probes(port) {
            stages.push(Self::prioritize_for_port(port, probes));
        }

        let range = PortRange::from_port(port);
        stages.push(Self::prioritize_for_port(port, range.default_probes()));

        // 1w 内端口增加全指纹并发兜底（有预算限制）
        if port <= 10_000 {
            stages.push(Self::prioritize_for_port(port, Self::all_supported_fingerprints()));
        }

        stages
            .into_iter()
            .map(Self::dedup_protocols)
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn dedup_protocols(protocols: Vec<&'static str>) -> Vec<&'static str> {
        let mut seen = HashSet::new();
        protocols.into_iter().filter(|p| seen.insert(*p)).collect()
    }

    fn all_supported_fingerprints() -> Vec<&'static str> {
        vec![
            "http", "tls", "ssh", "ftp", "ftp-data", "dns", "ldap",
            "mysql", "redis", "mongodb", "postgresql", "memcached",
            "elasticsearch", "mqtt", "mqtt-tls", "rmi", "jrmi",
            "idap", "idaps", "generic-banner", "raw-tcp",
        ]
    }

    fn is_high_port(port: u16) -> bool {
        port > 10_000
    }

    fn prioritize_for_port(port: u16, protocols: Vec<&'static str>) -> Vec<&'static str> {
        let host_service = ["ssh", "ssh-alt", "smb", "rdp", "msrpc", "netbios", "winrm"];
        let mut non_host = Vec::new();
        let mut host = Vec::new();
        for p in protocols {
            if host_service.contains(&p) {
                host.push(p);
            } else {
                non_host.push(p);
            }
        }

        if Self::is_high_port(port) {
            non_host.extend(host);
            return non_host;
        }

        host.extend(non_host);
        host
    }

    /// 分批并发运行探针，返回第一个成功结果
    async fn concurrent_probe_limited(
        &self,
        ctx: &ProbeContext,
        protocols: Vec<&'static str>,
        max_in_flight: usize,
    ) -> Option<ProtocolInfo> {
        if protocols.is_empty() {
            return None;
        }

        let budget = max_in_flight.max(1);
        let mut tasks = JoinSet::new();
        let ctx_arc = Arc::new(*ctx);
        let mut iter = protocols.into_iter();

        for _ in 0..budget {
            let Some(protocol) = iter.next() else { break };
            let ctx_clone = Arc::clone(&ctx_arc);
            tasks.spawn(async move {
                Self::run_probe_impl(&ctx_clone, protocol).await
            });
        }

        while let Some(result) = tasks.join_next().await {
            if let Ok(Some(info)) = result {
                tasks.abort_all();
                return Some(info);
            }

            if let Some(next_protocol) = iter.next() {
                let ctx_clone = Arc::clone(&ctx_arc);
                tasks.spawn(async move {
                    Self::run_probe_impl(&ctx_clone, next_protocol).await
                });
            }
        }

        None
    }

    /// 运行单个探针的实现
    async fn run_probe_impl(ctx: &Arc<ProbeContext>, protocol: &str) -> Option<ProtocolInfo> {
        let ctx = &**ctx;
        match protocol {
            "http" | "http-alt" | "http-proxy" | "dev" | "vestacp" | "cpanel" | "whm" | 
            "docker-api" | "etcd" | "sonarqube" | "kibana" |
            "prometheus" | "node-exporter" | "rabbitmq-mgmt" | 
            "activemq-web" | "webmin" | "usermin" | "tomcat" | "rundeck" | "glassfish" |
            "weblogic" | "ganglia" | "couchdb" | "winrm" | "ismap" |
            "oracle-xmldb" | "bittorrent-tracker" | "tor" | "mongodb-http" => {
                http::detect_http(ctx).await
            }
            "tls" | "https" | "https-alt" | "smtps" | "ldaps" | "imaps" | "pop3s" |
            "docker-tls" | "cpanel-ssl" | "whm-ssl" | "weblogic-ssl" | "kubelet" | "vmware" |
            "rabbitmq-amqps" => {
                http::detect_tls(ctx).await
            }
            "ssh" | "ssh-alt" => {
                ssh::detect_ssh(ctx).await
            }
            "ftp" => {
                generic::banner_grab(ctx).await.and_then(|info| {
                    if info.name == "ftp" { Some(info) } else { None }
                })
            }
            "ftp-data" => {
                generic::detect_ftp_data(ctx).await
            }
            "dns" => {
                generic::detect_dns(ctx).await
            }
            "ldap" => {
                generic::detect_ldap(ctx).await
            }
            "mysql" | "mysql-alt" => {
                database::detect_mysql(ctx).await
            }
            "redis" => {
                database::detect_redis(ctx).await
            }
            "mongodb" | "mongodb-shard" | "mongodb-config" => {
                database::detect_mongodb(ctx).await
            }
            "postgresql" => {
                database::detect_postgresql(ctx).await
            }
            "memcached" => {
                database::detect_memcached(ctx).await
            }
            "elasticsearch" => {
                database::detect_elasticsearch(ctx).await
            }
            "mqtt" => {
                mqtt::detect_mqtt(ctx).await
            }
            "mqtt-tls" => {
                mqtt::detect_mqtt_tls(ctx).await
            }
            "generic-banner" => {
                generic::banner_grab(ctx).await
            }
            "raw-tcp" => {
                generic::raw_tcp_echo(ctx).await
            }
            "rmi" | "jrmi" => {
                generic::detect_rmi(ctx).await
            }
            "idap" | "idaps" => {
                generic::detect_idap(ctx).await
            }
            // 其他协议暂不支持，回退到通用探测
            _ => None,
        }
    }
}

/// 格式化输出协议信息
pub fn format_protocol(info: &ProtocolInfo) -> String {
    let mut output = format!("{:<12}", info.name);
    
    if let Some(version) = &info.version {
        output = format!("{} | {:<20}", output, version);
    } else {
        output = format!("{} | {:<20}", output, "-");
    }
    
    if let Some(details) = &info.details {
        output = format!("{} | {}", output, details);
    }
    
    output = format!("{} | {:.2}", output, info.confidence);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::Duration;

    #[test]
    fn test_port_mapping_integration() {
        // 测试常用端口的映射
        assert!(has_exact_mapping(80));
        assert!(has_exact_mapping(443));
        assert!(has_exact_mapping(22));
        assert!(has_exact_mapping(3306));
        assert!(has_exact_mapping(6379));
    }

    #[test]
    fn test_protocol_format() {
        let info = ProtocolInfo::new("http", 0.95)
            .with_version("1.1")
            .with_details("nginx");
        
        let formatted = format_protocol(&info);
        assert!(formatted.contains("http"));
        assert!(formatted.contains("0.95"));
    }

    async fn spawn_single_response_server(response: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut req = [0u8; 512];
                let _ = stream.read(&mut req).await;
                let _ = stream.write_all(&response).await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_run_probe_impl_supports_dns() {
        // 最小 TCP DNS 响应片段（仅用于触发协议识别）
        let addr = spawn_single_response_server(vec![0x00, 0x0c, 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        let ctx = Arc::new(ProbeContext::new(addr, Duration::from_millis(300), 0));

        let info = ProtocolDetector::run_probe_impl(&ctx, "dns").await;
        assert!(info.is_some(), "dns probe should be supported");
    }

    #[tokio::test]
    async fn test_run_probe_impl_supports_ldap() {
        // 最小 LDAP BindResponse BER 片段
        let addr = spawn_single_response_server(vec![0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]).await;
        let ctx = Arc::new(ProbeContext::new(addr, Duration::from_millis(300), 0));

        let info = ProtocolDetector::run_probe_impl(&ctx, "ldap").await;
        assert!(info.is_some(), "ldap probe should be supported");
    }

    #[tokio::test]
    async fn test_rmi_probe_accepts_binary_handshake_response() {
        // 真实环境常见：二进制响应不含可读 JRMI/RMI 文本
        let addr = spawn_single_response_server(vec![0x4e, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await;
        let ctx = Arc::new(ProbeContext::new(addr, Duration::from_millis(300), 0));

        let info = ProtocolDetector::run_probe_impl(&ctx, "rmi").await;
        assert!(info.is_some(), "rmi probe should accept binary handshake style response");
    }

    #[test]
    fn test_registered_range_includes_ftp_for_pasv_ports() {
        let probes = PortRange::Registered.default_probes();
        assert!(probes.contains(&"ftp"), "registered range should include ftp probe for passive data ports");
    }

    #[test]
    fn test_common_host_port_prioritizes_host_fingerprints() {
        let ordered = ProtocolDetector::prioritize_for_port(22, vec!["http", "ssh", "dns"]);
        assert_eq!(ordered[0], "ssh", "common host port should prioritize host-service fingerprints");
    }

    #[test]
    fn test_high_port_deprioritizes_host_fingerprints() {
        let ordered = ProtocolDetector::prioritize_for_port(55000, vec!["ssh", "http", "dns"]);
        assert_ne!(ordered[0], "ssh", "high ports should deprioritize host-service fingerprints");
        assert_eq!(ordered.last().copied(), Some("ssh"), "host-service fingerprint should be pushed to the tail on high ports");
    }
}
