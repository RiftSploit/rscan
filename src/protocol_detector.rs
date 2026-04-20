/// 协议检测主入口
/// 实现三阶段识别策略：
/// 1. 端口精确匹配
/// 2. 端口区域匹配
/// 3. 通用探测兜底

use std::net::SocketAddr;
use tokio::time::Duration;
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

        // 阶段1: 端口精确匹配
        if let Some(info) = self.exact_match_probe(&ctx, port).await {
            return info;
        }

        // 阶段2: 端口区域匹配
        if let Some(info) = self.range_match_probe(&ctx, port).await {
            return info;
        }

        // 阶段3: 通用探测
        generic::generic_probe(&ctx).await
    }

    /// 阶段1: 精确端口匹配
    async fn exact_match_probe(&self, ctx: &ProbeContext, port: u16) -> Option<ProtocolInfo> {
        if !has_exact_mapping(port) {
            return None;
        }

        let protocols = get_protocols_for_port(port);
        
        for protocol in protocols {
            if let Some(info) = self.run_probe(ctx, protocol).await {
                return Some(info);
            }
        }

        None
    }

    /// 阶段2: 端口区域匹配
    async fn range_match_probe(&self, ctx: &ProbeContext, port: u16) -> Option<ProtocolInfo> {
        // 先检查特殊区域
        if let Some(probes) = get_special_range_probes(port) {
            for probe in probes {
                if let Some(info) = self.run_probe(ctx, probe).await {
                    return Some(info);
                }
            }
        }

        // 再按端口范围探测
        let range = PortRange::from_port(port);
        let probes = range.default_probes();
        
        for probe in probes {
            if let Some(info) = self.run_probe(ctx, probe).await {
                return Some(info);
            }
        }

        None
    }

    /// 运行单个探针
    async fn run_probe(&self, ctx: &ProbeContext, protocol: &str) -> Option<ProtocolInfo> {
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
}
