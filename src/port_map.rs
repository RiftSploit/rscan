/// 端口到协议的精确映射表
/// 根据端口号直接选择对应的协议探针

use std::collections::HashMap;
use once_cell::sync::Lazy;

/// 端口精确映射
pub static PORT_PROTOCOL_MAP: Lazy<HashMap<u16, Vec<&'static str>>> = Lazy::new(|| {
    let mut map = HashMap::new();
    
    // 常见服务端口 (1-1023)
    map.insert(20, vec!["ftp-data"]);
    map.insert(21, vec!["ftp"]);
    map.insert(22, vec!["ssh"]);
    map.insert(23, vec!["telnet"]);
    map.insert(25, vec!["smtp"]);
    map.insert(53, vec!["dns"]);  // UDP/TCP
    map.insert(79, vec!["finger"]);
    map.insert(80, vec!["http"]);
    map.insert(81, vec!["http"]);
    map.insert(88, vec!["kerberos"]);
    map.insert(110, vec!["pop3"]);
    map.insert(111, vec!["rpc"]);
    map.insert(113, vec!["ident"]);
    map.insert(119, vec!["nntp"]);
    map.insert(135, vec!["msrpc"]);
    map.insert(139, vec!["netbios"]);
    map.insert(143, vec!["imap"]);
    map.insert(161, vec!["snmp"]);  // UDP
    map.insert(179, vec!["bgp"]);
    map.insert(389, vec!["ldap"]);
    map.insert(443, vec!["tls", "https"]);
    map.insert(445, vec!["smb"]);
    map.insert(465, vec!["smtps", "tls"]);
    map.insert(515, vec!["lpd"]);
    map.insert(587, vec!["smtp-tls"]);
    map.insert(631, vec!["ipp", "cups"]);
    map.insert(636, vec!["ldaps", "tls"]);
    map.insert(873, vec!["rsync"]);
    map.insert(902, vec!["vmware"]);
    map.insert(993, vec!["imaps", "tls"]);
    map.insert(995, vec!["pop3s", "tls"]);
    
    // 注册端口 (1024-49151)
    map.insert(1080, vec!["socks5"]);
    map.insert(1098, vec!["rmi", "jrmi"]);
    map.insert(1099, vec!["rmi", "jrmi"]);
    map.insert(1194, vec!["openvpn"]);
    map.insert(1433, vec!["mssql"]);
    map.insert(1434, vec!["mssql-browser"]);
    map.insert(1521, vec!["oracle"]);
    map.insert(1604, vec!["citrix"]);
    map.insert(1723, vec!["pptp"]);
    map.insert(1883, vec!["mqtt"]);
    map.insert(2049, vec!["nfs"]);
    map.insert(2082, vec!["cpanel", "http"]);
    map.insert(2083, vec!["cpanel-ssl", "tls", "http"]);
    map.insert(2086, vec!["whm", "http"]);
    map.insert(2087, vec!["whm-ssl", "tls", "http"]);
    map.insert(2100, vec!["oracle-xmldb", "http"]);
    map.insert(2181, vec!["zookeeper"]);
    map.insert(2222, vec!["ssh-alt", "http"]);
    map.insert(2375, vec!["docker-api", "http"]);
    map.insert(2376, vec!["docker-tls", "tls", "http"]);
    map.insert(2379, vec!["etcd", "http"]);
    map.insert(3000, vec!["http", "dev"]);
    map.insert(3128, vec!["squid", "http"]);
    map.insert(3306, vec!["mysql"]);
    map.insert(3307, vec!["mysql-alt"]);
    map.insert(3389, vec!["rdp"]);
    map.insert(3690, vec!["svn"]);
    map.insert(4000, vec!["http-alt"]);
    map.insert(4440, vec!["rundeck", "http"]);
    map.insert(4444, vec!["metasploit"]);
    map.insert(4848, vec!["glassfish", "http"]);
    map.insert(5000, vec!["http", "upnp"]);
    map.insert(5060, vec!["sip"]);
    map.insert(5432, vec!["postgresql"]);
    map.insert(5555, vec!["adb", "http"]);
    map.insert(5601, vec!["kibana", "http"]);
    map.insert(5671, vec!["rabbitmq-amqps", "tls", "amqp"]);
    map.insert(5672, vec!["rabbitmq-amqp", "amqp"]);
    map.insert(5900, vec!["vnc", "rfb"]);
    map.insert(5984, vec!["couchdb", "http"]);
    map.insert(5985, vec!["winrm", "http"]);
    map.insert(6000, vec!["x11"]);
    map.insert(61616, vec!["activemq-openwire"]);
    map.insert(6379, vec!["redis"]);
    map.insert(6443, vec!["kubernetes", "tls", "http"]);
    map.insert(6881, vec!["bittorrent"]);
    map.insert(6969, vec!["bittorrent-tracker", "http"]);
    map.insert(7001, vec!["weblogic", "http"]);
    map.insert(7002, vec!["weblogic-ssl", "tls", "http"]);
    map.insert(7070, vec!["http-alt"]);
    map.insert(7077, vec!["weblogic", "http"]);
    map.insert(7443, vec!["https-alt", "tls", "http"]);
    map.insert(8000, vec!["http-alt"]);
    map.insert(8008, vec!["http-alt"]);
    map.insert(8009, vec!["ajp"]);
    map.insert(8080, vec!["http-proxy", "http"]);
    map.insert(8081, vec!["http-alt"]);
    map.insert(8082, vec!["http-alt"]);
    map.insert(8083, vec!["http", "vestacp"]);
    map.insert(8084, vec!["http-alt"]);
    map.insert(8085, vec!["http-alt"]);
    map.insert(8086, vec!["influxdb", "http"]);
    map.insert(8087, vec!["http-alt"]);
    map.insert(8088, vec!["influxdb-rpc", "http"]);
    map.insert(8089, vec!["http-alt"]);
    map.insert(8090, vec!["http-alt"]);
    map.insert(8161, vec!["activemq-web", "http"]);
    map.insert(8180, vec!["tomcat", "http"]);
    map.insert(8443, vec!["https-alt", "tls", "http"]);
    map.insert(8484, vec!["http-alt"]);
    map.insert(8649, vec!["ganglia", "http"]);
    map.insert(8880, vec!["http-alt"]);
    map.insert(8883, vec!["mqtt-tls", "tls", "mqtt"]);
    map.insert(8888, vec!["http-alt"]);
    map.insert(8899, vec!["http-alt"]);
    map.insert(9000, vec!["sonarqube", "http"]);
    map.insert(9001, vec!["tor", "http"]);
    map.insert(9042, vec!["cassandra"]);
    map.insert(9090, vec!["prometheus", "http"]);
    map.insert(9100, vec!["node-exporter", "http"]);
    map.insert(9200, vec!["elasticsearch", "http"]);
    map.insert(9300, vec!["es-transport"]);
    map.insert(9418, vec!["git"]);
    map.insert(9443, vec!["https-alt", "tls", "http"]);
    map.insert(9500, vec!["ismap", "http"]);
    map.insert(9999, vec!["http-alt"]);
    map.insert(10000, vec!["webmin", "http"]);
    map.insert(10050, vec!["zabbix-agent"]);
    map.insert(10051, vec!["zabbix-server"]);
    map.insert(10250, vec!["kubelet", "tls", "http"]);
    map.insert(10443, vec!["https-alt", "tls", "http"]);
    map.insert(11211, vec!["memcached"]);
    map.insert(12018, vec!["http-alt"]);
    map.insert(15672, vec!["rabbitmq-mgmt", "http"]);
    
    // 高位端口 (49152+)
    map.insert(18000, vec!["http", "iot"]);
    map.insert(18080, vec!["http-alt"]);
    map.insert(20000, vec!["usermin", "http"]);
    map.insert(20443, vec!["vmware", "tls", "http"]);
    map.insert(20720, vec!["http-alt"]);
    map.insert(27017, vec!["mongodb"]);
    map.insert(27018, vec!["mongodb-shard"]);
    map.insert(27019, vec!["mongodb-config"]);
    map.insert(28017, vec!["mongodb-http", "http"]);
    map.insert(3060, vec!["idap"]);
    map.insert(3061, vec!["idaps", "tls"]);
    
    map
});

/// 根据端口获取协议列表
pub fn get_protocols_for_port(port: u16) -> Vec<&'static str> {
    PORT_PROTOCOL_MAP
        .get(&port)
        .cloned()
        .unwrap_or_default()
}

/// 检查端口是否在精确映射表中
pub fn has_exact_mapping(port: u16) -> bool {
    PORT_PROTOCOL_MAP.contains_key(&port)
}

/// 端口区域分类
pub enum PortRange {
    WellKnown,      // 1-1023
    Registered,     // 1024-49151
    Dynamic,        // 49152-65535
}

impl PortRange {
    pub fn from_port(port: u16) -> Self {
        match port {
            1..=1023 => PortRange::WellKnown,
            1024..=49151 => PortRange::Registered,
            _ => PortRange::Dynamic,
        }
    }
    
    /// 获取该区域的默认探测序列
    pub fn default_probes(&self) -> Vec<&'static str> {
        match self {
            PortRange::WellKnown => vec![
                "http", "tls", "dns", "ssh", "ftp", "smtp", "smb", "generic-banner",
            ],
            PortRange::Registered => vec![
                "http", "tls", "ftp", "mysql", "postgresql", "redis", "memcached",
                "mongodb", "elasticsearch", "mqtt", "rabbitmq-amqp", 
                "influxdb", "zookeeper", "generic-banner",
            ],
            PortRange::Dynamic => vec![
                "http", "tls", "generic-banner", "raw-tcp",
            ],
        }
    }
}

/// 特殊服务密集区
pub fn get_special_range_probes(port: u16) -> Option<Vec<&'static str>> {
    match port {
        1389 => Some(vec!["ldap", "tls", "generic-banner"]),
        8000..=8999 => Some(vec!["http", "tls", "ajp"]),
        9000..=9999 => Some(vec!["http", "elasticsearch", "kibana", "prometheus"]),
        10000..=10999 => Some(vec!["http", "webmin", "usermin"]),
        16000..=16999 => Some(vec!["http", "tls", "generic-banner"]),  // IoT 通用探测
        20000..=20999 => Some(vec!["http", "generic-banner"]),
        27000..=27999 => Some(vec!["mongodb", "http"]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_mapping() {
        assert!(has_exact_mapping(80));
        assert!(has_exact_mapping(443));
        assert!(has_exact_mapping(3306));
        assert!(!has_exact_mapping(u16::MAX));
    }

    #[test]
    fn test_port_range() {
        assert!(matches!(PortRange::from_port(80), PortRange::WellKnown));
        assert!(matches!(PortRange::from_port(8080), PortRange::Registered));
        assert!(matches!(PortRange::from_port(50000), PortRange::Dynamic));
    }

    #[test]
    fn test_special_ranges() {
        assert!(get_special_range_probes(8080).is_some());
        assert!(get_special_range_probes(9200).is_some());
        let ldap_alt = get_special_range_probes(1389).unwrap_or_default();
        assert!(ldap_alt.contains(&"ldap"));
        assert!(get_special_range_probes(3389).is_none());
        assert!(get_special_range_probes(2000).is_none());
        assert!(get_special_range_probes(18000).is_none());
        assert!(get_special_range_probes(12345).is_none());
    }

    #[test]
    fn test_wellknown_range_includes_dns_probe() {
        let probes = PortRange::WellKnown.default_probes();
        assert!(probes.contains(&"dns"), "well-known range should include dns for broad <=10k probing");
    }
}
