/// SSH 协议探测器

use super::*;

/// 探测 SSH 服务
pub async fn detect_ssh(ctx: &ProbeContext) -> Option<ProtocolInfo> {
    let mut stream = match ctx.connect_with_timeout().await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // SSH 服务会主动发送版本横幅，我们只需要读取
    let banner = match read_banner_with_timeout(&mut stream, 256, ctx.timeout).await {
        Some(b) => b,
        None => return None,
    };

    // SSH 横幅格式: SSH-2.0-OpenSSH_8.4p1 Ubuntu
    if !banner.starts_with("SSH-") {
        return None;
    }

    // 提取软件信息
    let software = extract_ssh_software(&banner);
    let confidence = 1.0;  // SSH 横幅非常明确

    Some(
        ProtocolInfo::new("ssh", confidence)
            .with_version(&banner.trim())
            .with_details(&software),
    )
}

/// 提取 SSH 软件信息
fn extract_ssh_software(banner: &str) -> String {
    // SSH-2.0-OpenSSH_8.4p1 Ubuntu
    if let Some(software) = banner.splitn(3, '-').nth(2) {
        return software.trim().to_string();
    }
    "Unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ssh_software() {
        assert_eq!(
            extract_ssh_software("SSH-2.0-OpenSSH_8.4p1 Ubuntu\r\n"),
            "OpenSSH_8.4p1 Ubuntu"
        );
        assert_eq!(
            extract_ssh_software("SSH-1.99-OpenSSH_7.4"),
            "OpenSSH_7.4"
        );
    }
}
