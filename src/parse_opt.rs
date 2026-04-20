use structopt::StructOpt;
use std::path::PathBuf;
#[derive(StructOpt, Debug)]
#[structopt(name = "rscan" )]
pub struct Select {
    #[structopt(short, long, help = "输入端口号，例如 80,8080-10000,20311")]
    pub port: Option<String>,
    #[structopt(short, long, help = "输入IP地址, 例如 example.com,1.1.1.1,192.168.0.1/24", conflicts_with = "list")]
    pub input: Option<String>,
    #[structopt(short, long, help = "输入IP文件列表", conflicts_with = "input")]
    pub list: Option<String>,
    #[structopt(short, long, help = "静默一些七七八八的输出。")]
    pub silent: bool,
    #[structopt(short, long, help = "输出到文件。")]
    pub output: Option<PathBuf>,
    #[structopt(short = "j", long, help = "输出 JSON 格式（需配合 -o 使用）", conflicts_with = "xlsx")]
    pub json: bool,
    #[structopt(short = "x", long, help = "输出 XLSX 格式（需配合 -o 使用）", conflicts_with = "json")]
    pub xlsx: bool,
    #[structopt(short = "c", long = "concurrency", default_value = "1000", help = "并发数（批次大小）")]
    pub concurrency: usize,
    #[structopt(long = "initial-timeout-ms", default_value = "300", help = "初探连接超时（毫秒）")]
    pub initial_timeout_ms: u64,
    #[structopt(long = "probe-timeout-ms", default_value = "1500", help = "指纹探测超时（毫秒）")]
    pub probe_timeout_ms: u64,
    #[structopt(long = "connect-retries", default_value = "1", help = "连接重试次数（失败后额外重试）")]
    pub connect_retries: usize,
    #[structopt(short = "r", long = "resume", help = "断点续传：从已有输出中恢复并跳过已完成目标")]
    pub resume: bool,
    #[structopt(long = "debug-log", help = "输出调试日志文件路径")]
    pub debug_log: Option<PathBuf>,
}

#[allow(clippy::items_after_statements, clippy::needless_raw_string_hashes)]
pub fn show_banner() {

    let s = r#"> 
  ____                        
 |  _ \ ___  ___ __ _ _ __    
 | |_) / __|/ __/ _` | '_ \   
 |  _ <\__ \ (_| (_| | | | |  
 |_| \_\___/\___\__,_|_| |_|  

Super fast port scanning tool
"#;

    println!("{}", s);
  let info = r#"--------------------------------------
内部评估版
--------------------------------------"#;
    println!("{}", info);

}