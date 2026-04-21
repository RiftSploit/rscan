use rscan::ip_ext::input_file;
use rscan::ip_ext::input_ip;
use rscan::ip_ext::resolve_ips;
use structopt::StructOpt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use rscan::port_db::{parse_ports_v2, MERGED_PORTS};
use std::sync::Arc;
use rscan::parse_opt::{self, show_banner};
use rscan::scanner::{
    OutputFormat, ResumeConfig, Scanner, create_resume_state, default_resume_state_path,
    load_resume_state, pending_sockets, save_resume_state,
};
use tokio::time::Instant;

#[tokio::main]
async fn main() -> io::Result<()> {


    let opt = parse_opt::Select::from_args();
    let output_format = if opt.json {
        OutputFormat::Json
    } else if opt.xlsx {
        OutputFormat::Xlsx
    } else {
        OutputFormat::Text
    };

    if (opt.json || opt.xlsx) && opt.output.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "使用 --json/--xlsx 时必须同时指定 -o 输出文件",
        ));
    }

    if opt.resume && opt.output.is_none() {
        // resume 逻辑将以临时状态文件中的配置为准，这里不强制要求 -o。
    }

    let resume_path = default_resume_state_path();

    if opt.resume {
        let state = load_resume_state(&resume_path).map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("未找到可恢复的状态文件 {}: {}", resume_path.display(), e),
            )
        })?;

        if !state.config.silent {
            show_banner();
            println!("检测到恢复状态文件: {}", resume_path.display());
        }

        let pending = pending_sockets(&state);
        let start_time = Instant::now();
        let scanner = Arc::new(Scanner::new(state, resume_path.clone(), true)?);
        scanner.run(pending).await;
        let duration = start_time.elapsed();
        if !opt.silent {
            println!("{}\n恢复扫描完成，总耗时: {:.2?} 秒", "-".repeat(30), duration);
        }
        return Ok(());
    }

    if opt.input.is_none() && opt.list.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "非恢复模式下，必须指定 -i/--input 或 -l/--list 之一",
        ));
    }

    if !opt.silent {
        show_banner();
    }

    let start_time = Instant::now();
    let i = if opt.input.clone().is_some() { input_ip(opt.input) } else { input_file(opt.list).await };
    let i = resolve_ips(i).await;
    let assets = i.clone();
    let o = if opt.port.is_some() { parse_ports_v2(opt.port) } else { MERGED_PORTS.clone() };

    let sockets: Vec<SocketAddr> = i
        .into_iter()
        .flat_map(|ip| {
            let ip: IpAddr = ip.parse().unwrap();
            o.iter().cloned().map(move |port| SocketAddr::new(ip, port))
        })
        .collect();

    let resume_config = ResumeConfig {
        output_path: opt.output,
        output_format,
        concurrency: opt.concurrency,
        initial_timeout_ms: opt.initial_timeout_ms,
        probe_timeout_ms: opt.probe_timeout_ms,
        connect_retries: opt.connect_retries,
        assets,
        ports: o,
        silent: opt.silent,
        debug_log_path: opt.debug_log,
    };

    let state = create_resume_state(resume_config, &sockets);
    save_resume_state(&resume_path, &state)?;

    let scanner = Arc::new(Scanner::new(state, resume_path, false)?);
    scanner.run(sockets).await;
    let duration = start_time.elapsed();
    if !opt.silent {println!("{}\n扫描完成，总耗时: {:.2?} 秒", "-".repeat(30), duration);}

    Ok(())

    
}