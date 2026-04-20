# rscan

使用 Rust 编写的高速端口扫描与协议识别工具。

## 项目来源

本项目基于 [ESPortscan](https://github.com/Eonian-Sharp/ESPortscan) 修改与扩展。

## 特性

- 高速两阶段扫描：先进行连接探测，再对开放端口进行协议识别
- 端口表达式灵活：支持 `80`、`8080-8100`、`80,443,8080-8100`，自动去重并排序
- 支持多种输入：单个 IP、CIDR、域名、文件列表
- 支持多种输出：终端表格、JSON、XLSX
- 支持断点续扫：异常中断后可继续
- 支持调试日志输出：便于排查识别与网络问题

## 扫描流程

1. Discovery（快速探测）
2. Validation/Fingerprint（开放端口验证与协议识别）
3. 结果输出（终端 / JSON / XLSX）

默认采用并发批次执行，兼顾扫描速度与稳定性。

## 环境要求

- Rust（建议 stable，且支持 Edition 2024）
- Cargo
- 支持平台：macOS / Linux / Windows

## 构建

```bash
cargo build --release
```

可执行文件位于：

- `target/release/rscan`

## 快速开始

扫描单个目标常用端口（使用内置端口集合）：

```bash
./rscan -i 192.168.1.10
```

扫描指定端口：

```bash
./rscan -i 192.168.1.10 -p 22,80,443,8080-8100
```

扫描 CIDR：

```bash
./rscan -i 192.168.1.0/24 -p 80,443
```

从文件读取目标：

```bash
./rscan -l targets.txt -p 80,443,3306
```

输出 JSON（必须配合 `-o`）：

```bash
./rscan -i example.com -p 80,443 -j -o result
```

输出 XLSX（必须配合 `-o`）：

```bash
./rscan -l targets.txt -x -o report
```

恢复中断任务：

```bash
./rscan -r
```

## 命令行参数

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `-p, --port` | 输入端口表达式，如 `80,443,8080-8100` | 使用内置端口集合 |
| `-i, --input` | 输入目标（域名/IP/CIDR），与 `-l` 互斥 | - |
| `-l, --list` | 输入目标文件路径，与 `-i` 互斥 | - |
| `-s, --silent` | 静默模式，减少输出 | `false` |
| `-o, --output` | 输出文件路径 | - |
| `-j, --json` | 以 JSON 输出（需配合 `-o`） | `false` |
| `-x, --xlsx` | 以 XLSX 输出（需配合 `-o`） | `false` |
| `-c, --concurrency` | 并发批次大小 | `1000` |
| `--initial-timeout-ms` | 初探连接超时（毫秒） | `300` |
| `--probe-timeout-ms` | 指纹探测超时（毫秒） | `1500` |
| `--connect-retries` | 连接失败后的额外重试次数 | `1` |
| `-r, --resume` | 从状态文件恢复扫描 | `false` |
| `--debug-log` | 调试日志输出路径 | - |

说明：

- 非恢复模式下，必须指定 `-i/--input` 或 `-l/--list`。
- `--json` 与 `--xlsx` 互斥。
- 当输出路径未带扩展名时：JSON 自动追加 `.json`，XLSX 自动追加 `.xlsx`。

## 输入格式说明

`-i/--input` 支持：

- 单个 IP：`1.1.1.1`
- CIDR：`192.168.0.0/24`（当前仅展开 IPv4 网段）
- 域名：`example.com`
- 逗号分隔混合输入：`example.com,1.1.1.1,192.168.0.0/24`

`-l/--list` 文件格式：

- 每行一个目标
- 自动忽略空行

## 输出说明

终端输出字段：

- `target`：目标地址（IP:Port）
- `time`：识别时间
- `protocol`：识别协议（未知服务会归类为 `open`）
- `version`：协议或服务版本（若可识别）
- `details`：附加信息（若可识别）
- `confidence`：识别置信度

## 协议识别（当前实现）

已支持并在探测流程中使用的主要类别包括：

- HTTP/HTTPS/TLS
- SSH
- MySQL / PostgreSQL / Redis / MongoDB / Memcached / Elasticsearch
- MQTT / MQTT over TLS
- RMI 等通用探测

注：最终识别结果受目标服务行为、网络环境、超时与重试参数影响。

## 断点续扫

- 程序会维护状态文件：`rscan.resume.json`
- 使用 `-r/--resume` 可从上次中断处继续
- 扫描完成后会自动清理状态文件

## 调试与排障

建议组合：

```bash
./rscan -i 10.0.0.1 -p 22,80,443 --debug-log debug.log
```

常见调优方向：

- 丢包/抖动网络：适当增大 `--initial-timeout-ms`、`--probe-timeout-ms`
- 高延迟网络：适当提高 `--connect-retries`
- 主机性能有限：适当降低 `-c/--concurrency`

## 本地模拟测试

项目提供脚本(仅在Mac下通过测试)：

- `scripts/mock_env_test.sh`

用于快速拉起多协议 mock 环境并执行一次扫描回归。

## 合法使用声明

请仅在获得明确授权的目标范围内使用本工具。使用者需自行遵守当地法律法规与组织安全规范。

## License

本项目采用 MIT License。

## 致谢

- 基于 [ESPortscan](https://github.com/Eonian-Sharp/ESPortscan) 修改。
