#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RSCAN_BIN="${RSCAN_BIN:-./target/debug/rscan}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
CONCURRENCY="${CONCURRENCY:-400}"
INITIAL_TIMEOUT_MS="${INITIAL_TIMEOUT_MS:-600}"
PROBE_TIMEOUT_MS="${PROBE_TIMEOUT_MS:-2500}"
CONNECT_RETRIES="${CONNECT_RETRIES:-1}"
SKIP_BUILD="${SKIP_BUILD:-0}"

# if [[ "$SKIP_BUILD" != "1" ]]; then
#   echo "[INFO] building rscan..."
#   cargo build -q
# fi

if [[ ! -x "$RSCAN_BIN" ]]; then
  echo "[ERROR] rscan binary not found or not executable: $RSCAN_BIN"
  echo "[HINT] set RSCAN_BIN=/path/to/rscan or run with SKIP_BUILD=0"
  exit 1
fi

# We simulate MSSQL on 1433 and 11433. 101433 is not a valid TCP port (max 65535).
python3 - <<'PY'
import asyncio
import os
import sys
from datetime import datetime

HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
RSCAN_BIN = os.environ.get("RSCAN_BIN", "./target/debug/rscan")
CONCURRENCY = os.environ.get("CONCURRENCY", "400")
INITIAL_TIMEOUT_MS = os.environ.get("INITIAL_TIMEOUT_MS", "600")
PROBE_TIMEOUT_MS = os.environ.get("PROBE_TIMEOUT_MS", "2500")
CONNECT_RETRIES = os.environ.get("CONNECT_RETRIES", "1")

SERVICES = {
    18080: ("http-mock", "expect http"),
    28080: ("http-alt-mock", "expect http"),
    18443: ("tls-mock", "expect tls"),
    2222: ("ssh-alt-mock", "expect ssh"),
    2020: ("ftp-banner-mock", "expect ftp (banner)"),
    6379: ("redis-mock", "expect redis"),
    16379: ("redis-alt-mock", "usually open/unknown"),
    18883: ("mqtt-mock", "expect mqtt"),
    3306: ("mysql-mock", "expect mysql"),
    13306: ("mysql-alt-mock", "expect mysql (banner)"),
    5432: ("postgres-ssl-mock", "expect postgresql"),
    15432: ("postgres-alt-mock", "usually open/unknown"),
    11211: ("memcached-mock", "expect memcached"),
    9200: ("elasticsearch-mock", "expect elasticsearch"),
    19200: ("elasticsearch-alt-mock", "expect elasticsearch"),
    1433: ("mssql-like-banner-mock", "open (no mssql detector yet)"),
    11433: ("mssql-like-banner-mock", "open (no mssql detector yet)"),
}


async def http_handler(reader, writer):
    try:
        await reader.read(2048)
        body = b"OK"
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: mock-http\r\n"
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        writer.write(resp)
        await writer.drain()
    finally:
        await safe_close(writer)


async def elastic_handler(reader, writer):
    try:
        await reader.read(2048)
        body = b'{"cluster_name":"mock-es","tagline":"You Know, for Search"}'
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        writer.write(resp)
        await writer.drain()
    finally:
        await safe_close(writer)


async def tls_handler(reader, writer):
    try:
        await reader.read(1024)
        # Fake TLS ServerHello prefix that detector accepts.
        writer.write(bytes([0x16, 0x03, 0x03, 0x00, 0x2a]) + b"MOCKTLS")
        await writer.drain()
    finally:
        await safe_close(writer)


async def ssh_handler(reader, writer):
    try:
        writer.write(b"SSH-2.0-OpenSSH_9.8p1 Mock\r\n")
        await writer.drain()
        await reader.read(256)
    finally:
        await safe_close(writer)


async def ftp_handler(reader, writer):
    try:
        writer.write(b"220 (vsFTPd 3.0.5) FTP service ready\r\n")
        await writer.drain()
        await reader.read(256)
    finally:
        await safe_close(writer)


async def redis_handler(reader, writer):
    try:
        await reader.read(512)
        writer.write(b"+PONG\r\n")
        await writer.drain()
    finally:
        await safe_close(writer)


async def mqtt_handler(reader, writer):
    try:
        await reader.read(1024)
        writer.write(bytes([0x20, 0x02, 0x00, 0x00]))  # CONNACK accepted
        await writer.drain()
    finally:
        await safe_close(writer)


async def mysql_handler(reader, writer):
    try:
        # Send MySQL-like handshake banner containing mysql_native_password
        payload = b"\x0a8.0.36-mock\x00mysql_native_password\x00"
        writer.write(payload)
        await writer.drain()
        await reader.read(1024)
    finally:
        await safe_close(writer)


async def postgres_handler(reader, writer):
    try:
        await reader.read(64)
        writer.write(b"S")  # SSLRequest response
        await writer.drain()
    finally:
        await safe_close(writer)


async def memcached_handler(reader, writer):
    try:
        data = await reader.read(512)
        if b"stats" in data.lower():
            writer.write(b"STAT pid 123\r\nEND\r\n")
        else:
            writer.write(b"ERROR\r\n")
        await writer.drain()
    finally:
        await safe_close(writer)


async def banner_handler(reader, writer):
    try:
        writer.write(b"MSSQL-MOCK-BANNER\r\n")
        await writer.drain()
        await reader.read(512)
    finally:
        await safe_close(writer)


async def safe_close(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        pass


HANDLERS = {
    18080: http_handler,
    28080: http_handler,
    18443: tls_handler,
    2222: ssh_handler,
    2020: ftp_handler,
    6379: redis_handler,
    16379: redis_handler,
    18883: mqtt_handler,
    3306: mysql_handler,
    13306: mysql_handler,
    5432: postgres_handler,
    15432: postgres_handler,
    11211: memcached_handler,
    9200: elastic_handler,
    19200: elastic_handler,
    1433: banner_handler,
    11433: banner_handler,
}


async def start_servers():
    servers = []
    for port, handler in HANDLERS.items():
        srv = await asyncio.start_server(handler, HOST, port)
        servers.append(srv)
    return servers


async def stop_servers(servers):
    for s in servers:
        s.close()
    for s in servers:
        await s.wait_closed()


def print_matrix():
    print("[MOCK] Service Matrix")
    print("[MOCK] 101433 -> invalid TCP port; using 11433 as mssql-like mock")
    for port in sorted(SERVICES):
        name, expectation = SERVICES[port]
        print(f"[MOCK] {HOST}:{port:<5} {name:<26} {expectation}")


async def run_scan():
    port_arg = ",".join(str(p) for p in sorted(SERVICES.keys()))
    cmd = [
        RSCAN_BIN,
        "-i", HOST,
        "-p", port_arg,
        "--initial-timeout-ms", INITIAL_TIMEOUT_MS,
        "--probe-timeout-ms", PROBE_TIMEOUT_MS,
        "--connect-retries", CONNECT_RETRIES,
        "-c", CONCURRENCY,
    ]

    print("[MOCK] Running:", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    print("===== rscan output begin =====")
    print(out.decode(errors="replace"))
    print("===== rscan output end =====")
    return proc.returncode


async def main():
    print(f"[MOCK] start at {datetime.now().isoformat(timespec='seconds')}")
    servers = await start_servers()
    try:
        print_matrix()
        code = await run_scan()
        if code != 0:
            print(f"[MOCK] rscan exited with code {code}", file=sys.stderr)
            sys.exit(code)
    finally:
        await stop_servers(servers)
        print("[MOCK] servers stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[MOCK] interrupted")
        sys.exit(130)
PY