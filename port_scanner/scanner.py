#!/usr/bin/env python3
"""
CLI async Port & Service Scanner (mini-nmap clone)
Basic features:
- async TCP connect scan
- banner grabbing (non-intrusive)
- JSON/CSV report export
- configurable concurrency, timeout and port list
"""

import argparse
import asyncio
import socket
from datetime import datetime
from typing import List, Dict, Optional

from .utils import resolve_target, TOP_TCP_PORTS, save_json, save_csv, infer_service

DEFAULT_TIMEOUT = 3.0
DEFAULT_CONCURRENCY = 500


async def try_connect(ip: str, port: int, timeout: float) -> Optional[asyncio.StreamReader]:
    """
    Try to open TCP connection to (ip, port). Return (reader) on success, None on failure.
    """
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        # Don't close writer here — let caller handle it after banner.
        return reader, writer
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float) -> Optional[str]:
    """
    Attempt to read a small banner non-intrusively.
    We set a read timeout and read up to N bytes.
    """
    try:
        # Some services only send banner after connecting; others don't.
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        if data:
            return data.decode(errors="ignore").strip()
        else:
            return None
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def scan_port(semaphore: asyncio.Semaphore, ip: str, port: int, timeout: float) -> Dict:
    """
    Scan a single port with concurrency control.
    Returns a dict with port, status, banner, inferred_service
    """
    async with semaphore:
        result = {"port": port, "status": "closed", "banner": None, "service": None}
        conn = await try_connect(ip, port, timeout)
        if conn:
            reader, writer = conn
            result["status"] = "open"
            banner = await grab_banner(reader, writer, timeout=0.8)  # small additional timeout for banner
            result["banner"] = banner
            result["service"] = infer_service(port, banner)
        return result


async def run_scan(target: str, ports: List[int], timeout: float, concurrency: int) -> List[Dict]:
    ip = resolve_target(target)
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_port(semaphore, ip, p, timeout) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda r: r["port"])


def parse_ports(ports_arg: Optional[str]) -> List[int]:
    """
    Support forms:
      - None => return TOP_TCP_PORTS (small curated list)
      - "22,80,443"
      - "1-1024"
      - "22-25,80,443"
    """
    if not ports_arg:
        return TOP_TCP_PORTS.copy()
    ports = set()
    for part in ports_arg.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_i = int(start)
                end_i = int(end)
                ports.update(range(start_i, end_i + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)


def main():
    parser = argparse.ArgumentParser(description="Mini Port & Service Scanner (async, banner grab)")
    parser.add_argument("target", help="IP or domain to scan")
    parser.add_argument("-p", "--ports", help="Ports (csv or ranges). Example: 22,80,443 or 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="TCP connect timeout (s)")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max concurrent connections")
    parser.add_argument("-o", "--output", help="Output filename prefix (will produce .json and .csv)")
    parser.add_argument("--only-open", action="store_true", help="Show only open ports in CLI output")
    args = parser.parse_args()

    ports = parse_ports(args.ports)

    print(f"[*] Resolving and scanning {args.target} ({len(ports)} ports) with timeout={args.timeout}s concurrency={args.concurrency}")
    start = datetime.utcnow()
    results = asyncio.run(run_scan(args.target, ports, args.timeout, args.concurrency))
    duration = (datetime.utcnow() - start).total_seconds()

    open_ports = [r for r in results if r["status"] == "open"]

    print(f"\n[+] Scan finished in {duration:.2f}s — open ports: {len(open_ports)}\n")
    for r in open_ports if args.only_open else results:
        line = f"Port {r['port']:5d} | {r['status']:6} | Service: {r['service'] or '-'}"
        if r["banner"]:
            line += f" | Banner: {r['banner'][:120]!s}"
        print(line)

    # save reports if requested
    if args.output:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_file = f"{args.output}_{timestamp}.json"
        csv_file = f"{args.output}_{timestamp}.csv"
        save_json(results, json_file)
        save_csv(results, csv_file)
        print(f"\n[+] Reports saved to {json_file} and {csv_file}")
    else:
        # default name
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        save_json(results, f"scan_{timestamp}.json")
        save_csv(results, f"scan_{timestamp}.csv")
        print(f"\n[+] Reports saved to scan_{timestamp}.json and scan_{timestamp}.csv")


if __name__ == "__main__":
    main()
