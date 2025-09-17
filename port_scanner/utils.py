"""
Helper utilities for port_scanner
"""
import json
import csv
import socket
from typing import List, Optional

# Curated top TCP ports (small set for quick scans). Expand as needed.
TOP_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    587, 993, 995, 3306, 3389, 5900, 8080
]


def resolve_target(target: str) -> str:
    """
    Resolve domain to IPv4 address, or return the IP if already provided.
    Raises socket.gaierror on failure.
    """
    try:
        # allow passing IP directly
        socket.inet_aton(target)
        return target
    except OSError:
        # not an IPv4 dotted quad - try DNS
        resolved = socket.getaddrinfo(target, None, family=socket.AF_INET)
        if not resolved:
            raise socket.gaierror(f"Could not resolve {target}")
        return resolved[0][4][0]


def save_json(results: List[dict], filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def save_csv(results: List[dict], filename: str):
    fieldnames = ["port", "status", "service", "banner"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "port": r.get("port"),
                "status": r.get("status"),
                "service": r.get("service") or "",
                "banner": (r.get("banner") or "").replace("\n", " ").replace("\r", " ")
            })


# Basic inference from port number or banner (non-exhaustive)
SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    8080: "http-alt",
}


def infer_service(port: int, banner: Optional[str]) -> Optional[str]:
    # try port map first
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    # try banner heuristics
    if banner:
        b = banner.lower()
        if "ssh" in b:
            return "ssh"
        if "http" in b or "apache" in b or "nginx" in b:
            return "http"
        if "smtp" in b:
            return "smtp"
        if "mysql" in b or "mariadb" in b:
            return "mysql"
        if "rdp" in b or "mstsc" in b:
            return "rdp"
    return None
