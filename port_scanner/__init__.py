"""
port_scanner package initializer

Provides a small public API for CLI invocation and programmatic use.
Keeps imports lazy so `import port_scanner` remains cheap.
"""

from typing import List, Dict, Optional

__all__ = [
    "VERSION",
    "TOP_TCP_PORTS",
    "run_cli",
    "run_scan_sync",
]

# Package version
VERSION = "0.1.0"


def _load_top_ports() -> List[int]:
    """Lazy-load the curated top ports from utils."""
    from .utils import TOP_TCP_PORTS as _TP  # local import to keep top-level cheap
    return list(_TP)


# Exposed constant (evaluated lazily on import)
TOP_TCP_PORTS = _load_top_ports()


def run_cli() -> None:
    """
    Run the CLI entrypoint. Equivalent to `python -m port_scanner.scanner`.
    Useful for console_scripts entrypoints.
    """
    from . import scanner as _scanner  # lazy import
    return _scanner.main()


def run_scan_sync(
    target: str,
    ports: Optional[List[int]] = None,
    timeout: float = 3.0,
    concurrency: int = 500,
) -> List[Dict]:
    """
    Synchronous wrapper to run a scan programmatically.

    Args:
        target: IP or hostname to scan.
        ports: list of integer ports. If None, uses TOP_TCP_PORTS.
        timeout: TCP connect timeout in seconds.
        concurrency: maximum concurrent connections.

    Returns:
        List[dict] - scan results (each dict contains port, status, service, banner)
    """
    from .scanner import run_scan  # lazy import
    import asyncio

    if ports is None:
        ports = list(TOP_TCP_PORTS)

    return asyncio.run(run_scan(target, ports, timeout, concurrency))
