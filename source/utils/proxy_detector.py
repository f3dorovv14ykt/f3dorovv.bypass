"""Proxy detection utility - scans common ports for active SOCKS/HTTP proxies."""

import socket
from typing import Optional, Dict, List

COMMON_PROXY_PORTS = [
    10808,  # v2rayN, Hiddify default
    2080,   # NekoRay default
    7890,   # Clash default
    7891,   # Clash alternative
    1080,   # Standard SOCKS
    8080,   # Common HTTP proxy
]


def check_port_open(host: str = '127.0.0.1', port: int = 10808, timeout: float = 0.5) -> bool:
    """Check if proxy port is listening."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def find_active_proxy_port(host: str = '127.0.0.1', ports: List[int] = None) -> Optional[int]:
    """Scan common proxy ports to find active one.
    
    Returns:
        Port number if found, None otherwise
    """
    ports_to_scan = ports or COMMON_PROXY_PORTS
    
    for port in ports_to_scan:
        if check_port_open(host, port):
            return port
    return None


def detect_proxy_type(host: str = '127.0.0.1', port: int = 10808) -> Optional[str]:
    """Detect proxy type by checking port number conventions.
    
    Returns:
        'socks5', 'http', or None
    """
    # Common port conventions
    socks_ports = [10808, 1080, 7891, 2080]
    http_ports = [8080, 7890, 10809, 2081]
    
    if port in socks_ports:
        return 'socks5'
    elif port in http_ports:
        return 'http'
    else:
        # Default to SOCKS5 for unknown ports
        return 'socks5'


def get_proxy_info(host: str = '127.0.0.1') -> Optional[Dict]:
    """Find and return info about active proxy.
    
    Returns:
        Dict with host, port, type, url or None if no proxy found
    """
    port = find_active_proxy_port(host)
    if not port:
        return None
    
    proxy_type = detect_proxy_type(host, port)
    
    return {
        'host': host,
        'port': port,
        'type': proxy_type,
        'url': f"{proxy_type}://{host}:{port}"
    }
