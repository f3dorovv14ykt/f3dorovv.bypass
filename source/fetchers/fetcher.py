"""Fetcher module for downloading VPN configs using curl_cffi for speed."""

import os
import warnings
from curl_cffi import requests
from typing import Optional
from config.settings import CHROME_UA

# Suppress SSL warnings when verify=False
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


def _get_env_proxy() -> Optional[str]:
    """Get proxy from environment variables (set by main.py --proxy arg)."""
    return os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY') or os.environ.get('ALL_PROXY')


def build_session(max_pool_size: int = 4, proxy_url: Optional[str] = None):
    """Builds a requests session with proper proxy support.
    
    Args:
        max_pool_size: Connection pool size
        proxy_url: Optional proxy URL (e.g., 'socks5h://127.0.0.1:10808').
                    If not provided, checks environment variables.
    """
    import requests as std_requests
    from requests.adapters import HTTPAdapter
    
    # Use provided proxy or fall back to environment variable
    effective_proxy = proxy_url or _get_env_proxy()
    
    # Always use standard requests for better SOCKS support
    session = std_requests.Session()
    
    # Configure proxy if present
    if effective_proxy:
        session.proxies = {
            'http': effective_proxy,
            'https': effective_proxy,
        }
    
    # Configure connection pooling
    adapter = HTTPAdapter(pool_connections=max_pool_size, pool_maxsize=max_pool_size)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    session.headers.update({"User-Agent": CHROME_UA})
    return session


def fetch_data(url: str, timeout: int = 7, max_attempts: int = 3, session=None, proxy_url: Optional[str] = None) -> str:
    """Fetches data from URL with retry logic and fallbacks.
    
    Args:
        url: URL to fetch
        timeout: Request timeout in seconds (default: 7)
        max_attempts: Number of retry attempts
        session: Optional existing session
        proxy_url: Optional proxy URL for routing request.
                  If not provided, uses environment variable (set by --proxy arg).
    
    Note: Uses standard requests library for SOCKS proxies.
    """
    # Use provided proxy or fall back to environment
    effective_proxy = proxy_url or _get_env_proxy()
    
    sess = session or build_session(max_pool_size=4, proxy_url=effective_proxy)
    
    for attempt in range(1, max_attempts + 1):
        try:
            modified_url = url
            verify = True
            
            if attempt == 2:
                verify = False
            elif attempt == 3:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.scheme == "https":
                    modified_url = parsed._replace(scheme="http").geturl()
                verify = False
            
            response = sess.get(
                modified_url,
                timeout=timeout,
                verify=verify,
                allow_redirects=True,
            )
            response.raise_for_status()
            return response.text
            
        except Exception as exc:
            last_exc = exc
            if attempt < max_attempts:
                continue
            raise last_exc