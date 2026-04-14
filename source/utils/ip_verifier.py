"""IP verification utility - checks if proxy actually hides real IP."""

import os
import requests
import subprocess
import time
import socket
import threading
import atexit
import sys
from typing import Tuple, Optional, Dict
from urllib.parse import urlparse
from utils.logger import log

# Global registry for persistent Xray processes with thread-safe locking
_xray_process_registry = []
_xray_registry_lock = threading.Lock()
_original_env_vars = {}  # Save original proxy env vars for restoration

IP_CHECK_URLS = [
    'https://ipwho.is/',
    'https://api.ipify.org?format=json',
    'https://ifconfig.me/ip',
]


def get_real_ip(timeout: float = 5.0) -> Optional[str]:
    """Get external IP without proxy."""
    for url in IP_CHECK_URLS:
        try:
            response = requests.get(url, timeout=timeout)
            if 'ipwho.is' in url:
                return response.json().get('ip')
            elif 'ipify' in url:
                return response.json().get('ip')
            else:
                return response.text.strip()
        except Exception:
            continue
    return None


def get_proxy_ip(proxy_url: str, timeout: float = 5.0) -> Optional[str]:
    """Get external IP through proxy."""
    proxies = {
        'http': proxy_url,
        'https': proxy_url,
    }
    
    for url in IP_CHECK_URLS:
        try:
            response = requests.get(url, proxies=proxies, timeout=timeout)
            if 'ipwho.is' in url:
                return response.json().get('ip')
            elif 'ipify' in url:
                return response.json().get('ip')
            else:
                return response.text.strip()
        except Exception:
            continue
    return None


def verify_protection(proxy_host: str = '127.0.0.1', proxy_port: int = 10808, timeout: float = 5.0) -> Dict:
    """Verify proxy actually hides real IP.
    
    Returns:
        Dict with:
        - active: bool - proxy is working and hiding IP
        - real_ip: str - IP without proxy
        - proxy_ip: str - IP through proxy
        - different: bool - IPs are different
        - country: str - proxy country (if available)
        - error: str - error message if any
    """
    result = {
        'active': False,
        'real_ip': None,
        'proxy_ip': None,
        'different': False,
        'country': None,
        'error': None
    }
    
    try:
        # Get real IP (without proxy)
        result['real_ip'] = get_real_ip(timeout=timeout)
        
        # Get proxy IP
        proxy_url = f"socks5h://{proxy_host}:{proxy_port}"
        result['proxy_ip'] = get_proxy_ip(proxy_url, timeout=timeout)
        
        # Get country info from ipwho.is
        try:
            proxies = {'http': proxy_url, 'https': proxy_url}
            response = requests.get('https://ipwho.is/', proxies=proxies, timeout=timeout)
            data = response.json()
            result['country'] = data.get('country')
        except Exception:
            pass
        
        # Compare IPs
        if result['real_ip'] and result['proxy_ip']:
            result['different'] = result['real_ip'] != result['proxy_ip']
            result['active'] = result['different']
        
        return result
        
    except Exception as e:
        result['error'] = str(e)
        return result



def _cleanup_xray_processes():
    """Cleanup all registered Xray processes (called on exit)."""
    if not _xray_process_registry:
        return
    
    log(f"Cleaning up {len(_xray_process_registry)} Xray process(es)...")
    
    with _xray_registry_lock:
        for tester, process in _xray_process_registry[:]:  # Copy list for safe iteration
            try:
                if process.poll() is None:  # Still running
                    tester.stop_xray_process(process)
            except Exception as e:
                log(f"Warning: Failed to stop Xray process: {e}")
        _xray_process_registry.clear()
    
    log("Xray cleanup complete")


def _wait_for_tcp_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Wait for TCP port to be listening."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            pass
        time.sleep(0.05)
    return False


def _mask_ip(ip: str) -> str:
    """Mask IP address for display (show only country)."""
    if not ip:
        return "***"
    # Show only first octet for IPv4, or just indicate IPv6
    if ':' in ip:
        return "IPv6:***"
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.***.***.***"
    return "***"


def _validate_proxy_security(url: str) -> tuple:
    """Validate proxy has proper encryption. Returns (valid, error_message)."""
    try:
        protocol = url.split('://')[0].lower()
        params = {}
        if '?' in url:
            query = url.split('?')[1].split('#')[0]
            for param in query.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = v
        
        security = params.get('security', 'none')
        
        # VLESS/VMess/Trojan with security=none is insecure
        if protocol in ['vless', 'vmess', 'trojan'] and security == 'none':
            return False, f"{protocol} with security=none transmits data unencrypted"
        
        # REALITY without publicKey is insecure
        if security == 'reality' and not params.get('pbk'):
            return False, "REALITY without publicKey is insecure"
        
        # TLS without SNI may be blocked
        if security == 'tls' and not params.get('sni'):
            return False, "TLS without SNI may be blocked or intercepted"
        
        return True, ""
    except Exception as e:
        return False, f"Validation error: {e}"


def _cleanup_all_processes():
    """Force cleanup of all Xray processes."""
    # Defensive import for atexit scenarios
    import os
    
    # Unset proxy env vars
    for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']:
        os.environ.pop(var, None)
    
    # Stop all Xray processes with verification
    with _xray_registry_lock:
        for tester, process in _xray_process_registry[:]:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=1)
            except Exception:
                pass
        _xray_process_registry.clear()


def _cleanup_proxy():
    """Cleanup proxy resources on exit or error."""
    _cleanup_all_processes()


def setup_global_proxy(proxy_url: str, timeout: float = 8.0) -> Dict:
    """Setup global proxy using a proxy URL (vless://, socks5://, etc.).
    
    For vless://, vmess://, trojan://, ss:// - starts PERSISTENT Xray instance
    For socks5:// - just tests and sets environment variables
    
    Sets environment variables:
        HTTP_PROXY, HTTPS_PROXY, ALL_PROXY
    
    Returns:
        Dict with:
        - active: bool - proxy is working and hiding IP
        - real_ip: str - IP without proxy
        - proxy_ip: str - IP through proxy
        - different: bool - IPs are different
        - country: str - proxy country (if available)
        - error: str - error message if any
        - socks_port: int - local SOCKS port (if Xray was started)
    """
    import os
    
    result = {
        'active': False,
        'real_ip': None,
        'proxy_ip': None,
        'different': False,
        'country': None,
        'error': None,
        'socks_port': None
    }
    
    try:
        # Validate proxy URL
        if not proxy_url or not isinstance(proxy_url, str):
            result['error'] = "Invalid proxy URL"
            return result
        
        if '://' not in proxy_url:
            result['error'] = "Proxy URL must include protocol (e.g., socks5://, vless://)"
            return result
        
        # Save original environment variables for restoration
        global _original_env_vars
        if not _original_env_vars:  # Only save once
            _original_env_vars = {
                'HTTP_PROXY': os.environ.get('HTTP_PROXY'),
                'HTTPS_PROXY': os.environ.get('HTTPS_PROXY'),
                'ALL_PROXY': os.environ.get('ALL_PROXY'),
            }
        
        # Get real IP first (for internal comparison, not displayed)
        result['real_ip'] = get_real_ip(timeout=timeout)
        
        # Parse proxy URL
        parsed = urlparse(proxy_url)
        protocol = parsed.scheme.lower()
        
        if protocol in ['socks5', 'socks5h', 'socks4', 'http', 'https']:
            # Direct proxy - just test and set env vars
            result['proxy_ip'] = get_proxy_ip(proxy_url, timeout=timeout)
            
            # Get country
            try:
                proxies = {'http': proxy_url, 'https': proxy_url}
                response = requests.get('https://ipwho.is/', proxies=proxies, timeout=timeout)
                data = response.json()
                result['country'] = data.get('country')
            except Exception:
                pass
            
            # Set environment variables for all HTTP requests
            os.environ['HTTP_PROXY'] = proxy_url
            os.environ['HTTPS_PROXY'] = proxy_url
            os.environ['ALL_PROXY'] = proxy_url
                
        elif protocol in ['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'hy2']:
            # Need to start PERSISTENT Xray for VPN protocols
            from utils.xray_tester import XrayTester
            from utils.download_xray import ensure_xray_installed
            
            xray_path = ensure_xray_installed()
            if not xray_path:
                result['error'] = "Xray-core not installed"
                return result
            
            tester = XrayTester(xray_path=xray_path)
            socks_port = 24000  # Use persistent proxy port range (24000-24999)
            
            # Create single config
            config = tester.create_single_outbound_config(proxy_url, socks_port)
            if not config:
                result['error'] = "Failed to parse proxy config"
                return result
            
            # Start Xray and KEEP IT RUNNING
            success, process, error = tester.start_xray_instance(config, socks_port, verbose=True)
            if not success:
                result['error'] = f"Failed to start Xray: {error}"
                return result
            
            # Thread-safe registration of Xray process
            with _xray_registry_lock:
                _xray_process_registry.append((tester, process))
            
            # Register cleanup handlers (only once)
            # Signal handlers already registered by xray_tester - avoid conflicts
            if not hasattr(setup_global_proxy, '_cleanup_registered'):
                atexit.register(_cleanup_proxy)
                setup_global_proxy._cleanup_registered = True
            
            result['socks_port'] = socks_port
            
            # Wait for port
            if not tester._wait_for_port(socks_port, timeout=5.0):
                result['error'] = "Xray SOCKS port not listening"
                # Cleanup this failed process
                tester.stop_xray_process(process)
                # Remove from registry
                with _xray_registry_lock:
                    if (tester, process) in _xray_process_registry:
                        _xray_process_registry.remove((tester, process))
                return result
            
            # Test through Xray SOCKS proxy
            socks_url = f"socks5h://127.0.0.1:{socks_port}"
            result['proxy_ip'] = get_proxy_ip(socks_url, timeout=timeout)
            
            # Get country
            try:
                proxies = {'http': socks_url, 'https': socks_url}
                response = requests.get('https://ipwho.is/', proxies=proxies, timeout=timeout)
                data = response.json()
                result['country'] = data.get('country')
            except Exception:
                pass
            
            # Set environment variables pointing to local SOCKS proxy
            os.environ['HTTP_PROXY'] = socks_url
            os.environ['HTTPS_PROXY'] = socks_url
            os.environ['ALL_PROXY'] = socks_url
        else:
            result['error'] = f"Unsupported proxy protocol: {protocol}. Supported: socks5, socks5h, http, vless, vmess, trojan, ss, hysteria2, hy2"
            return result
        
        # Compare IPs
        if result['real_ip'] and result['proxy_ip']:
            result['different'] = result['real_ip'] != result['proxy_ip']
            result['active'] = result['different']
        
        return result
        
    except Exception as e:
        result['error'] = f"{type(e).__name__}: {str(e)}"
        return result



def setup_proxy_chain(proxy_urls: list, timeout: float = 8.0) -> Dict:
    """Setup 2-hop proxy chain using SINGLE Xray instance with dialerProxy (EXPERIMENTAL).
    
    ⚠️  EXPERIMENTAL FEATURE - Proxy chaining is under development
    
    ⚠️  TRANSPORT REQUIREMENT: All hops MUST use WebSocket or HTTPUpgrade (NOT Reality)
    
    Args:
        proxy_urls: List of exactly 2 proxy URLs ['vless://hop1', 'vless://hop2']
        timeout: Connection timeout
    
    Returns:
        Dict with proxy status, final IP, country, socks_port
    """
    import os
    
    result = {
        'active': False,
        'proxy_ip': None,
        'country': None,
        'error': None,
        'socks_port': None,
        'chain_length': len(proxy_urls)
    }
    
    if len(proxy_urls) != 2:
        result['error'] = "Proxy chain requires exactly 2 proxies"
        return result
    
    try:
        # Validate proxy URLs
        VALID_PROTOCOLS = ['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'hy2', 'socks5', 'socks5h']
        for i, url in enumerate(proxy_urls):
            if not url or '://' not in url:
                result['error'] = f"Invalid proxy URL at position {i+1}"
                return result
            
            protocol = url.split('://')[0].lower()
            if protocol not in VALID_PROTOCOLS:
                result['error'] = f"Unsupported protocol '{protocol}' at position {i+1}"
                return result
            
            # Validate encryption security
            valid, error = _validate_proxy_security(url)
            if not valid:
                result['error'] = f"Insecure proxy at position {i+1}: {error}"
                log(f"  WARNING: {error}")
                return result
        
        # Get real IP
        result['real_ip'] = get_real_ip(timeout=timeout)
        if not result['real_ip']:
            result['error'] = "Failed to get real IP"
            return result
        
        log(f"Real IP detected: {_mask_ip(result['real_ip'])}")
        
        # Import XrayTester
        from utils.xray_tester import XrayTester
        from utils.download_xray import ensure_xray_installed
        
        xray_path = ensure_xray_installed()
        if not xray_path:
            result['error'] = "Xray-core not installed"
            return result
        
        ENTRY_SOCKS_PORT = 22000
        
        log(f"Setting up proxy chain (EXPERIMENTAL)...")
        
        # Create chain config
        log("Creating chain config...")
        tester = XrayTester(xray_path=xray_path)
        
        config = tester.create_chain_config(
            proxy_urls=proxy_urls,
            socks_port=ENTRY_SOCKS_PORT
        )
        
        if not config:
            result['error'] = "Failed to create chain config (check transport - Reality not supported)"
            return result
        
        # Start Xray
        log("Starting Xray instance...")
        success, process, error = tester.start_xray_instance(config, ENTRY_SOCKS_PORT, verbose=True)
        if not success:
            result['error'] = f"Xray failed: {error}"
            log(f"  ERROR: {error[:500] if error else 'no error message'}")
            return result
        
        with _xray_registry_lock:
            _xray_process_registry.append((tester, process))
        
        if not tester._wait_for_port(ENTRY_SOCKS_PORT, timeout=3.0):
            result['error'] = "Xray port not listening"
            tester.stop_xray_process(process)
            return result
        
        log(f"  ✓ Xray ready on port {ENTRY_SOCKS_PORT}")
        log("  ✓ Proxy chain started")
        
        socks_url = f"socks5h://127.0.0.1:{ENTRY_SOCKS_PORT}"
        
        # Test chain
        log("Verifying proxy chain...")
        
        # Test hop 1 alone
        log("  Testing hop 1...")
        tester_temp = XrayTester(xray_path=xray_path)
        temp_port = 22999
        config_temp = tester_temp.create_single_outbound_config(proxy_urls[0], temp_port)
        hop1_ip = None
        if config_temp:
            success_temp, process_temp, _ = tester_temp.start_xray_instance(config_temp, temp_port, verbose=False)
            if success_temp and tester_temp._wait_for_port(temp_port, timeout=2.0):
                hop1_ip = get_proxy_ip(f"socks5h://127.0.0.1:{temp_port}", timeout=timeout)
                if hop1_ip:
                    log(f"  ✓ Hop 1 IP: {_mask_ip(hop1_ip)}")
                    result['hop1_ip'] = hop1_ip
                tester_temp.stop_xray_process(process_temp)
        
        # Test full chain
        log("  Testing full chain...")
        from utils.ip_verifier import IP_CHECK_URLS
        chain_success = False
        for url in IP_CHECK_URLS:
            try:
                proxies = {'http': socks_url, 'https': socks_url}
                response = requests.get(url, proxies=proxies, timeout=timeout)
                if 'ipwho.is' in url:
                    data = response.json()
                    result['proxy_ip'] = data.get('ip')
                    result['chain_country'] = data.get('country')
                    result['chain_asn'] = data.get('asn', {}).get('org', '')
                    log(f"  ✓ Chain IP: {_mask_ip(result['proxy_ip'])}")
                    log(f"     Country: {result['chain_country']}, ASN: {result['chain_asn']}")
                    chain_success = True
                    break
                elif 'ipify' in url:
                    result['proxy_ip'] = response.json().get('ip')
                    log(f"  ✓ Chain IP: {_mask_ip(result['proxy_ip'])}")
                    chain_success = True
                    break
                else:
                    result['proxy_ip'] = response.text.strip()
                    log(f"  ✓ Chain IP: {_mask_ip(result['proxy_ip'])}")
                    chain_success = True
                    break
            except requests.exceptions.SSLError as e:
                log(f"  ✗ SSLError: {type(e).__name__}")
                log(f"     This usually means:")
                log(f"     - WebSocket TLS certificate issue")
                log(f"     - Wrong WebSocket host/path in config")
                log(f"     - Proxy config is invalid or expired")
            except requests.exceptions.ProxyError as e:
                log(f"  ✗ Proxy error: {type(e).__name__}")
                log(f"     Xray may not be connecting properly")
            except requests.exceptions.ConnectTimeout as e:
                log(f"  ✗ Connection timeout")
            except requests.exceptions.ConnectionError as e:
                log(f"  ✗ Connection error: {type(e).__name__}")
            except Exception as e:
                log(f"  ✗ Error: {type(e).__name__}: {str(e)[:100]}")
        
        if not chain_success:
            result['error'] = "Failed to get IP through proxy chain"
            tester.stop_xray_process(process)
            return result
        
        # Get hop1 details for comparison
        hop1_details = None
        if hop1_ip:
            try:
                tester_temp2 = XrayTester(xray_path=xray_path)
                config_temp2 = tester_temp2.create_single_outbound_config(proxy_urls[0], temp_port)
                if config_temp2:
                    success_temp2, process_temp2, _ = tester_temp2.start_xray_instance(config_temp2, temp_port, verbose=False)
                    if success_temp2 and tester_temp2._wait_for_port(temp_port, timeout=2.0):
                        hop1_url2 = f"socks5h://127.0.0.1:{temp_port}"
                        proxies = {'http': hop1_url2, 'https': hop1_url2}
                        resp = requests.get('https://ipwho.is/', proxies=proxies, timeout=timeout)
                        hop1_details = resp.json()
                        log(f"  Hop 1 details: {hop1_details.get('country')}, ASN: {hop1_details.get('asn', {}).get('org', '')}")
                    tester_temp2.stop_xray_process(process_temp2)
            except Exception:
                pass
        
        # Compare chain vs hop1
        if hop1_details and result.get('chain_asn'):
            hop1_asn = hop1_details.get('asn', {}).get('org', '')
            chain_asn = result.get('chain_asn', '')
            hop1_country = hop1_details.get('country', '')
            chain_country = result.get('chain_country', '')
            
            if hop1_ip == result['proxy_ip']:
                log(f"  ✗ CRITICAL: Same IP - chain NOT working")
                result['error'] = "Proxy chain broken - hop2 bypassed"
                tester.stop_xray_process(process)
                return result
            elif hop1_asn == chain_asn and hop1_country == chain_country:
                log(f"  ⚠️  WARNING: Same ASN/Country - might be same provider")
                log(f"     This could mean chain is working but both exit same network")
            else:
                log(f"  ✓ Chain appears to be working (different ASN/Country)")
        
        # Get country
        try:
            proxies = {'http': socks_url, 'https': socks_url}
            response = requests.get('https://ipwho.is/', proxies=proxies, timeout=timeout)
            result['country'] = response.json().get('country')
        except Exception:
            pass
        
        # Verify chain hides real IP
        if result['proxy_ip'] == result['real_ip']:
            result['error'] = "Proxy chain is not hiding your real IP!"
            tester.stop_xray_process(process)
            return result
        
        # Verify both hops are used
        if hop1_ip and result['proxy_ip'] and hop1_ip == result['proxy_ip']:
            log(f"  ✗ CRITICAL: Chain exits via hop1 only - hop2 is bypassed!")
            log(f"  ✗ Possible cause: Using Reality protocol (not supported with dialerProxy)")
            result['error'] = "Proxy chain broken - hop2 bypassed. Use WebSocket/HTTPUpgrade, NOT Reality."
            tester.stop_xray_process(process)
            return result
        
        log(f"  ✓ Chain working ({result.get('country', 'Unknown')})")
        
        # Set env vars
        os.environ['HTTP_PROXY'] = socks_url
        os.environ['HTTPS_PROXY'] = socks_url
        os.environ['ALL_PROXY'] = socks_url
        
        result['active'] = True
        result['socks_port'] = ENTRY_SOCKS_PORT
        return result
        
    except Exception as e:
        result['error'] = f"{type(e).__name__}: {str(e)}"
        return result


class ProxyMonitor:
    """Monitor proxy health and prompt for replacement if failed."""
    
    def __init__(self, socks_port: int, real_ip: str, check_interval: int = 30, timeout: float = 5.0):
        self.socks_port = socks_port
        self.real_ip = real_ip  # Store real IP to verify it's hidden
        self.check_interval = check_interval
        self.timeout = timeout
        self.running = False
        self.thread = None
        self.proxy_failed = False
        self.last_check_ok = True
    
    def check_proxy(self) -> bool:
        """Check if proxy is still working AND hiding real IP."""
        try:
            socks_url = f"socks5h://127.0.0.1:{self.socks_port}"
            proxies = {'http': socks_url, 'https': socks_url}
            
            # Check connectivity AND verify real IP is hidden
            response = requests.get('https://ipwho.is/', 
                                   proxies=proxies, 
                                   timeout=self.timeout)
            data = response.json()
            proxy_ip = data.get('ip')
            
            if not proxy_ip:
                log("Monitor: Failed to get IP through proxy")
                return False
            
            # Verify real IP is hidden (compare without logging real IP)
            if proxy_ip == self.real_ip:
                log("Monitor: WARNING - Real IP is exposed!")
                return False
            
            # Success - proxy working and hiding real IP
            if not self.last_check_ok:
                log(f"Monitor: Proxy recovered - IP: {proxy_ip}")
            self.last_check_ok = True
            return True
            
        except requests.exceptions.Timeout:
            if self.last_check_ok:
                log("Monitor: Proxy timeout")
            self.last_check_ok = False
            return False
        except Exception as e:
            if self.last_check_ok:
                log(f"Monitor: Proxy check failed - {type(e).__name__}")
            self.last_check_ok = False
            return False
    
    def prompt_for_new_proxy_chain(self) -> tuple:
        """Prompt user to enter new proxy chain."""
        print("\n" + "="*70)
        print("ENTER NEW PROXY CHAIN")
        print("="*70)
        print("\nEnter TWO proxy URLs for chaining:")
        print("  Hop 1 (entry): Your IP → Proxy 1")
        print("  Hop 2 (exit):  Proxy 1 → Proxy 2 → Internet")
        print("="*70)
        
        while True:
            print("\n--- Hop 1 (Entry Proxy) ---")
            proxy1 = input("Enter first proxy URL (or 'quit' to exit): ").strip()
            
            if proxy1.lower() == 'quit':
                return ('quit', None)
            
            if not proxy1 or '://' not in proxy1:
                print("Invalid format. Use: vless://uuid@host:port")
                continue
            
            print("\n--- Hop 2 (Exit Proxy) ---")
            proxy2 = input("Enter second proxy URL (or 'quit' to exit): ").strip()
            
            if proxy2.lower() == 'quit':
                return ('quit', None)
            
            if not proxy2 or '://' not in proxy2:
                print("Invalid format. Use: vless://uuid@host:port")
                continue
            
            # Test the chain
            print(f"\nTesting proxy chain...")
            result = setup_proxy_chain([proxy1, proxy2], timeout=8.0)
            
            if result['active']:
                print(f"[OK] Proxy chain working ({result.get('country', 'Unknown')})")
                return ('ok', [proxy1, proxy2])
            else:
                print(f"[FAIL] Proxy chain failed: {result.get('error', 'Unknown error')}")
                print("\nTry different proxies. Common issues:")
                print("  • One or both proxies are offline")
                print("  • Proxies don't support chaining")
                print("  • Network connectivity issues")
    
    def monitor_loop(self):
        """Main monitoring loop - stops fetching when proxy fails."""
        while self.running and not self.proxy_failed:
            time.sleep(self.check_interval)
            
            if not self.check_proxy():
                print("\n" + "="*70)
                print("!!! PROXY CHAIN FAILED !!!")
                print("="*70)
                print("\nFetching stopped to prevent IP leaks.")
                print("\nWhat happened:")
                print("  • Proxy chain stopped responding")
                print("  • Config download paused")
                print("\nNext steps:")
                print("  1. Enter new proxy chain (2 proxies) to continue")
                print("  2. Or type 'quit' to exit")
                print("="*70)
                
                self.proxy_failed = True
                
                # Prompt for new proxy chain
                status, new_chain = self.prompt_for_new_proxy_chain()
                
                if status == 'quit':
                    print("\nExiting...")
                    import sys
                    sys.exit(0)  # Allow cleanup
                elif status == 'ok' and new_chain:
                    # New chain is working - continue
                    print("\n✓ Proxy chain restored - resuming fetch...")
                    self.proxy_failed = False
                    self.last_check_ok = True
                    # Continue monitoring with new chain
    
    def _safe_monitor_loop(self):
        """Wrapper for monitor_loop with error handling."""
        try:
            self.monitor_loop()
        except KeyboardInterrupt:
            log("\nMonitor interrupted")
        except Exception as e:
            log(f"Monitor thread crashed: {type(e).__name__}: {str(e)[:100]}")
            self.proxy_failed = True
    
    def start(self):
        """Start monitoring in background thread."""
        self.running = True
        self.thread = threading.Thread(target=self._safe_monitor_loop, daemon=True)
        self.thread.start()
        log(f"Proxy monitor started (checking every {self.check_interval}s)")
    
    def stop(self):
        """Stop monitoring."""
        if not self.running:
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
            if self.thread.is_alive():
                log("Warning: Monitor thread did not stop gracefully")
