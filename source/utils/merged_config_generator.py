"""Merged config generator for Xray - tests multiple proxies with single process."""

import os
import json
import tempfile
import threading
import time
import socket
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
import base64
from utils.logger import log


class MergedConfigGenerator:
    """Generate merged Xray configs for parallel testing.
    
    Creates single Xray config with multiple inbounds/outbounds.
    Each inbound listens on unique local port, routed to corresponding outbound.
    Allows testing 50-100 proxies with single Xray process.
    """
    
    BASE_PORT = 21000
    MAX_PROXIES_PER_CONFIG = 100
    
    def __init__(self):
        self._port_lock = threading.Lock()
        self._last_port = self.BASE_PORT
    
    def _get_sequential_ports(self, count: int) -> List[int]:
        """Get sequential ports for inbounds."""
        with self._port_lock:
            ports = list(range(self._last_port + 1, self._last_port + 1 + count))
            self._last_port = ports[-1]
            if self._last_port > self.BASE_PORT + 1000:
                self._last_port = self.BASE_PORT
            return ports
    
    def _is_port_available(self, port: int) -> bool:
        """Check if port is available."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', port))
            sock.close()
            return True
        except Exception:
            return False
    
    def _parse_vless(self, url: str) -> Optional[Dict]:
        """Parse VLESS URL to outbound settings."""
        try:
            url_part = url.replace('vless://', '', 1)
            if '#' in url_part:
                url_part = url_part.split('#', 1)[0]
            
            if '?' in url_part:
                base_part, query_part = url_part.split('?', 1)
            else:
                base_part = url_part
                query_part = ''
            
            if '@' not in base_part:
                return None
            
            uuid, host_port = base_part.rsplit('@', 1)
            if ':' not in host_port:
                return None
            
            hostname, port_str = host_port.rsplit(':', 1)
            port_str = port_str.strip().rstrip('/')
            
            try:
                port = int(port_str)
            except:
                return None
            
            params = parse_qs(query_part)
            security = params.get('security', ['none'])[0] if params.get('security') else 'none'
            
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": hostname,
                        "port": port,
                        "users": [{
                            "id": uuid,
                            "encryption": params.get('encryption', ['none'])[0],
                            "flow": params.get('flow', [''])[0]
                        }]
                    }]
                },
                "streamSettings": {
                    "network": params.get('type', ['tcp'])[0],
                    "security": security
                }
            }
            
            if security == 'tls':
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get('sni', [hostname])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0]
                }
            elif security == 'reality':
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": params.get('sni', [''])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0],
                    "publicKey": params.get('pbk', [''])[0],
                    "shortId": params.get('sid', [''])[0]
                }
            
            transport = params.get('type', ['tcp'])[0]
            if transport == 'ws':
                outbound["streamSettings"]["wsSettings"] = {
                    "path": unquote(params.get('path', ['/'])[0]),
                    "headers": {"Host": unquote(params.get('host', [hostname])[0])}
                }
            elif transport == 'grpc':
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": unquote(params.get('serviceName', [''])[0])
                }
            
            return outbound
        except Exception:
            return None
    
    def _parse_vmess(self, url: str) -> Optional[Dict]:
        """Parse VMess URL to outbound settings."""
        try:
            encoded = url.replace('vmess://', '').strip()
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += '=' * padding
            
            try:
                decoded_bytes = base64.b64decode(encoded)
            except:
                return None
            
            try:
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
            except:
                return None
            
            try:
                data = json.loads(decoded)
            except:
                return None
            
            if not data.get('add') or not data.get('port') or not data.get('id'):
                return None
            
            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": str(data.get('add', '')),
                        "port": int(data.get('port', 443)),
                        "users": [{
                            "id": str(data.get('id', '')),
                            "alterId": int(data.get('aid', 0)),
                            "security": data.get('scy', 'auto')
                        }]
                    }]
                },
                "streamSettings": {
                    "network": data.get('net', 'tcp'),
                    "security": 'tls' if data.get('tls') == 'tls' else 'none'
                }
            }
        except Exception:
            return None
    
    def _parse_trojan(self, url: str) -> Optional[Dict]:
        """Parse Trojan URL to outbound settings."""
        try:
            url_part = url.replace('trojan://', '', 1)
            if '#' in url_part:
                url_part = url_part.split('#', 1)[0]
            
            if '@' not in url_part:
                return None
            
            password, host_port = url_part.rsplit('@', 1)
            if ':' not in host_port:
                return None
            
            hostname, port_str = host_port.rsplit(':', 1)
            port_str = port_str.strip().rstrip('/')
            
            try:
                port = int(port_str)
            except:
                return None
            
            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": hostname,
                        "port": port,
                        "password": password
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {"serverName": hostname}
                }
            }
        except Exception:
            return None
    
    def _parse_shadowsocks(self, url: str) -> Optional[Dict]:
        """Parse Shadowsocks URL to outbound settings."""
        try:
            url_part = url.replace('ss://', '', 1)
            if '#' in url_part:
                url_part = url_part.split('#', 1)[0]
            
            method = 'chacha20-poly1305'
            password = ''
            hostname = None
            port = None
            
            try:
                padding = 4 - len(url_part) % 4
                if padding != 4:
                    url_part += '=' * padding
                
                decoded = base64.urlsafe_b64decode(url_part).decode('utf-8', errors='ignore')
                
                if '@' in decoded:
                    userinfo, server = decoded.rsplit('@', 1)
                    if ':' in userinfo:
                        method, password = userinfo.split(':', 1)
                    
                    if ':' in server:
                        hostname, port_str = server.rsplit(':', 1)
                        port_str = port_str.strip().rstrip('/')
                        port = int(port_str)
                    else:
                        hostname = server
                        port = 443
            except:
                pass
            
            if not hostname:
                if '@' in url_part:
                    userinfo, server = url_part.rsplit('@', 1)
                    if ':' in server:
                        hostname, port_str = server.rsplit(':', 1)
                        port_str = port_str.strip().rstrip('/')
                        try:
                            port = int(port_str)
                        except:
                            port = 443
            
            if not hostname:
                return None
            
            if not port:
                port = 443
            
            if not password:
                password = 'password'
            
            return {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": str(hostname),
                        "port": int(port),
                        "password": str(password),
                        "method": str(method)
                    }]
                }
            }
        except Exception:
            return None
    
    def _url_to_outbound(self, url: str) -> Optional[Dict]:
        """Convert URL to outbound based on protocol."""
        protocol_parsers = {
            'vless://': self._parse_vless,
            'vmess://': self._parse_vmess,
            'trojan://': self._parse_trojan,
            'ss://': self._parse_shadowsocks,
        }
        
        for prefix, parser in protocol_parsers.items():
            if url.startswith(prefix):
                return parser(url)
        
        return None
    
    def generate_merged_config(self, urls: List[str], base_port: int = None) -> Optional[Tuple[Dict, List[int]]]:
        """Generate merged Xray config for multiple URLs.
        
        Args:
            urls: List of proxy URLs to test
            base_port: Starting port for inbounds (optional)
        
        Returns:
            Tuple of (config_dict, list_of_ports) or None if failed
        """
        if not urls:
            return None
        
        if len(urls) > self.MAX_PROXIES_PER_CONFIG:
            urls = urls[:self.MAX_PROXIES_PER_CONFIG]
        
        if base_port is None:
            ports = self._get_sequential_ports(len(urls))
            base_port = ports[0] - 1
        else:
            ports = list(range(base_port + 1, base_port + 1 + len(urls)))
        
        inbounds = []
        outbounds = []
        routing_rules = []
        
        for i, (url, port) in enumerate(zip(urls, ports)):
            outbound = self._url_to_outbound(url)
            if not outbound:
                log(f"Failed to parse URL: {url[:50]}")
                continue
            
            inbound_tag = f"socks_{port}"
            outbound_tag = f"proxy_{i}"
            
            inbound = {
                "tag": inbound_tag,
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True}
            }
            
            outbound["tag"] = outbound_tag
            
            rule = {
                "type": "field",
                "inboundTag": [inbound_tag],
                "outboundTag": outbound_tag
            }
            
            inbounds.append(inbound)
            outbounds.append(outbound)
            routing_rules.append(rule)
        
        if not inbounds:
            return None
        
        config = {
            "log": {"loglevel": "error", "access": "", "error": ""},
            "inbounds": inbounds,
            "outbounds": outbounds + [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": routing_rules
            }
        }
        
        used_ports = [port for port in ports if any(r['inboundTag'][0] == f"socks_{port}" for r in routing_rules)]
        
        return config, used_ports
    
    def generate_batch_configs(self, urls: List[str]) -> List[Tuple[Dict, List[int], List[str]]]:
        """Generate multiple merged configs for large URL lists.
        
        Args:
            urls: List of proxy URLs
        
        Returns:
            List of tuples: (config_dict, ports_list, urls_list)
        """
        if not urls:
            return []
        
        configs = []
        current_port = self.BASE_PORT
        
        for i in range(0, len(urls), self.MAX_PROXIES_PER_CONFIG):
            batch = urls[i:i + self.MAX_PROXIES_PER_CONFIG]
            result = self.generate_merged_config(batch, base_port=current_port)
            
            if result:
                config, ports = result
                configs.append((config, ports, batch))
                current_port = ports[-1] + 1
            
            if current_port > self.BASE_PORT + 4000:
                current_port = self.BASE_PORT
        
        return configs
