"""File handling utilities with refactored, streamlined logic."""

import os
import ipaddress
import math
from typing import List, Set
import re
import base64
import json
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from utils.logger import log
from config.settings import SNI_DOMAINS

# Pre-compiled regex patterns for performance (avoids recompiling on every call)
_BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]+=*$')
_ALLOWINSECURE_PATTERN = re.compile(r'allowinsecure=([^&\?#]+)')
_INSECURE_PATTERN = re.compile(r'insecure=([^&\?#]+)')
_SKIPCERT_PATTERN = re.compile(r'skip-cert-verify=([^&\?#]+)')
_VPN_PROTOCOL_PATTERN = re.compile(r'^(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', re.IGNORECASE)
_GLUE_PATTERN = re.compile(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://')


def _write_chunk(args):
    """Worker function to write a single chunk with 64KB buffer (must be at module level for pickling)."""
    chunk_lines, chunk_path = args
    with open(chunk_path, 'w', encoding='utf-8', buffering=65536) as f:
        f.write(''.join(chunk_lines))
    return chunk_path


def save_to_local_file(path: str, content: str):
    """Saves content to a local file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", buffering=65536) as file:
        file.write(content)
    log(f"Data saved locally to {path}")


def load_from_local_file(path: str) -> str:
    """Loads content from a local file."""
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", buffering=65536) as file:
        return file.read()


def split_config_file(content: str, max_lines_per_file: int = 300) -> List[str]:
    """Splits a config file content into smaller parts."""
    lines = content.strip().split('\n')
    # Remove empty lines
    lines = [line.strip() for line in lines if line.strip()]

    chunks = []
    for i in range(0, len(lines), max_lines_per_file):
        chunk = '\n'.join(lines[i:i + max_lines_per_file])
        chunks.append(chunk)

    return chunks


def split_file_by_size(filepath: str, max_size_mb: float = 49.0) -> List[str]:
    """
    Splits a file into multiple parts if it exceeds the maximum size.
    
    Args:
        filepath: Path to the file to split
        max_size_mb: Maximum file size in MB (default: 49 MB for GitHub limit)
    
    Returns:
        List of paths to created files. If file was small enough, returns [filepath].
        If file was split, returns [filepath-1.txt, filepath-2.txt, ...]
    """
    if not os.path.exists(filepath):
        log(f"File not found: {filepath}")
        return []
    
    # Get file size in bytes
    file_size_bytes = os.path.getsize(filepath)
    max_size_bytes = int(max_size_mb * 1024 * 1024)
    
    log(f"Checking file size: {filepath} = {file_size_bytes / (1024*1024):.2f} MB (limit: {max_size_mb} MB)")
    
    # If file is within limit, return as-is
    if file_size_bytes <= max_size_bytes:
        log(f"File size OK, no splitting needed")
        return [filepath]
    
    # Read all lines from the file with 64KB buffer
    with open(filepath, 'r', encoding='utf-8', buffering=65536) as f:
        lines = f.readlines()
    
    # Remove empty lines and strip
    lines = [line.strip() + '\n' for line in lines if line.strip()]
    
    if not lines:
        log("File is empty after cleaning")
        return [filepath]
    
    # Estimate average line size
    total_chars = sum(len(line) for line in lines)
    avg_line_size = total_chars / len(lines) if lines else 1
    
    # Estimate lines per chunk (with 10% safety margin)
    safe_max_size = int(max_size_bytes * 0.9)
    estimated_lines_per_chunk = max(1, int(safe_max_size / (avg_line_size + 1)))
    
    # Calculate number of chunks needed
    num_chunks = math.ceil(len(lines) / estimated_lines_per_chunk)
    
    log(f"Splitting file into {num_chunks} parts (estimated {estimated_lines_per_chunk} lines per chunk)")
    
    # Get base path and extension
    base_path, ext = os.path.splitext(filepath)
    
    # Prepare all chunks to write
    chunks_to_write = []
    for i in range(num_chunks):
        start_idx = i * estimated_lines_per_chunk
        end_idx = min(start_idx + estimated_lines_per_chunk, len(lines))
        chunk_lines = lines[start_idx:end_idx]
        chunk_path = f"{base_path}-{i + 1}{ext}"
        chunks_to_write.append((chunk_lines, chunk_path))
    
    # Write all chunks in PARALLEL using ThreadPoolExecutor (lower overhead for I/O)
    created_files = []
    with ThreadPoolExecutor(max_workers=min(8, num_chunks)) as executor:
        created_files = list(executor.map(_write_chunk, chunks_to_write))
    
    # Log results
    for chunk_path in created_files:
        chunk_size = os.path.getsize(chunk_path)
        # Count lines in chunk
        with open(chunk_path, 'r', encoding='utf-8', buffering=65536) as f:
            line_count = sum(1 for _ in f)
        log(f"Created {chunk_path} with {line_count} lines ({chunk_size / (1024*1024):.2f} MB)")
    
    # Remove original large file
    try:
        os.remove(filepath)
        log(f"Removed original large file: {filepath}")
    except Exception as e:
        log(f"Warning: Could not remove original file {filepath}: {e}")
    
    return created_files


def extract_host_port(line: str):
    """Extracts host and port from a config line."""
    if not line:
        return None
    if line.startswith("vmess://"):
        try:
            payload = line[8:]
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded.startswith('{'):
                j = json.loads(decoded)
                host = j.get('add') or j.get('host') or j.get('ip')
                port = j.get('port')
                if host and port:
                    return str(host), str(port)
        except Exception:
            pass
        return None
    m = re.search(r'(?:@|//)([\w\.-]+):(\d{1,5})', line)
    if m:
        return m.group(1), m.group(2)
    return None


def extract_ip_from_config(config_line: str):
    """Extract IP address from a config line."""
    if not config_line:
        return None

    # Extract host from config line
    host_port = extract_host_port(config_line)
    if host_port:
        host = host_port[0]
        # Check if it's an IP address
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            # Not an IP address, return None
            return None
    return None


def load_cidr_whitelist(cidr_file_path: str = "../source/config/cidrwhitelist.txt") -> set:
    """Load CIDR whitelist from file and return as a set of individual IPs for fast lookup."""
    try:
        with open(cidr_file_path, 'r', encoding='utf-8', buffering=65536) as f:
            lines = [line.strip() for line in f if line.strip()]

        # Create a set of valid IP addresses for O(1) lookup
        ip_set = set()
        for line in lines:
            try:
                # Validate it's a valid IP and add to set
                ipaddress.ip_address(line)
                ip_set.add(line)
            except ValueError:
                # Skip invalid entries
                continue
        return ip_set
    except FileNotFoundError:
        log(f"CIDR whitelist file not found at {cidr_file_path}")
        return set()


def is_ip_in_cidr_whitelist(ip_str: str, cidr_whitelist: set) -> bool:
    """Check if an IP address is in the CIDR whitelist (optimized version with O(1) lookup)."""
    if not ip_str or not cidr_whitelist:
        return False

    # Direct lookup in the set (O(1) operation)
    return ip_str in cidr_whitelist


def deduplicate_configs(configs: List[str]) -> List[str]:
    """Remove only exact duplicate configs (same full string).
    
    Preserves order of first occurrence. Two configs with same host:port
    but different paths/SNI/settings are BOTH kept, as they may have
    different working status.
    
    Args:
        configs: List of config strings to deduplicate
        
    Returns:
        List of unique config strings, preserving original order
    """
    seen = set()
    unique_configs = []
    
    for cfg in configs:
        c = cfg.strip()
        if not c or c in seen:
            continue
        seen.add(c)
        unique_configs.append(c)
    
    return unique_configs


@lru_cache(maxsize=65536)
def has_insecure_setting(config_line: str) -> bool:
    """Check if a config has insecure settings."""
    config_lower = config_line.lower()

    # Check for allowInsecure in query parameters (common in vless/trojan)
    if 'allowinsecure=' in config_lower:
        # Check if it's set to true, 1, or yes
        allow_insecure_match = _ALLOWINSECURE_PATTERN.search(config_lower)
        if allow_insecure_match:
            value = allow_insecure_match.group(1).strip()
            if value in ['1', 'true', 'yes', 'on']:
                return True

    # Check for insecure in query parameters
    if 'insecure=' in config_lower:
        insecure_match = _INSECURE_PATTERN.search(config_lower)
        if insecure_match:
            value = insecure_match.group(1).strip()
            if value in ['1', 'true', 'yes', 'on']:
                return True

    # Check for skip-cert-verify in query parameters (used in some clients like TUIC)
    if 'skip-cert-verify=' in config_lower:
        skip_cert_verify_match = _SKIPCERT_PATTERN.search(config_lower)
        if skip_cert_verify_match:
            value = skip_cert_verify_match.group(1).strip()
            if value in ['1', 'true', 'yes', 'on', 'enabled']:
                return True

    # Check for security=none (no encryption)
    if 'security=none' in config_lower:
        return True

    # Check for encryption=none in VLESS configs (when not using TLS/REALITY)
    # Note: encryption=none with TLS/REALITY is acceptable, but we can't determine transport layer here
    # So we treat encryption=none alone as potentially insecure
    if 'encryption=none' in config_lower and ('security=tls' not in config_lower and 'security=reality' not in config_lower):
        return True

    # Check for insecure settings in vmess base64 JSON configuration
    if config_line.startswith("vmess://"):
        try:
            payload = config_line[8:]
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded.startswith('{'):
                j = json.loads(decoded)
                # Check for insecure settings in vmess config
                insecure_setting = j.get('insecure') or j.get('allowInsecure')
                if insecure_setting in [True, 'true', 1, '1']:
                    return True
                # Also check for security=none in vmess config
                security_setting = j.get('scy') or j.get('security')
                if security_setting and str(security_setting).lower() == 'none':
                    return True
                # Check for legacy VMess mode (alterId > 0 indicates vulnerable legacy mode)
                alter_id = j.get('aid') or j.get('alterId')
                if alter_id is not None:
                    alter_id_value = int(alter_id) if isinstance(alter_id, (int, str)) else 0
                    if alter_id_value > 0:
                        return True  # Legacy VMess mode with MD5 header authentication is insecure
        except Exception:
            pass

    # Check for insecure Shadowsocks methods
    if config_line.startswith("ss://"):
        try:
            # Parse the Shadowsocks URL to extract method
            # Format: ss://method:password@host:port
            # Or: ss://base64(method:password)@host:port
            ss_part = config_line[5:]  # Remove "ss://"

            # Check if the format is method:password@host:port (non-base64)
            if ':' in ss_part and '@' in ss_part and ss_part.index(':') < ss_part.index('@'):
                # Format is method:password@host:port
                method = ss_part.split(':')[0].lower()

                # Check for weak encryption methods
                weak_methods = [
                    'rc4-md5', 'rc4-md5-6', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
                    'aes-128-cfb8', 'aes-192-cfb8', 'aes-256-cfb8', 'aes-128-cfb1',
                    'aes-192-cfb1', 'aes-256-cfb1', 'aes-128-cfb-fast', 'aes-192-cfb-fast',
                    'aes-256-cfb-fast', 'aes-128-cfb-simple', 'aes-192-cfb-simple',
                    'aes-256-cfb-simple', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
                    'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
                    'cast5-cfb', 'des-cfb', 'idea-cfb', 'rc2-cfb', 'seed-cfb',
                    'salsa20', 'chacha20', 'xsalsa20', 'xchacha20'
                ]

                if method in weak_methods:
                    return True
            else:
                # Contains credentials in base64 format: ss://base64(method:password)@host:port
                if '@' in ss_part:
                    # Contains credentials, method is in base64 part before '@'
                    encoded_part = ss_part.split('@')[0]

                    # Handle padding for base64 decoding
                    rem = len(encoded_part) % 4
                    if rem:
                        padded_encoded_part = encoded_part + '=' * (4 - rem)
                    else:
                        padded_encoded_part = encoded_part

                    try:
                        decoded_credentials = base64.b64decode(padded_encoded_part).decode('utf-8')
                        method = decoded_credentials.split(':')[0].lower()

                        # Check for weak encryption methods
                        weak_methods = [
                            'rc4-md5', 'rc4-md5-6', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
                            'aes-128-cfb8', 'aes-192-cfb8', 'aes-256-cfb8', 'aes-128-cfb1',
                            'aes-192-cfb1', 'aes-256-cfb1', 'aes-128-cfb-fast', 'aes-192-cfb-fast',
                            'aes-256-cfb-fast', 'aes-128-cfb-simple', 'aes-192-cfb-simple',
                            'aes-256-cfb-simple', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
                            'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
                            'cast5-cfb', 'des-cfb', 'idea-cfb', 'rc2-cfb', 'seed-cfb',
                            'salsa20', 'chacha20', 'xsalsa20', 'xchacha20'
                        ]

                        if method in weak_methods:
                            return True

                    except Exception:
                        # If we can't decode, continue with other checks
                        pass
        except Exception:
            pass

    # Check for insecure ShadowsocksR methods
    if config_line.startswith("ssr://"):
        try:
            # SSR URL format: ssr://base64(host:port:protocol:method:obfs:base64pass/?params)
            payload = config_line[6:]
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8')

            # Parse the decoded string: host:port:protocol:method:obfs:base64(password)
            parts = decoded.split(':')
            if len(parts) >= 6:
                method = parts[3].lower()

                # Check for weak encryption methods
                weak_methods = [
                    'rc4-md5', 'rc4-md5-6', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
                    'aes-128-cfb8', 'aes-192-cfb8', 'aes-256-cfb8', 'aes-128-cfb1',
                    'aes-192-cfb1', 'aes-256-cfb1', 'aes-128-cfb-fast', 'aes-192-cfb-fast',
                    'aes-256-cfb-fast', 'aes-128-cfb-simple', 'aes-192-cfb-simple',
                    'aes-256-cfb-simple', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
                    'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
                    'cast5-cfb', 'des-cfb', 'idea-cfb', 'rc2-cfb', 'seed-cfb',
                    'salsa20', 'chacha20', 'xsalsa20', 'xchacha20'
                ]

                if method in weak_methods:
                    return True
        except Exception:
            pass

    # Check for other insecure indicators in the URL
    if 'insecure=1' in config_lower or 'insecure=true' in config_lower:
        return True
    if 'verify=0' in config_lower or 'verify=false' in config_lower:
        return True

    return False


def filter_secure_configs(configs: List[str]) -> List[str]:
    """Filter out configs with insecure settings using parallel processing."""
    from concurrent.futures import ThreadPoolExecutor
    
    def check_secure(config: str) -> tuple:
        """Return (config, is_secure) tuple."""
        return (config, not has_insecure_setting(config))
    
    # Use ThreadPoolExecutor for parallel filtering (IO-bound due to regex operations)
    secure_configs = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(check_secure, configs))
        for config, is_secure in results:
            if is_secure:
                secure_configs.append(config)
    
    return secure_configs


def prepare_config_content(content: str) -> List[str]:
    """Prepares and normalizes config content by separating glued configs."""
    # Add newlines before known protocol prefixes that might be glued to previous lines
    content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', r'\n\1://', content)
    lines = content.splitlines()
    # Filter out empty lines, comments, and non-VPN config lines
    configs = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and is_valid_vpn_config_url(line):
            configs.append(line)
    return configs


def is_valid_vpn_config_url(line: str) -> bool:
    """Check if a line is a valid VPN config URL."""
    return bool(_VPN_PROTOCOL_PATTERN.match(line))


def apply_sni_cidr_filter(configs: List[str], filter_secure: bool = True) -> List[str]:
    """Apply SNI/CIDR filtering to configs, with optional secure filtering (PARALLEL)."""
    from config.settings import SNI_DOMAINS
    from utils.file_utils import load_cidr_whitelist, is_ip_in_cidr_whitelist, extract_ip_from_config
    
    # Load CIDR whitelist
    cidr_whitelist = load_cidr_whitelist()
    
    # Optimize domain list by removing redundant domains
    sorted_domains = sorted(SNI_DOMAINS, key=len)
    optimized_domains = []
    
    for d in sorted_domains:
        is_redundant = False
        for existing in optimized_domains:
            if existing in d:
                is_redundant = True
                break
        if not is_redundant:
            optimized_domains.append(d)
    
    # Compile Regex
    try:
        pattern_str = r"(?:" + "|".join(re.escape(d) for d in optimized_domains) + r")"
        sni_regex = re.compile(pattern_str)
    except Exception as e:
        log(f"Error compiling Regex: {e}")
        return []
    
    # PARALLEL PROCESSING - check each config in parallel
    def check_config(config: str) -> tuple:
        """Return (config, should_include) tuple."""
        config = config.strip()
        if not config:
            return (config, False)
        
        # Check if config should be included based on SNI or CIDR criteria
        matches_sni = sni_regex.search(config)
        matches_cidr = False
        if cidr_whitelist:
            ip = extract_ip_from_config(config)
            if ip and is_ip_in_cidr_whitelist(ip, cidr_whitelist):
                matches_cidr = True
        
        # If config matches either SNI or CIDR criteria
        if matches_sni or matches_cidr:
            # Only add the config if it's a valid VPN config URL
            if is_valid_vpn_config_url(config):
                # Apply security filter based on the parameter
                if not filter_secure or not has_insecure_setting(config):
                    return (config, True)
        
        return (config, False)
    
    # Process configs in parallel with 8 workers
    filtered_configs = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(check_config, configs))
        for config, should_include in results:
            if should_include:
                filtered_configs.append(config)
    
    return filtered_configs