"""Configuration settings for VPN config generator."""

import os
from datetime import datetime
import zoneinfo
from utils.logger import log

# Repository settings
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "whoahaow/rjsxrd"  # Updated repository name

# Time settings
ZONE = zoneinfo.ZoneInfo("Europe/Moscow")
THISTIME = datetime.now(ZONE)
OFFSET = THISTIME.strftime("%H:%M | %d.%m.%Y")

# URL sources - parsed from single URLS.txt file with sections
URLS = []  # Default URLs (auto-detects base64)
URLS_EXTRA_BYPASS = []  # Extra URLs for SNI/CIDR bypass configs (auto-detects base64)
URLS_YAML = []  # YAML config URLs (needs separate section - special conversion)
TELEGRAM_PROXY_URLS = []  # Telegram proxy sources URLs

def parse_urls_file():
    """Parse URLS.txt file with section markers."""
    urls = []
    urls_extra_bypass = []
    urls_yaml = []
    telegram_proxy_urls = []
    
    config_dir = os.path.dirname(__file__)
    urls_file = os.path.join(config_dir, 'URLS.txt')
    
    current_section = 'default'  # Default section
    
    try:
        with open(urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines
                if not line:
                    continue
                
                # Check for section markers
                if line.startswith('# '):
                    section_name = line[2:].strip().lower()
                    if 'yaml' in section_name:
                        current_section = 'yaml'
                    elif 'telegram' in section_name or 'tg' in section_name:
                        current_section = 'telegram'
                    elif 'extra' in section_name or 'bypass' in section_name:
                        current_section = 'extra_bypass'
                    else:
                        current_section = 'default'
                    continue
                
                # Skip pure comment lines (not section markers)
                if line.startswith('#'):
                    continue
                
                # Add URL to current section
                if current_section == 'default':
                    urls.append(line)
                elif current_section == 'extra_bypass':
                    urls_extra_bypass.append(line)
                elif current_section == 'yaml':
                    urls_yaml.append(line)
                elif current_section == 'telegram':
                    telegram_proxy_urls.append(line)
                    
    except FileNotFoundError:
        log("URLS.txt file not found!")
    
    return urls, urls_extra_bypass, urls_yaml, telegram_proxy_urls

# Parse all URLs from single file
URLS, URLS_EXTRA_BYPASS, URLS_YAML, TELEGRAM_PROXY_URLS = parse_urls_file()

# Manual server configs from servers.txt
MANUAL_SERVERS = []
try:
    with open(os.path.join(os.path.dirname(__file__), 'servers.txt'), 'r', encoding='utf-8') as f:
        MANUAL_SERVERS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    log("servers.txt file not found!")
    MANUAL_SERVERS = []  # Fallback to empty list

# Telegram proxy sources URLs - parsed from URLS.txt (telegram section)
# (TELEGRAM_PROXY_URLS is now populated by parse_urls_file() above)

# SNI domains for filtering - Russian white-list bypass
def load_sni_domains():
    """Load SNI domains from whitelist-all.txt file."""
    config_dir = os.path.dirname(__file__)  # Get the directory of the current file
    whitelist_path = os.path.join(config_dir, 'whitelist-all.txt')
    try:
        with open(whitelist_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
        return domains
    except FileNotFoundError:
        log(f"whitelist-all.txt not found at {whitelist_path}, using empty list")
        return []

SNI_DOMAINS = load_sni_domains()

# Split configuration
MAX_SERVERS_PER_FILE = 300

# Other settings
DEFAULT_MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "16"))

# Validation concurrency settings
VALIDATION_TCP_CONCURRENCY = int(os.environ.get("VALIDATION_TCP_CONCURRENCY", "100"))
VALIDATION_HTTP_CONCURRENCY = int(os.environ.get("VALIDATION_HTTP_CONCURRENCY", "20"))
VALIDATION_MAX_WORKERS = int(os.environ.get("VALIDATION_MAX_WORKERS", "200"))

# Validation timeout settings (seconds)
VALIDATION_TCP_TIMEOUT = float(os.environ.get("VALIDATION_TCP_TIMEOUT", "3.0"))
VALIDATION_HTTP_TIMEOUT = float(os.environ.get("VALIDATION_HTTP_TIMEOUT", "5.0"))  # Reduced from 10.0s for faster testing

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0.0.0 Safari/537.36"
)

# Proxy detection settings
PROXY_AUTO_DETECT = True
COMMON_PROXY_PORTS = [10808, 2080, 7890, 7891, 1080, 8080]

# Async testing concurrency settings
# Windows has higher process overhead, so lower concurrency prevents system freeze
# Linux/WSL can handle higher concurrency
ASYNC_CONCURRENCY_WIN32 = int(os.environ.get("ASYNC_CONCURRENCY_WIN32", "50"))
ASYNC_CONCURRENCY_LINUX = int(os.environ.get("ASYNC_CONCURRENCY_LINUX", "300"))