"""Config processing module with all the main processing logic."""

import os
import sys
import time
import concurrent.futures
import base64
import re
import glob
from typing import List, Tuple, Optional
import math

# Add the source directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Pre-compiled base64 pattern for performance
_BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]+=*$')

from config.settings import URLS, URLS_EXTRA_BYPASS, URLS_YAML, MANUAL_SERVERS, DEFAULT_MAX_WORKERS, TELEGRAM_PROXY_URLS, VALIDATION_MAX_WORKERS, VALIDATION_TCP_TIMEOUT, VALIDATION_HTTP_TIMEOUT
from config.constants import V2RAYN_MAX_CONCURRENCY, MAX_SAFE_CONCURRENCY
from fetchers.fetcher import fetch_data, build_session
from fetchers.daily_repo_fetcher import fetch_configs_from_daily_repo
from utils.file_utils import save_to_local_file, load_from_local_file, split_config_file, deduplicate_configs, prepare_config_content, filter_secure_configs, has_insecure_setting, apply_sni_cidr_filter, split_file_by_size
from utils.logger import log
from processors.telegram_proxy_processor import TelegramProxyProcessor


def _try_decode_base64_content(content: str) -> Optional[str]:
    """Try to decode base64 content. Returns decoded string if successful, None otherwise.
    
    Uses quick heuristics to skip obvious non-base64 content before attempting decode.
    """
    try:
        # QUICK HEURISTICS to skip obvious non-base64 content
        content_stripped = content.strip()
        if not content_stripped:
            return None
        
        # Heuristic 1: If content has many newlines, probably not base64
        newline_ratio = content_stripped.count('\n') / len(content_stripped)
        if newline_ratio > 0.1:  # More than 10% newlines = probably not base64
            return None
        
        # Heuristic 2: If content already has protocol markers, not base64
        if '://' in content_stripped:
            return None
        
        # Heuristic 3: If content looks like plain text (spaces, common words), skip
        if ' ' in content_stripped and len(content_stripped) > 100:
            # Lots of spaces in long content = probably plain text, not base64
            space_ratio = content_stripped.count(' ') / len(content_stripped)
            if space_ratio > 0.05:  # More than 5% spaces
                return None
        
        # Now check if content looks like base64 (only valid base64 chars, possibly with newlines)
        cleaned = content_stripped.replace('\n', '').replace(' ', '')
        if not _BASE64_PATTERN.match(cleaned):
            return None
        
        # Try to decode
        decoded_bytes = base64.b64decode(content_stripped)
        decoded_content = decoded_bytes.decode('utf-8', errors='ignore')
        
        # Verify it looks like config data (contains vless://, vmess://, etc.)
        if any(proto in decoded_content for proto in ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria://', 'hy2://', 'tuic://']):
            return decoded_content
        
        return None
    except Exception:
        return None


def download_all_configs(output_dir: str = "../githubmirror", scan_for_telegram_proxies: bool = False) -> Tuple[List[str], List[str], List[Tuple[List[str], str]], List[str], List[str]]:
    """Downloads all configs from all sources. 
    
    Returns:
        If scan_for_telegram_proxies=False: (all_configs, extra_bypass_configs, numbered_configs_with_urls)
        If scan_for_telegram_proxies=True: (all_configs, extra_bypass_configs, numbered_configs_with_urls, mtproto_proxies, socks5_proxies)
    """
    fetch_start_time = time.time()
    
    all_configs = []
    extra_bypass_configs = []
    numbered_configs_with_urls = []  # Will store (configs, url) tuples for numbered files
    all_mtproto_proxies = []
    all_socks5_proxies = []

    # Create output directories
    os.makedirs(f"{output_dir}/default", exist_ok=True)
    os.makedirs(f"{output_dir}/bypass", exist_ok=True)
    os.makedirs(f"{output_dir}/bypass-unsecure", exist_ok=True)
    os.makedirs(f"{output_dir}/split-by-protocols", exist_ok=True)
    os.makedirs(f"{output_dir}/tg-proxy", exist_ok=True)
    os.makedirs("../qr-codes", exist_ok=True)

    # Import scraper for telegram proxy scanning
    from fetchers.telegram_proxy_scraper import TelegramProxyScraper
    scraper = TelegramProxyScraper() if scan_for_telegram_proxies else None

    # Download from regular URLs with auto-detection of base64 (PARALLEL - much faster)
    if URLS:
        log(f"Fetching {len(URLS)} URLs in parallel...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(1, len(URLS)))) as executor:
            future_to_url = {executor.submit(fetch_data, url): url for url in URLS}
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    content = future.result()
                    corresponding_url = future_to_url[future]
                    
                    # Try to parse as regular configs first
                    configs = prepare_config_content(content)
                    
                    # If no configs found, try base64 decoding
                    if not configs:
                        decoded_content = _try_decode_base64_content(content)
                        if decoded_content:
                            log(f"Auto-detected base64 format for {corresponding_url[:80]}...")
                            configs = prepare_config_content(decoded_content)
                    
                    all_configs.extend(configs)
                    numbered_configs_with_urls.append((configs, corresponding_url))
                    
                    # Scan for telegram proxies
                    if scraper:
                        try:
                            mtproto, socks5 = scraper.extract_proxies(content)
                            all_mtproto_proxies.extend(mtproto)
                            all_socks5_proxies.extend(socks5)
                        except Exception as e:
                            pass
                except Exception as e:
                    # Log full URL on error
                    url = future_to_url[future]
                    log(f"Error downloading from {url}: {str(e)[:100]}")

    # Download from extra bypass URLs (PARALLEL) - merged with base64 auto-detection
    if URLS_EXTRA_BYPASS:
        log(f"Fetching {len(URLS_EXTRA_BYPASS)} extra bypass URLs in parallel...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(1, len(URLS_EXTRA_BYPASS)))) as executor:
            future_to_url = {executor.submit(fetch_data, url): url for url in URLS_EXTRA_BYPASS}
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    content = future.result()
                    corresponding_url = future_to_url[future]
                    
                    # Try to parse as regular configs first
                    configs = prepare_config_content(content)
                    
                    # If no configs found, try base64 decoding
                    if not configs:
                        decoded_content = _try_decode_base64_content(content)
                        if decoded_content:
                            log(f"Auto-detected base64 format for {corresponding_url[:80]}...")
                            configs = prepare_config_content(decoded_content)
                    
                    extra_bypass_configs.extend(configs)
                    all_configs.extend(configs)
                    numbered_configs_with_urls.append((configs, corresponding_url))
                    
                    # Scan for telegram proxies
                    if scraper:
                        try:
                            mtproto, socks5 = scraper.extract_proxies(content)
                            all_mtproto_proxies.extend(mtproto)
                            all_socks5_proxies.extend(socks5)
                        except Exception as e:
                            pass
                except Exception as e:
                    log(f"Error downloading from extra bypass URL: {str(e)[:200]}...")

    # YAML URLs need special handling (Clash/Surge format conversion)
    if URLS_YAML:
        from fetchers.yaml_converter import convert_yaml_to_vpn_configs
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(1, len(URLS_YAML)))) as executor:
            future_to_url = {executor.submit(fetch_data, url): url for url in URLS_YAML}
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    yaml_content = future.result()
                    vpn_configs = convert_yaml_to_vpn_configs(yaml_content)
                    corresponding_url = future_to_url[future]
                    if vpn_configs:
                        all_configs.extend(vpn_configs)
                        numbered_configs_with_urls.append((vpn_configs, corresponding_url))
                        
                        # Scan for telegram proxies
                        if scraper:
                            try:
                                mtproto, socks5 = scraper.extract_proxies(yaml_content)
                                all_mtproto_proxies.extend(mtproto)
                                all_socks5_proxies.extend(socks5)
                            except Exception as e:
                                pass
                except Exception as e:
                    log(f"Error downloading or converting YAML: {str(e)[:200]}...")

    # Download from daily-updated repository
    try:
        daily_configs = fetch_configs_from_daily_repo()
        all_configs.extend(daily_configs)
        numbered_configs_with_urls.append((daily_configs, "DAILY_REPO"))
        log(f"Downloaded {len(daily_configs)} configs from daily-updated repository")
        
        # Scan for telegram proxies
        if scraper and daily_configs:
            try:
                daily_content = "\n".join(daily_configs)
                mtproto, socks5 = scraper.extract_proxies(daily_content)
                all_mtproto_proxies.extend(mtproto)
                all_socks5_proxies.extend(socks5)
            except Exception as e:
                pass
    except Exception as e:
        log(f"Error downloading from daily-updated repository: {str(e)[:200]}...")

    # Add manual servers from servers.txt
    if MANUAL_SERVERS:
        manual_configs = prepare_config_content("\n".join(MANUAL_SERVERS))
        all_configs.extend(manual_configs)
        extra_bypass_configs.extend(manual_configs)
        numbered_configs_with_urls.append((manual_configs, "MANUAL_SERVERS"))
        log(f"Added {len(manual_configs)} manual configs from servers.txt")

    # Summary of all downloads
    total_downloaded = sum(len(cfgs) for cfgs, _ in numbered_configs_with_urls)
    fetch_elapsed = time.time() - fetch_start_time
    log(f"DOWNLOAD COMPLETE: {total_downloaded} configs from {len(numbered_configs_with_urls)} sources in {fetch_elapsed:.2f}s (parallel fetching enabled)")

    # Deduplicate telegram proxies
    if scan_for_telegram_proxies:
        all_mtproto_proxies = scraper.deduplicate_proxies(all_mtproto_proxies)
        all_socks5_proxies = scraper.deduplicate_proxies(all_socks5_proxies)
        log(f"Scanned URLs for Telegram proxies: {len(all_mtproto_proxies)} MTProto, {len(all_socks5_proxies)} SOCKS5")

    if scan_for_telegram_proxies:
        return all_configs, extra_bypass_configs, numbered_configs_with_urls, all_mtproto_proxies, all_socks5_proxies, fetch_elapsed
    else:
        return all_configs, extra_bypass_configs, numbered_configs_with_urls, fetch_elapsed


def create_all_configs_file(all_configs: List[str], output_dir: str = "../githubmirror", max_size_mb: float = 49.0) -> List[str]:
    """Creates the all.txt file with all unique configs. Splits if file exceeds size limit."""
    unique_configs = deduplicate_configs(all_configs)
    all_txt_path = f"{output_dir}/default/all.txt"
    
    # Pre-calculate if splitting needed to avoid double-write
    estimated_size = sum(len(cfg) + 1 for cfg in unique_configs)
    max_size_bytes = int(max_size_mb * 1024 * 1024)
    
    if estimated_size > max_size_bytes:
        log(f"Estimated size ({estimated_size / (1024*1024):.2f} MB) exceeds limit, splitting directly")
        num_files_needed = math.ceil(estimated_size / max_size_bytes)
        max_configs_per_file = max(1, len(unique_configs) // num_files_needed)
        return split_configs_to_files(unique_configs, f"{output_dir}/default", "all", max_configs_per_file=max_configs_per_file)
    
    try:
        os.makedirs(os.path.dirname(all_txt_path), exist_ok=True)
        header = get_subscription_header("all")
        configs_with_suffix = [append_remark_suffix(cfg) for cfg in unique_configs]
        with open(all_txt_path, "w", encoding="utf-8", buffering=65536) as f:
            f.write(header + "\n".join(configs_with_suffix))
        log(f"Created {all_txt_path} with {len(unique_configs)} unique configs")
        
        # Check if file needs splitting
        created_files = split_file_by_size(all_txt_path, max_size_mb)
        return created_files
    except Exception as e:
        log(f"Error creating all.txt: {e}")
        return []


def create_secure_configs_file(all_configs: List[str], output_dir: str = "../githubmirror", max_size_mb: float = 49.0) -> List[str]:
    """Creates the all-secure.txt file with only secure configs. Splits if file exceeds size limit."""
    unique_configs = deduplicate_configs(all_configs)
    secure_configs = filter_secure_configs(unique_configs)
    all_secure_txt_path = f"{output_dir}/default/all-secure.txt"
    
    # Pre-calculate if splitting needed to avoid double-write
    estimated_size = sum(len(cfg) + 1 for cfg in secure_configs)
    max_size_bytes = int(max_size_mb * 1024 * 1024)
    
    if estimated_size > max_size_bytes:
        log(f"Estimated size ({estimated_size / (1024*1024):.2f} MB) exceeds limit, splitting directly")
        num_files_needed = math.ceil(estimated_size / max_size_bytes)
        max_configs_per_file = max(1, len(secure_configs) // num_files_needed)
        return split_configs_to_files(secure_configs, f"{output_dir}/default", "all-secure", max_configs_per_file=max_configs_per_file)
    
    try:
        os.makedirs(os.path.dirname(all_secure_txt_path), exist_ok=True)
        header = get_subscription_header("all-secure")
        configs_with_suffix = [append_remark_suffix(cfg) for cfg in secure_configs]
        with open(all_secure_txt_path, "w", encoding="utf-8", buffering=65536) as f:
            f.write(header + "\n".join(configs_with_suffix))
        log(f"Created {all_secure_txt_path} with {len(secure_configs)} unique secure configs")
        
        # Check if file needs splitting
        created_files = split_file_by_size(all_secure_txt_path, max_size_mb)
        return created_files
    except Exception as e:
        log(f"Error creating all-secure.txt: {e}")
        return []


def append_remark_suffix(config: str, suffix: str = "%20t.me%2Frjsxrd") -> str:
    """Append suffix to config remark. Configs are already URL-encoded."""
    if "#" in config:
        return f"{config}{suffix}"
    else:
        return f"{config}#{suffix}"


def get_subscription_header(filename: str, current_file: int = None, total_files: int = None) -> str:
    """Generate subscription header for a file."""
    if current_file and total_files:
        title = f"{filename}-{current_file}/{total_files} t.me/rjsxrd"
    else:
        title = f"{filename} t.me/rjsxrd"
    
    return (
        f"#profile-title: {title}\n"
        "#profile-update-interval: 48\n"
        "#support-url: https://t.me/rjsxrd\n"
        "#announce: t.me/rjsxrd\n"
        "#subscription-userinfo: upload=0; download=0; total=0; expire=0\n"
        "\n"
    )


def _write_config_chunk(args):
    """Worker function to write a single config chunk (must be at module level for pickling)."""
    chunk, filename, current_file, num_files, total_configs, filename_prefix, add_suffix = args
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        header = get_subscription_header(filename_prefix, current_file, num_files)
        if add_suffix:
            configs_with_suffix = [append_remark_suffix(cfg) for cfg in chunk]
            with open(filename, "w", encoding="utf-8", buffering=65536) as f:
                f.write(header + "\n".join(configs_with_suffix))
        else:
            with open(filename, "w", encoding="utf-8", buffering=65536) as f:
                f.write(header + "\n".join(chunk))
        return (filename, len(chunk), current_file, num_files, None)
    except Exception as e:
        return (filename, 0, current_file, num_files, str(e))


def split_configs_to_files(configs: List[str], output_dir: str, filename_prefix: str, max_configs_per_file: int = 300, add_suffix: bool = True) -> List[str]:
    """Splits configs into multiple files with a given prefix using parallel processing."""
    num_configs = len(configs)
    if not num_configs:
        return []

    # Calculate the number of files needed, rounding up
    num_files = math.ceil(num_configs / max_configs_per_file)
    log(f"Number of configs: {num_configs}, Max configs per file: {max_configs_per_file}, Calculated number of files: {num_files}")

    # Prepare all chunks to write
    chunks_to_write = []
    for i in range(int(num_files)):
        start = i * max_configs_per_file
        end = start + max_configs_per_file
        chunk = configs[start:end]
        filename = f"{output_dir}/{filename_prefix}-{i + 1}.txt"
        chunks_to_write.append((chunk, filename, i + 1, num_files, num_configs, filename_prefix, add_suffix))

    # Write all chunks in PARALLEL using ThreadPoolExecutor
    created_files = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, num_files)) as executor:
        results = list(executor.map(_write_config_chunk, chunks_to_write))
        
        for filename, count, current_file, num_files, error in results:
            if error:
                log(f"Error creating {filename}: {error}")
            else:
                log(f"Created {filename} with {count} configs (file {current_file} of {num_files})")
                created_files.append(filename)

    return created_files


def _write_protocol_file(args):
    """Worker function to write a protocol file (must be at module level for pickling)."""
    protocol, configs, output_dir, max_size_mb, is_secure = args
    import os
    from utils.file_utils import split_file_by_size
    from utils.logger import log
    
    if not configs:
        return []
    
    filename = f"{protocol}{'-secure' if is_secure else ''}.txt"
    filepath = os.path.join(f"{output_dir}/split-by-protocols", filename)
    
    # Remove duplicates while preserving order
    unique_configs = list(dict.fromkeys(configs))
    
    file_pairs = []
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        header = get_subscription_header(filename)
        configs_with_suffix = [append_remark_suffix(cfg) for cfg in unique_configs]
        with open(filepath, "w", encoding="utf-8", buffering=65536) as f:
            f.write(header + "\n".join(configs_with_suffix))
        log(f"Created file {filepath} with {len(unique_configs)} {'secure ' if is_secure else ''}configs ({protocol})")
        
        # Split file if it exceeds size limit
        created_files = split_file_by_size(filepath, max_size_mb)
        
        # Add all created files to file_pairs
        for created_file in created_files:
            created_filename = os.path.basename(created_file)
            file_pairs.append((created_file, f"githubmirror/split-by-protocols/{created_filename}"))
    except Exception as e:
        log(f"Error creating {filepath}: {e}")
    
    return file_pairs


def create_protocol_split_files(all_configs: List[str], output_dir: str = "../githubmirror", max_size_mb: float = 49.0) -> List[Tuple[str, str]]:
    """Creates protocol-specific files in the split-by-protocols folder, both secure and unsecure versions. Splits large files using parallel processing."""
    # Define supported protocols
    protocols = ['vless', 'vmess', 'trojan', 'ss', 'ssr', 'tuic', 'hysteria', 'hysteria2', 'hy2']

    # Deduplicate first to reduce security filtering work
    unique_configs = deduplicate_configs(all_configs)

    # Separate configs by protocol and security
    protocol_configs = {protocol: [] for protocol in protocols}
    protocol_secure_configs = {protocol: [] for protocol in protocols}

    for config in unique_configs:
        # Determine the protocol from the config line
        config_lower = config.lower()
        matched_protocol = None

        for protocol in protocols:
            if config_lower.startswith(f"{protocol}://"):
                matched_protocol = protocol
                break

        if matched_protocol:
            # Add to unsecure version (all configs for this protocol)
            protocol_configs[matched_protocol].append(config)

            # Add to secure version only if it's secure
            if not has_insecure_setting(config):
                protocol_secure_configs[matched_protocol].append(config)

    # Prepare all file writes as tasks
    write_tasks = []
    for protocol, configs in protocol_configs.items():
        if configs:
            write_tasks.append((protocol, configs, output_dir, max_size_mb, False))
    
    for protocol, configs in protocol_secure_configs.items():
        if configs:
            write_tasks.append((protocol, configs, output_dir, max_size_mb, True))

    # Write all protocol files in PARALLEL using ThreadPoolExecutor
    all_file_pairs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(write_tasks))) as executor:
        results = list(executor.map(_write_protocol_file, write_tasks))
        for file_pairs in results:
            all_file_pairs.extend(file_pairs)

    return all_file_pairs


def _write_numbered_file(args):
    """Worker function to write a numbered file (must be at module level for pickling)."""
    i, configs, source_url, output_dir, total_files = args
    import os
    from utils.logger import log
    
    if not configs:
        return (None, None)
    
    filename = f"{i + 1}.txt"
    filepath = os.path.join(f"{output_dir}/default", filename)

    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        header = get_subscription_header(str(i + 1), i + 1, total_files)
        configs_with_suffix = [append_remark_suffix(cfg) for cfg in configs]
        with open(filepath, "w", encoding="utf-8", buffering=65536) as f:
            f.write(header + "\n".join(configs_with_suffix))
        log(f"Created numbered file {filepath} with {len(configs)} configs from source: {source_url}")
        return (filepath, None)
    except Exception as e:
        log(f"Error creating numbered file {filepath}: {e}")
        return (None, str(e))


def create_numbered_default_files(numbered_configs_with_urls: List[Tuple[List[str], str]], output_dir: str = "../githubmirror") -> List[str]:
    """Creates numbered files (1.txt - 26.txt only) in the default directory based on URL order using parallel processing.
    
    Limits to first 26 sources to avoid creating too many numbered files.
    all.txt and all-secure.txt are still created from ALL sources.
    """
    # LIMIT to first 26 sources only
    original_count = len(numbered_configs_with_urls)
    numbered_configs_with_urls = numbered_configs_with_urls[:26]
    
    if original_count > 26:
        log(f"Limiting numbered files to 26 sources (had {original_count}, dropped {original_count - 26})")
    
    # Count total files for counter format
    total_files = sum(1 for configs, _ in numbered_configs_with_urls if configs)
    # Prepare all file writes as tasks
    write_tasks = [(i, configs, source_url, output_dir, total_files) for i, (configs, source_url) in enumerate(numbered_configs_with_urls) if configs]

    # Write all numbered files in PARALLEL using ThreadPoolExecutor
    created_files = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(write_tasks))) as executor:
        results = list(executor.map(_write_numbered_file, write_tasks))
        for filepath, error in results:
            if filepath:
                created_files.append(filepath)

    return created_files


def create_working_config_files(output_dir: str = "../githubmirror") -> tuple:
    """Creates verified working config files sorted by ping (fastest first) using optimized verification.
    
    Reads from raw files in /raw/ subfolders, writes verified configs to main folders.
    Returns: (bypass_files, bypass_unsecure_files) - lists of split file paths
    """
    bypass_all_raw_path = f"{output_dir}/bypass/raw/bypass-all-raw.txt"
    bypass_all_txt_path = f"{output_dir}/bypass/bypass-all.txt"
    bypass_unsecure_raw_path = f"{output_dir}/bypass-unsecure/raw/bypass-unsecure-all-raw.txt"
    bypass_unsecure_all_txt_path = f"{output_dir}/bypass-unsecure/bypass-unsecure-all.txt"
    
    # Check if raw files exist
    if not os.path.exists(bypass_all_raw_path) and not os.path.exists(bypass_unsecure_raw_path):
        log("No bypass raw config files found for verification")
        return ([], [])
    
    # STEP 1: Verify bypass-all-raw.txt and create bypass-all.txt
    working_bypass = []
    if os.path.exists(bypass_all_raw_path):
        log(f"Verifying bypass-all-raw.txt...")
        working_bypass = _verify_config_file(bypass_all_raw_path)
        
        if working_bypass:
            os.makedirs(os.path.dirname(bypass_all_txt_path), exist_ok=True)
            header = get_subscription_header("bypass-all")
            configs_with_suffix = [append_remark_suffix(cfg) for cfg in working_bypass]
            with open(bypass_all_txt_path, 'w', encoding='utf-8', buffering=65536) as f:
                f.write(header + '\n'.join(configs_with_suffix))
            log(f"Created {bypass_all_txt_path} with {len(working_bypass)} working configs")
            
            # Split verified configs into bypass-1.txt, bypass-2.txt, etc.
            bypass_files = split_configs_to_files(working_bypass, f"{output_dir}/bypass", "bypass", max_configs_per_file=300)
        else:
            log(f"No working configs found in bypass-all-raw.txt")
            bypass_files = []
    else:
        log(f"bypass-all-raw.txt not found, skipping")
        bypass_files = []
    
    # STEP 2: Verify bypass-unsecure-all-raw.txt
    if os.path.exists(bypass_unsecure_raw_path):
        log(f"Verifying bypass-unsecure-all-raw.txt (optimizing by skipping already-tested configs)...")
        
        with open(bypass_unsecure_raw_path, 'r', encoding='utf-8', buffering=65536) as f:
            unsecure_configs = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        # Find configs that are only in unsecure (not in bypass-all-raw.txt or split raw files)
        all_bypass_configs = set()
        
        # Check bypass-all-raw.txt first
        if os.path.exists(bypass_all_raw_path):
            with open(bypass_all_raw_path, 'r', encoding='utf-8', buffering=65536) as f:
                all_bypass_configs.update(line.strip() for line in f if line.strip() and not line.strip().startswith('#'))
        
        # Also check split RAW files (bypass-all-raw-1.txt, bypass-all-raw-2.txt, etc.)
        bypass_raw_dir = f"{output_dir}/bypass/raw"
        if os.path.isdir(bypass_raw_dir):
            # Match only numeric suffix files (bypass-all-raw-1.txt, bypass-all-raw-2.txt, etc.)
            bypass_raw_split_files = glob.glob(f"{bypass_raw_dir}/bypass-all-raw-[0-9]*.txt")
            for bypass_raw_file in bypass_raw_split_files:
                if os.path.exists(bypass_raw_file):
                    try:
                        with open(bypass_raw_file, 'r', encoding='utf-8', buffering=65536) as f:
                            all_bypass_configs.update(line.strip() for line in f if line.strip() and not line.strip().startswith('#'))
                    except (IOError, OSError, UnicodeDecodeError) as e:
                        log(f"Warning: Could not read split raw file {bypass_raw_file}: {e}")
        
        unsecure_only = [cfg for cfg in unsecure_configs if cfg not in all_bypass_configs]
        
        log(f"bypass-unsecure-all-raw.txt has {len(unsecure_configs)} configs, {len(all_bypass_configs)} already tested (including split raw files), testing {len(unsecure_only)} new configs...")
        
        if unsecure_only:
            # Verify only the new (insecure-only) configs
            working_unsecure_only = _verify_config_file(bypass_unsecure_raw_path, unsecure_only)
            
            # Merge: already verified secure + newly verified insecure
            all_working = working_bypass + working_unsecure_only
            
            # Write verified unsecure configs
            os.makedirs(os.path.dirname(bypass_unsecure_all_txt_path), exist_ok=True)
            header = get_subscription_header("bypass-unsecure-all")
            configs_with_suffix = [append_remark_suffix(cfg) for cfg in all_working]
            with open(bypass_unsecure_all_txt_path, 'w', encoding='utf-8', buffering=65536) as f:
                f.write(header + '\n'.join(configs_with_suffix))
            log(f"Created {bypass_unsecure_all_txt_path} with {len(all_working)} working configs ({len(working_bypass)} secure + {len(working_unsecure_only)} insecure)")
            
            # Split verified configs into bypass-unsecure-1.txt, bypass-unsecure-2.txt, etc.
            bypass_unsecure_files = split_configs_to_files(all_working, f"{output_dir}/bypass-unsecure", "bypass-unsecure", max_configs_per_file=300)
        else:
            log(f"All configs in bypass-unsecure-all-raw.txt were already verified in bypass-all-raw.txt or split raw files")
            # Use the same working_bypass configs
            if working_bypass:
                os.makedirs(os.path.dirname(bypass_unsecure_all_txt_path), exist_ok=True)
                header = get_subscription_header("bypass-unsecure-all")
                configs_with_suffix = [append_remark_suffix(cfg) for cfg in working_bypass]
                with open(bypass_unsecure_all_txt_path, 'w', encoding='utf-8', buffering=65536) as f:
                    f.write(header + '\n'.join(configs_with_suffix))
                log(f"Created {bypass_unsecure_all_txt_path} with {len(working_bypass)} working configs (copied from bypass-all)")
                
                # Split verified configs
                bypass_unsecure_files = split_configs_to_files(working_bypass, f"{output_dir}/bypass-unsecure", "bypass-unsecure", max_configs_per_file=300)
            else:
                bypass_unsecure_files = []
    else:
        log(f"bypass-unsecure-all-raw.txt not found, skipping")
        bypass_unsecure_files = []
    
    log(f"Verification complete: {len(bypass_files)} bypass files, {len(bypass_unsecure_files)} bypass-unsecure files")
    return (bypass_files, bypass_unsecure_files)


def _verify_config_file(input_path: str, configs: List[str] = None, verbose: bool = False) -> List[str]:
    """Verify configs in a file and return sorted working configs."""
    try:
        if configs is None:
            with open(input_path, 'r', encoding='utf-8') as f:
                configs = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        
        if not configs:
            log(f"No configs in {input_path}")
            return []
        
        # Use Xray tester (concurrent testing with sorting by latency)
        verifier = None
        try:
            from utils.xray_tester import XrayTester
            verifier = XrayTester()  # Async testing on all platforms
            
            if verifier.xray_path and os.path.exists(verifier.xray_path):
                log(f"Using Xray-core tester: {verifier.xray_path}")
                working = verifier.test_batch(configs, timeout=VALIDATION_HTTP_TIMEOUT, verbose=verbose)
                sorted_configs = [cfg for cfg, _, _ in working]
            else:
                log("WARNING: Xray not found, skipping verification")
                sorted_configs = configs
                
        except Exception as e:
            log(f"Xray testing error: {e}")
            raise  # Re-raise instead of falling back to TCP
        
        finally:
            # Always cleanup processes
            if verifier:
                try:
                    verifier.cleanup()
                except Exception as cleanup_error:
                    if verbose:
                        log(f"Cleanup warning: {cleanup_error}")
        
        return sorted_configs
    except Exception as e:
        log(f"Error verifying {input_path}: {e}")
        return []


def process_all_configs(output_dir: str = "../githubmirror") -> List[Tuple[str, str]]:
    """Main processing function that orchestrates the entire config generation process."""
    overall_start = time.time()
    timing = {}
    
    # Step 1: Download all configs from all sources AND scan for telegram proxies in single pass
    log("Downloading all configs from all sources (with Telegram proxy scanning)...")
    download_start = time.time()
    result = download_all_configs(output_dir, scan_for_telegram_proxies=True)
    all_configs, extra_bypass_configs, numbered_configs_with_urls, mtproto_proxies, socks5_proxies, fetch_elapsed = result
    timing['fetch_urls'] = fetch_elapsed
    log(f"Downloaded {len(all_configs)} total configs, {len(extra_bypass_configs)} extra bypass configs, and {len(numbered_configs_with_urls)} sources for numbered files")
    log(f"Found {len(mtproto_proxies)} MTProto and {len(socks5_proxies)} SOCKS5 Telegram proxies during download")

    # Step 2: Create numbered default files (1.txt, 2.txt, etc.) based on URL order
    log("Creating numbered default files...")
    numbered_default_files = create_numbered_default_files(numbered_configs_with_urls, output_dir)

    # Step 3: Create all.txt file (all unique configs)
    log("Creating all.txt file...")
    start = time.time()
    all_txt_files = create_all_configs_file(all_configs, output_dir)
    timing['all_txt'] = time.time() - start

    # Step 4: Create all-secure.txt file (only secure configs)
    log("Creating all-secure.txt file...")
    start = time.time()
    all_secure_txt_files = create_secure_configs_file(all_configs, output_dir)
    timing['all_secure_txt'] = time.time() - start

    # Step 5: Create bypass raw file (untested configs in /raw/ subfolder)
    log("Creating bypass raw file...")
    start = time.time()
    # Apply SNI/CIDR filtering to main configs (regular + base64 + yaml) without security filtering yet
    sni_cidr_filtered_configs = apply_sni_cidr_filter(all_configs, filter_secure=False)
    # Combine with extra bypass configs, then deduplicate, then filter for security once
    all_bypass_configs = sni_cidr_filtered_configs + extra_bypass_configs
    unique_bypass_configs = deduplicate_configs(all_bypass_configs)
    secure_bypass_configs = filter_secure_configs(unique_bypass_configs)

    bypass_all_txt_path = f"{output_dir}/bypass/raw/bypass-all-raw.txt"
    
    # Pre-calculate if splitting needed to avoid double-write
    estimated_size = sum(len(cfg) + 1 for cfg in secure_bypass_configs)
    max_size_bytes = int(49.0 * 1024 * 1024)
    
    if estimated_size > max_size_bytes:
        log(f"Estimated size ({estimated_size / (1024*1024):.2f} MB) exceeds limit, splitting directly")
        num_files_needed = math.ceil(estimated_size / max_size_bytes)
        max_configs_per_file = max(1, len(secure_bypass_configs) // num_files_needed)
        # Don't add suffix to raw split files - they're intermediate
        bypass_all_txt_files = split_configs_to_files(secure_bypass_configs, f"{output_dir}/bypass/raw", "bypass-all-raw", max_configs_per_file=max_configs_per_file, add_suffix=False)
    else:
        try:
            os.makedirs(os.path.dirname(bypass_all_txt_path), exist_ok=True)
            header = get_subscription_header("bypass-all-raw")
            # Don't add suffix to raw files - they're intermediate and will be read for verification
            with open(bypass_all_txt_path, "w", encoding="utf-8", buffering=65536) as f:
                f.write(header + "\n".join(secure_bypass_configs))
            log(f"Created {bypass_all_txt_path} with {len(secure_bypass_configs)} unique secure bypass configs")
            bypass_all_txt_files = split_file_by_size(bypass_all_txt_path, max_size_mb=49.0)
        except Exception as e:
            log(f"Error creating bypass-all-raw.txt: {e}")
            bypass_all_txt_files = []
    timing['bypass_files'] = time.time() - start

    # Step 6: Split bypass configs into multiple files (will be populated after verification)
    bypass_files = []

    # Step 7: Create bypass-unsecure raw file (untested configs in /raw/ subfolder)
    log("Creating bypass-unsecure raw file...")
    start = time.time()
    # Apply SNI/CIDR filtering to main configs (regular + base64 + yaml) without secure filtering
    sni_cidr_filtered_unsecure_configs = apply_sni_cidr_filter(all_configs, filter_secure=False)
    # Add extra bypass configs (without SNI/CIDR filtering and without secure filtering)
    all_bypass_unsecure_configs = sni_cidr_filtered_unsecure_configs + extra_bypass_configs
    unique_bypass_unsecure_configs = deduplicate_configs(all_bypass_unsecure_configs)

    bypass_unsecure_all_txt_path = f"{output_dir}/bypass-unsecure/raw/bypass-unsecure-all-raw.txt"
    
    # Pre-calculate if splitting needed to avoid double-write
    estimated_size = sum(len(cfg) + 1 for cfg in unique_bypass_unsecure_configs)
    max_size_bytes = int(49.0 * 1024 * 1024)
    
    if estimated_size > max_size_bytes:
        log(f"Estimated size ({estimated_size / (1024*1024):.2f} MB) exceeds limit, splitting directly")
        num_files_needed = math.ceil(estimated_size / max_size_bytes)
        max_configs_per_file = max(1, len(unique_bypass_unsecure_configs) // num_files_needed)
        # Don't add suffix to raw split files - they're intermediate
        bypass_unsecure_all_txt_files = split_configs_to_files(unique_bypass_unsecure_configs, f"{output_dir}/bypass-unsecure/raw", "bypass-unsecure-all-raw", max_configs_per_file=max_configs_per_file, add_suffix=False)
    else:
        try:
            os.makedirs(os.path.dirname(bypass_unsecure_all_txt_path), exist_ok=True)
            header = get_subscription_header("bypass-unsecure-all-raw")
            # Don't add suffix to raw files - they're intermediate and will be read for verification
            with open(bypass_unsecure_all_txt_path, "w", encoding="utf-8", buffering=65536) as f:
                f.write(header + "\n".join(unique_bypass_unsecure_configs))
            log(f"Created {bypass_unsecure_all_txt_path} with {len(unique_bypass_unsecure_configs)} unique unsecure bypass configs")
            bypass_unsecure_all_txt_files = split_file_by_size(bypass_unsecure_all_txt_path, max_size_mb=49.0)
        except Exception as e:
            log(f"Error creating bypass-unsecure-all-raw.txt: {e}")
            bypass_unsecure_all_txt_files = []
    timing['bypass_unsecure_files'] = time.time() - start

    # Step 8: Split bypass-unsecure configs into multiple files (will be populated after verification)
    bypass_unsecure_files = []

# Step 9: Create protocol-specific files
    log("Creating protocol-specific files...")
    all_protocol_configs = all_configs + extra_bypass_configs  # Include extra bypass configs in protocol splitting
    protocol_files = create_protocol_split_files(all_protocol_configs, output_dir)

    # Step 10: Process Telegram proxies (already collected during download - no re-download needed!)
    log("Processing Telegram proxies (collected during config download)...")
    start = time.time()
    telegram_proxy_processor = TelegramProxyProcessor(output_dir)
    
    # Load manual proxies and merge with scanned proxies
    manual_mtproto, manual_socks5 = telegram_proxy_processor.load_manual_proxies()
    
    if manual_mtproto:
        log(f"Merging {len(manual_mtproto)} manual MTProto proxies")
        mtproto_proxies = list(set(mtproto_proxies + manual_mtproto))
    
    if manual_socks5:
        log(f"Merging {len(manual_socks5)} manual SOCKS5 proxies")
        socks5_proxies = list(set(socks5_proxies + manual_socks5))
    
    # Also scan dedicated telegram proxy URLs (these weren't in the main config URLs)
    if TELEGRAM_PROXY_URLS:
        log(f"Scanning {len(TELEGRAM_PROXY_URLS)} dedicated Telegram proxy URLs...")
        tg_mtproto, tg_socks5 = telegram_proxy_processor.scan_urls_for_proxies(TELEGRAM_PROXY_URLS)
        if tg_mtproto:
            mtproto_proxies = list(set(mtproto_proxies + tg_mtproto))
        if tg_socks5:
            socks5_proxies = list(set(socks5_proxies + tg_socks5))
    
    # Create proxy files with verification
    telegram_proxy_files = telegram_proxy_processor.create_proxy_files(
        mtproto_proxies, socks5_proxies, 
        verify_mtproto=True, verify_socks5=True,
        max_workers=200  # High concurrency for faster verification
    )
    timing['telegram_proxy_verification'] = time.time() - start

    # Prepare file pairs for upload
    file_pairs = []

    # Add numbered default files
    for numbered_file in numbered_default_files:
        filename = os.path.basename(numbered_file)
        file_pairs.append((numbered_file, f"githubmirror/default/{filename}"))

    # Add default files
    for all_txt_file in all_txt_files:
        if all_txt_file:
            filename = os.path.basename(all_txt_file)
            # Use original name for single file, or split name for multiple files
            file_pairs.append((all_txt_file, f"githubmirror/default/{filename}"))
    
    for all_secure_txt_file in all_secure_txt_files:
        if all_secure_txt_file:
            filename = os.path.basename(all_secure_txt_file)
            file_pairs.append((all_secure_txt_file, f"githubmirror/default/{filename}"))

    # Add bypass raw files
    for bypass_file in bypass_all_txt_files:
        if bypass_file:
            filename = os.path.basename(bypass_file)
            file_pairs.append((bypass_file, f"githubmirror/bypass/raw/{filename}"))

    # Add bypass-unsecure raw files
    for bypass_unsecure_file in bypass_unsecure_all_txt_files:
        if bypass_unsecure_file:
            filename = os.path.basename(bypass_unsecure_file)
            file_pairs.append((bypass_unsecure_file, f"githubmirror/bypass-unsecure/raw/{filename}"))

# Add protocol files (already in correct format)
    file_pairs.extend(protocol_files)

    # Add Telegram proxy files
    for proxy_file in telegram_proxy_files:
        filename = os.path.basename(proxy_file)
        file_pairs.append((proxy_file, f"githubmirror/tg-proxy/{filename}"))
    
    # Step 11: Create verified working config files (sorted by ping)
    log("Creating verified working config files...")
    start = time.time()
    verified_bypass_files, verified_bypass_unsecure_files = create_working_config_files(output_dir)
    timing['bypass_verification'] = time.time() - start
    
    # Add verified bypass files to file_pairs
    for bypass_file in verified_bypass_files:
        filename = os.path.basename(bypass_file)
        file_pairs.append((bypass_file, f"githubmirror/bypass/{filename}"))
    
    # Add verified bypass-unsecure files to file_pairs
    for bypass_file in verified_bypass_unsecure_files:
        filename = os.path.basename(bypass_file)
        file_pairs.append((bypass_file, f"githubmirror/bypass-unsecure/{filename}"))
    
    # Add main verified files (bypass-all.txt and bypass-unsecure-all.txt)
    file_pairs.append((f"{output_dir}/bypass/bypass-all.txt", "githubmirror/bypass/bypass-all.txt"))
    file_pairs.append((f"{output_dir}/bypass-unsecure/bypass-unsecure-all.txt", "githubmirror/bypass-unsecure/bypass-unsecure-all.txt"))

    # Print timing summary
    overall_elapsed = time.time() - overall_start
    log("")
    log("=" * 60)
    log("TIMING SUMMARY")
    log("=" * 60)
    log(f"Fetching URLs (download):          {timing.get('fetch_urls', 0):>8.2f}s")
    log(f"Create all.txt files:              {timing.get('all_txt', 0):>8.2f}s")
    log(f"Create all-secure.txt files:       {timing.get('all_secure_txt', 0):>8.2f}s")
    log(f"Create bypass files:               {timing.get('bypass_files', 0):>8.2f}s")
    log(f"Create bypass-unsecure files:      {timing.get('bypass_unsecure_files', 0):>8.2f}s")
    log(f"Verification of Telegram proxies:  {timing.get('telegram_proxy_verification', 0):>8.2f}s")
    log(f"Verification of bypass configs:    {timing.get('bypass_verification', 0):>8.2f}s")
    log("-" * 60)
    log(f"OVERALL TOTAL:                     {overall_elapsed:>8.2f}s")
    log("=" * 60)
    log("")

    return file_pairs