"""Module for fetching VPN configs from daily-updated repository."""

import datetime
import base64
import concurrent.futures
from typing import List, Optional
from urllib.parse import urljoin
import sys
import os

# Add the source directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fetchers.fetcher import fetch_data
from utils.logger import log
from utils.file_utils import prepare_config_content


def generate_date_filenames(date: datetime.date) -> List[str]:
    """Generate filenames in format v2YYYYMMDD1, v2YYYYMMDD2 based on the given date."""
    return [
        f"v2{date.strftime('%Y%m%d')}1",
        f"v2{date.strftime('%Y%m%d')}2",
    ]


def fetch_daily_configs(base_url: str, date: datetime.date) -> Optional[List[str]]:
    """Fetch configs from daily-updated repository for a specific date."""
    filenames = generate_date_filenames(date)
    all_configs = []
    
    for filename in filenames:
        url = urljoin(base_url, filename)

        try:
            content = fetch_data(url)
            # Check if content is base64-encoded (common for VPN config repositories)
            try:
                # Try to decode as base64
                decoded_bytes = base64.b64decode(content.strip())
                decoded_content = decoded_bytes.decode('utf-8')
                configs = prepare_config_content(decoded_content)
            except Exception:
                # If base64 decoding fails, treat as plain text
                configs = prepare_config_content(content)

            if configs:
                log(f"Successfully fetched {len(configs)} configs from {url}")
                all_configs.extend(configs)
        except Exception as e:
            # Silently try next filename
            pass
    
    if all_configs:
        log(f"Total for date {date}: {sum(len(c) for c in all_configs)} configs from {len(all_configs)} files")
        return all_configs
    
    return None


def fetch_daily_configs_with_timezone_fallback(base_url: str, target_date: Optional[datetime.date] = None) -> List[str]:
    """Fetch configs from daily-updated repository with parallel date fetching.

    Tries to fetch configs from multiple dates in PARALLEL for maximum speed.
    Fetches until successfully getting configs from 10 different dates.

    Returns combined configs from up to 10 successful fetches, or empty list if all attempts fail.
    """
    if target_date is None:
        target_date = datetime.date.today()

    all_configs = []
    successful_fetches = 0
    max_fetches = 10
    
    # Build list of dates to try (today, tomorrow, then past 30 days)
    dates_to_try = []
    dates_to_try.append(target_date)  # today
    dates_to_try.append(target_date + datetime.timedelta(days=1))  # tomorrow
    
    # Add past dates (up to 30 days back)
    for i in range(1, 31):
        dates_to_try.append(target_date - datetime.timedelta(days=i))
    
    # PARALLEL FETCH: Try multiple dates simultaneously
    import concurrent.futures
    from fetchers.fetcher import fetch_data
    
    log(f"Fetching configs from {len(dates_to_try)} dates in parallel...")
    
    def fetch_date(date: datetime.date) -> tuple:
        """Fetch configs for a single date."""
        filenames = generate_date_filenames(date)
        date_configs = []
        
        for filename in filenames:
            url = urljoin(base_url, filename)
            try:
                content = fetch_data(url)
                # Try base64 decode
                try:
                    decoded_bytes = base64.b64decode(content.strip())
                    decoded_content = decoded_bytes.decode('utf-8')
                    configs = prepare_config_content(decoded_content)
                except:
                    configs = prepare_config_content(content)
                
                if configs:
                    date_configs.extend(configs)
            except:
                pass
        
        return (date, date_configs)
    
    # Fetch dates in parallel (up to 10 at a time)
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_date = {executor.submit(fetch_date, date): date for date in dates_to_try}
        
        for future in concurrent.futures.as_completed(future_to_date):
            if successful_fetches >= max_fetches:
                break
            
            try:
                date, date_configs = future.result()
                if date_configs:
                    log(f"Fetched {len(date_configs)} configs for {date} ({'/'.join(generate_date_filenames(date))})")
                    all_configs.extend(date_configs)
                    successful_fetches += 1
            except Exception as e:
                pass
    
    log(f"Completed fetching. Successfully fetched configs from {successful_fetches} different dates")
    if not all_configs:
        log(f"No configs found after trying multiple dates")

    return all_configs


def fetch_configs_from_daily_repo(base_url: str = "https://raw.githubusercontent.com/free-nodes/v2rayfree/refs/heads/main/") -> List[str]:
    """Main function to fetch configs from the daily-updated repository."""
    log(f"Fetching configs from daily-updated repository: {base_url}")
    configs = fetch_daily_configs_with_timezone_fallback(base_url)
    log(f"Total configs fetched from daily repository: {len(configs)}")
    return configs