#!/usr/bin/env python3
"""
Cleanup script: Fetch all URLs from URLS.txt and remove those that return 404 errors.
Preserves the section structure (# default, # extra for bypass, etc.)
"""

import os
import sys
from curl_cffi import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
URLS_FILE = os.path.join(os.path.dirname(__file__), 'config', 'URLS.txt')
TIMEOUT = 7  # Seconds to wait for each URL
MAX_WORKERS = 32  # Concurrent URL checks
DRY_RUN = False  # Set to True to preview changes without modifying file


def check_url(url: str) -> tuple[str, int, bool]:
    """
    Check if URL is accessible.
    
    Returns:
        (url, status_code, is_alive)
    """
    try:
        response = requests.get(url, timeout=TIMEOUT)
        status_code = response.status_code
        
        # Consider 200, 301, 302 as alive
        is_alive = status_code in [200, 301, 302]
        
        return (url, status_code, is_alive)
    
    except Exception as e:
        # Various errors: timeout, connection refused, DNS failure, etc.
        return (url, 0, False)


def parse_urls_with_sections(filepath: str) -> list[tuple[str, str]]:
    """
    Parse URLS.txt preserving section information.
    
    Returns:
        List of (url_or_line, section_name) tuples
        For non-URL lines (comments, empty), section_name is 'marker' or 'empty'
    """
    result = []
    current_section = 'default'
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line_stripped = line.strip()
            
            # Empty line
            if not line_stripped:
                result.append(('', 'empty'))
                continue
            
            # Section marker
            if line_stripped.startswith('# '):
                section_name = line_stripped[2:].strip().lower()
                if 'base64' in section_name:
                    current_section = 'base64'
                elif 'yaml' in section_name:
                    current_section = 'yaml'
                elif 'telegram' in section_name or 'tg' in section_name:
                    current_section = 'telegram'
                elif 'extra' in section_name or 'bypass' in section_name:
                    current_section = 'extra_bypass'
                else:
                    current_section = 'default'
                result.append((line.rstrip('\n'), 'marker'))
                continue
            
            # Comment line (not a marker)
            if line_stripped.startswith('#'):
                result.append((line.rstrip('\n'), 'comment'))
                continue
            
            # URL line
            result.append((line.rstrip('\n'), current_section))
    
    return result


def main():
    print("="*60)
    print("URLS.txt Dead URL Cleanup Script")
    print("="*60)
    print(f"URLS file: {URLS_FILE}")
    print(f"Timeout: {TIMEOUT}s per URL")
    print(f"Concurrent workers: {MAX_WORKERS}")
    print(f"Dry run: {DRY_RUN}")
    print("="*60)
    
    if not os.path.exists(URLS_FILE):
        print(f"ERROR: File not found: {URLS_FILE}")
        sys.exit(1)
    
    # Parse URLS.txt
    print("\nParsing URLS.txt...")
    parsed_lines = parse_urls_with_sections(URLS_FILE)
    
    # Extract only URL lines for checking
    urls_to_check = [(line, section) for line, section in parsed_lines 
                     if section not in ['marker', 'empty', 'comment']]
    
    print(f"Found {len(urls_to_check)} URLs to check")
    
    # Check all URLs in parallel
    print(f"\nChecking URLs (this may take a while)...")
    results = {}
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(check_url, url): url 
                        for url, section in urls_to_check}
        
        completed = 0
        total = len(future_to_url)
        
        for future in as_completed(future_to_url):
            url, status_code, is_alive = future.result()
            results[url] = (status_code, is_alive)
            completed += 1
            
            if completed % 50 == 0 or completed == total:
                alive = sum(1 for _, (_, alive) in results.items() if alive)
                dead = sum(1 for _, (_, alive) in results.items() if not alive)
                print(f"  Progress: {completed}/{total} - Alive: {alive}, Dead: {dead}")
    
    # Categorize results
    alive_urls = [url for url, (_, is_alive) in results.items() if is_alive]
    dead_urls = [url for url, (_, is_alive) in results.items() if not is_alive]
    
    print("\n" + "="*60)
    print("RESULTS:")
    print("="*60)
    print(f"Total URLs checked: {len(results)}")
    print(f"Alive URLs: {len(alive_urls)} ({len(alive_urls)/len(results)*100:.1f}%)")
    print(f"Dead URLs: {len(dead_urls)} ({len(dead_urls)/len(results)*100:.1f}%)")
    
    if dead_urls:
        print("\n" + "-"*60)
        print("Dead URLs (will be removed):")
        print("-"*60)
        for url in dead_urls:
            status, _ = results[url]
            status_str = f"HTTP {status}" if status > 0 else "Connection Error"
            print(f"  [{status_str}] {url[:80]}...")
    
    # Show what will be kept
    print("\n" + "-"*60)
    print("Alive URLs (will be kept):")
    print("-"*60)
    print(f"  {len(alive_urls)} URLs will remain in URLS.txt")
    
    if DRY_RUN:
        print("\n" + "="*60)
        print("DRY RUN MODE - No changes made")
        print("="*60)
        print("\nTo actually remove dead URLs, set DRY_RUN = False in this script")
        return
    
    # Write cleaned URLS.txt
    print("\n" + "="*60)
    print("Writing cleaned URLS.txt...")
    print("="*60)
    
    backup_file = URLS_FILE + '.backup'
    print(f"Creating backup: {backup_file}")
    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        original_content = f.read()
    with open(backup_file, 'w', encoding='utf-8') as f:
        f.write(original_content)
    
    # Rebuild URLS.txt preserving structure
    with open(URLS_FILE, 'w', encoding='utf-8') as f:
        for line, section in parsed_lines:
            if section in ['marker', 'empty', 'comment']:
                # Keep markers, comments, and preserve empty lines between sections
                f.write(line + '\n')
            else:
                # It's a URL - only write if alive
                if results.get(line, (0, False))[1]:  # is_alive
                    f.write(line + '\n')
    
    print(f"\n✅ URLS.txt cleaned successfully!")
    print(f"   Removed: {len(dead_urls)} dead URLs")
    print(f"   Kept: {len(alive_urls)} alive URLs")
    print(f"   Backup saved to: {backup_file}")
    
    # Clean up consecutive empty lines (more than 2)
    print("\nCleaning up excessive empty lines...")
    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    cleaned_lines = []
    empty_count = 0
    for line in lines:
        if line.strip() == '':
            empty_count += 1
            if empty_count <= 2:  # Keep up to 2 consecutive empty lines
                cleaned_lines.append(line)
        else:
            empty_count = 0
            cleaned_lines.append(line)
    
    with open(URLS_FILE, 'w', encoding='utf-8') as f:
        f.writelines(cleaned_lines)
    
    print("✅ Cleanup complete!")
    print("\n" + "="*60)
    print("SUMMARY:")
    print("="*60)
    print(f"Before: {len(results)} URLs")
    print(f"After:  {len(alive_urls)} URLs")
    print(f"Removed: {len(dead_urls)} dead URLs ({len(dead_urls)/len(results)*100:.1f}%)")
    print("="*60)


if __name__ == '__main__':
    main()
