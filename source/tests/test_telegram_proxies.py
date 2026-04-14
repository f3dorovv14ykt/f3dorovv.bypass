"""Test script for Telegram proxy verification - follows same logic as main.py."""

import os
import sys
import time

os.environ['PYTHONUNBUFFERED'] = '1'
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from utils.logger import log
from processors.config_processor import process_all_configs
from utils.telegram_proxy_verifier import TelegramProxyVerifier
from utils.file_utils import prepare_config_content


def test_telegram_proxies(output_dir: str = "../githubmirror"):
    """Test Telegram proxies following same logic as main.py."""
    log("=" * 60)
    log("TELEGRAM PROXY VERIFICATION TEST")
    log("=" * 60)
    
    start_time = time.time()
    
    # Step 1: Fetch configs and extract Telegram proxies (same as main.py)
    # Note: download_all_configs always scans for telegram proxies
    log("\nStep 1/3: Fetching configs from all sources...")
    from processors.config_processor import download_all_configs
    from config.settings import TELEGRAM_PROXY_URLS
    from processors.telegram_proxy_processor import TelegramProxyProcessor
    
    all_configs, extra_bypass, numbered, mtproto_proxies, socks5_proxies = download_all_configs(
        output_dir, 
        scan_for_telegram_proxies=True
    )
    
    # Also load manual proxies from tg_proxies.txt (same as main.py line 579-591)
    telegram_proxy_processor = TelegramProxyProcessor()
    manual_mtproto, manual_socks5 = telegram_proxy_processor.load_manual_proxies()
    
    if manual_mtproto:
        log(f"Merging {len(manual_mtproto)} manual MTProto proxies from tg_proxies.txt")
        mtproto_proxies = list(set(mtproto_proxies + manual_mtproto))
    if manual_socks5:
        log(f"Merging {len(manual_socks5)} manual SOCKS5 proxies from tg_proxies.txt")
        socks5_proxies = list(set(socks5_proxies + manual_socks5))
    
    # Also scan dedicated telegram proxy URLs (same as main.py line 594-600)
    if TELEGRAM_PROXY_URLS:
        log(f"Scanning {len(TELEGRAM_PROXY_URLS)} dedicated Telegram proxy URLs...")
        tg_mtproto, tg_socks5 = telegram_proxy_processor.scan_urls_for_proxies(TELEGRAM_PROXY_URLS)
        if tg_mtproto:
            mtproto_proxies = list(set(mtproto_proxies + tg_mtproto))
        if tg_socks5:
            socks5_proxies = list(set(socks5_proxies + tg_socks5))
    
    log(f"Total VPN configs fetched: {len(all_configs)}")
    log(f"MTProto proxies extracted: {len(mtproto_proxies)}")
    log(f"SOCKS5 proxies extracted: {len(socks5_proxies)}")
    
    if not mtproto_proxies and not socks5_proxies:
        log("No Telegram proxies found to test!")
        return
    
    # Step 2: Verify proxies (same as main.py logic)
    log("\nStep 2/3: Verifying Telegram proxies...")
    verifier = TelegramProxyVerifier()
    
    all_mtproto = mtproto_proxies.copy()
    all_socks5 = socks5_proxies.copy()
    
    # Verify MTProto proxies
    if all_mtproto:
        log(f"\nVerifying {len(all_mtproto)} MTProto proxies...")
        mtproto_results = verifier.verify_proxy_list(
            all_mtproto,
            timeout=5,
            max_concurrent=200  # Same as main.py
        )
        
        working_mtproto = [url for url, ok, _ in mtproto_results if ok]
        log(f"MTProto results: {len(working_mtproto)}/{len(all_mtproto)} working ({len(working_mtproto)/len(all_mtproto)*100:.1f}%)")
    else:
        working_mtproto = []
        log("No MTProto proxies to verify")
    
    # Verify SOCKS5 proxies
    if all_socks5:
        log(f"\nVerifying {len(all_socks5)} SOCKS5 proxies...")
        socks5_results = verifier.verify_proxy_list(
            all_socks5,
            timeout=5,
            max_concurrent=200  # Same as main.py
        )
        
        working_socks5 = [url for url, ok, _ in socks5_results if ok]
        log(f"SOCKS5 results: {len(working_socks5)}/{len(all_socks5)} working ({len(working_socks5)/len(all_socks5)*100:.1f}%)")
    else:
        working_socks5 = []
        log("No SOCKS5 proxies to verify")
    
    # Step 3: Save results to files (same as main.py)
    log("\nStep 3/3: Saving results to files...")
    
    os.makedirs(f"{output_dir}/tg-proxy", exist_ok=True)
    
    # Save MTProto
    if working_mtproto:
        mtproto_path = f"{output_dir}/tg-proxy/mtproto.txt"
        with open(mtproto_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(working_mtproto))
        log(f"Saved {len(working_mtproto)} working MTProto proxies to {mtproto_path}")
    else:
        log("No working MTProto proxies to save")
    
    # Save SOCKS5
    if working_socks5:
        socks5_path = f"{output_dir}/tg-proxy/socks5.txt"
        with open(socks5_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(working_socks5))
        log(f"Saved {len(working_socks5)} working SOCKS5 proxies to {socks5_path}")
    else:
        log("No working SOCKS5 proxies to save")
    
    # Summary
    elapsed = time.time() - start_time
    total_proxies = len(all_mtproto) + len(all_socks5)
    total_working = len(working_mtproto) + len(working_socks5)
    
    log("\n" + "=" * 60)
    log("VERIFICATION SUMMARY")
    log("=" * 60)
    log(f"Total proxies tested: {total_proxies}")
    log(f"  - MTProto: {len(working_mtproto)}/{len(all_mtproto)} working")
    log(f"  - SOCKS5: {len(working_socks5)}/{len(all_socks5)} working")
    log(f"Total working: {total_working}/{total_proxies} ({total_working/total_proxies*100:.1f}% if total > 0 else 0)")
    log(f"Total time: {elapsed:.1f} seconds")
    if total_proxies > 0:
        log(f"Proxies per second: {total_proxies/elapsed:.1f}")
    log("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Test Telegram proxies")
    parser.add_argument("--output-dir", default="../githubmirror", help="Output directory")
    args = parser.parse_args()
    
    test_telegram_proxies(output_dir=args.output_dir)
