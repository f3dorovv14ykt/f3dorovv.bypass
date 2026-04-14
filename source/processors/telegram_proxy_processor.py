"""Telegram proxy processor module for handling proxy collection and file generation."""

import os
from typing import List, Tuple, Dict
import concurrent.futures

from config.settings import TELEGRAM_PROXY_URLS, DEFAULT_MAX_WORKERS
from fetchers.fetcher import fetch_data
from fetchers.telegram_proxy_scraper import TelegramProxyScraper
from utils.logger import log


class TelegramProxyProcessor:
    """Processes Telegram proxies from various sources."""

    def __init__(self, output_dir: str = "../githubmirror"):
        self.output_dir = output_dir
        self.scraper = TelegramProxyScraper()
    
    def load_manual_proxies(self, filepath: str = None) -> Tuple[List[str], List[str]]:
        """
        Load manual proxies from a text file.
        
        Args:
            filepath: Path to the file with manual proxy URLs. If None, uses default location.
            
        Returns:
            Tuple[List[str], List[str]]: (mtproto_proxies, socks5_proxies)
        """
        if filepath is None:
            # Default location relative to source directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            filepath = os.path.join(script_dir, "..", "config", "tg_proxies.txt")
        
        if not os.path.exists(filepath):
            log(f"Manual proxies file not found: {filepath}")
            return [], []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            mtproto_proxies, socks5_proxies = self.scraper.extract_proxies(content)
            
            # Deduplicate
            mtproto_proxies = self.scraper.deduplicate_proxies(mtproto_proxies)
            socks5_proxies = self.scraper.deduplicate_proxies(socks5_proxies)
            
            log(f"Loaded {len(mtproto_proxies)} MTProto and {len(socks5_proxies)} SOCKS5 manual proxies from {os.path.basename(filepath)}")
            
            return mtproto_proxies, socks5_proxies
            
        except Exception as e:
            log(f"Error loading manual proxies: {str(e)}")
            return [], []
    
    def scan_content_for_proxies(self, content_list: List[str]) -> Tuple[List[str], List[str]]:
        """
        Scan a list of content strings for Telegram proxy links.
        
        Args:
            content_list: List of content strings to scan for proxies
            
        Returns:
            Tuple[List[str], List[str]]: (mtproto_proxies, socks5_proxies)
        """
        all_mtproto_proxies = []
        all_socks5_proxies = []
        
        log(f"Scanning {len(content_list)} content items for Telegram proxies...")
        
        for i, content in enumerate(content_list):
            if not content.strip():
                continue

            try:
                # Extract proxies from content
                mtproto_proxies, socks5_proxies = self.scraper.extract_proxies(content)

                all_mtproto_proxies.extend(mtproto_proxies)
                all_socks5_proxies.extend(socks5_proxies)

                if mtproto_proxies or socks5_proxies:
                    log(f"Found {len(mtproto_proxies)} MTProto and {len(socks5_proxies)} SOCKS5 proxies in content item {i+1}")

            except Exception as e:
                log(f"Error scanning content item {i+1} for proxies: {str(e)[:200]}...")
        
        # Deduplicate proxies
        unique_mtproto = self.scraper.deduplicate_proxies(all_mtproto_proxies)
        unique_socks5 = self.scraper.deduplicate_proxies(all_socks5_proxies)
        
        log(f"Total unique proxies found: {len(unique_mtproto)} MTProto, {len(unique_socks5)} SOCKS5")
        
        return unique_mtproto, unique_socks5
    
    def scan_urls_for_proxies(self, url_list: List[str]) -> Tuple[List[str], List[str]]:
        """
        Download and scan URLs for Telegram proxy links.
        
        Args:
            url_list: List of URLs to download and scan
            
        Returns:
            Tuple[List[str], List[str]]: (mtproto_proxies, socks5_proxies)
        """
        all_mtproto_proxies = []
        all_socks5_proxies = []
        
        if not url_list:
            return [], []
        
        log(f"Scanning {len(url_list)} URLs for Telegram proxies...")
        
        import concurrent.futures
        
        urls_with_proxies = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(1, len(url_list)))) as executor:
            # Submit all futures
            future_to_url = {executor.submit(fetch_data, url): url for url in url_list}
            
            # Process completed futures
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    content = future.result()
                    url = future_to_url[future]
                    
                    # Extract proxies from content
                    mtproto_proxies, socks5_proxies = self.scraper.extract_proxies(content)
                    
                    all_mtproto_proxies.extend(mtproto_proxies)
                    all_socks5_proxies.extend(socks5_proxies)
                    
                    if mtproto_proxies or socks5_proxies:
                        urls_with_proxies += 1
                        log(f"Found {len(mtproto_proxies)} MTProto and {len(socks5_proxies)} SOCKS5 proxies in {url}")
                    
                except Exception as e:
                    url = future_to_url[future]
                    log(f"Error processing URL {url}: {str(e)[:200]}...")
        
        # Deduplicate proxies
        unique_mtproto = self.scraper.deduplicate_proxies(all_mtproto_proxies)
        unique_socks5 = self.scraper.deduplicate_proxies(all_socks5_proxies)
        
        log(f"Total from {len(url_list)} URLs: {len(unique_mtproto)} MTProto, {len(unique_socks5)} SOCKS5 (found in {urls_with_proxies} sources)")
        
        return unique_mtproto, unique_socks5

    def verify_proxies(self, proxy_urls: List[str], max_workers: int = 400) -> List[Tuple[str, float]]:
        """
        Verify proxies (both MTProto and SOCKS5) with HIGH CONCURRENCY.

        Args:
            proxy_urls: List of proxy URLs to verify
            max_workers: Maximum number of concurrent verification workers (default: 400)

        Returns:
            List of tuples (proxy_url, latency_ms) for working proxies
        """
        if not proxy_urls:
            return []

        log(f"Verifying {len(proxy_urls)} proxies with {max_workers} concurrent workers...")

        try:
            from utils.telegram_proxy_verifier import TelegramProxyVerifier
            import concurrent.futures
            
            verifier = TelegramProxyVerifier()

            def run_verification():
                return verifier.verify_proxy_list(proxy_urls, timeout=3.0, max_concurrent=max_workers)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_verification)
                try:
                    # Dynamic timeout: 10s minimum + 0.1s per proxy
                    dynamic_timeout = max(10, len(proxy_urls) * 0.1)
                    results = future.result(timeout=dynamic_timeout)
                except concurrent.futures.TimeoutError:
                    log(f"Proxy verification timed out after {dynamic_timeout}s")
                    return []

            # Extract working proxies with latency
            working_proxies = []
            for proxy_url, is_working, error_msg in results:
                if is_working:
                    # Extract latency from error_msg (format: "OK - 150ms")
                    latency = float('inf')
                    if "OK -" in error_msg:
                        try:
                            latency = float(error_msg.split("OK - ")[1].split("ms")[0])
                        except:
                            pass
                    working_proxies.append((proxy_url, latency))

            log(f"Proxy verification complete: {len(working_proxies)} working proxies")
            return working_proxies

        except Exception as e:
            log(f"Error during proxy verification: {str(e)}")
            return []

    def create_proxy_files(self, mtproto_proxies: List[Tuple[str, float]], socks5_proxies: List[Tuple[str, float]], verify_mtproto: bool = True, verify_socks5: bool = True, max_workers: int = 200) -> List[str]:
        """
        Create Telegram proxy files sorted by ping (fastest first).

        Args:
            mtproto_proxies: List of tuples (proxy_url, latency_ms) for MTProto
            socks5_proxies: List of tuples (proxy_url, latency_ms) for SOCKS5
            verify_mtproto: Whether to verify MTProto proxies before creating files
            verify_socks5: Whether to verify SOCKS5 proxies before creating files
            max_workers: Maximum concurrent verification workers (default: 200)

        Returns:
            List[str]: List of created file paths
        """
        # Verify MTProto proxies if requested
        if verify_mtproto and mtproto_proxies:
            # Convert to plain URLs for verification
            mtproto_urls = [p[0] if isinstance(p, tuple) else p for p in mtproto_proxies]
            mtproto_proxies = self.verify_proxies(mtproto_urls, max_workers=max_workers)
            log(f"MTProto verification: {len(mtproto_proxies)} working proxies")
        
        # Verify SOCKS5 proxies if requested
        if verify_socks5 and socks5_proxies:
            # Convert to plain URLs for verification
            socks5_urls = [p[0] if isinstance(p, tuple) else p for p in socks5_proxies]
            socks5_proxies = self.verify_proxies(socks5_urls, max_workers=max_workers)
            log(f"SOCKS5 verification: {len(socks5_proxies)} working proxies")
        
        # Sort by latency (fastest first)
        if mtproto_proxies:
            mtproto_proxies.sort(key=lambda x: x[1] if isinstance(x, tuple) else float('inf'))
            log(f"Sorted {len(mtproto_proxies)} MTProto proxies by ping (fastest first)")
        
        if socks5_proxies:
            socks5_proxies.sort(key=lambda x: x[1] if isinstance(x, tuple) else float('inf'))
            log(f"Sorted {len(socks5_proxies)} SOCKS5 proxies by ping (fastest first)")
        
        # Extract just URLs for file writing
        mtproto_urls = [p[0] if isinstance(p, tuple) else p for p in mtproto_proxies]
        socks5_urls = [p[0] if isinstance(p, tuple) else p for p in socks5_proxies]
        
        # Combine all proxies and sort by ping (fastest first)
        all_combined = mtproto_proxies + socks5_proxies
        all_combined.sort(key=lambda x: x[1] if isinstance(x, tuple) else float('inf'))
        all_urls = [p[0] for p in all_combined]
        
        if all_urls:
            log(f"Sorted {len(all_urls)} total proxies by ping (fastest first)")

        # Create tg-proxy directory
        tg_proxy_dir = f"{self.output_dir}/tg-proxy"
        os.makedirs(tg_proxy_dir, exist_ok=True)

        created_files = []

        # Create all.txt with all working proxies (sorted by ping)
        all_txt_path = f"{self.output_dir}/tg-proxy/all.txt"
        try:
            with open(all_txt_path, "w", encoding="utf-8") as f:
                f.write("\n\n".join(all_urls))
            log(f"Created {all_txt_path} with {len(all_urls)} proxies (sorted by ping)")
            created_files.append(all_txt_path)
        except Exception as e:
            log(f"Error creating all.txt: {e}")

        # Create MTProto.txt with sorted MTProto proxies
        mtproto_txt_path = f"{self.output_dir}/tg-proxy/MTProto.txt"
        try:
            with open(mtproto_txt_path, "w", encoding="utf-8") as f:
                f.write("\n\n".join(mtproto_urls))
            log(f"Created {mtproto_txt_path} with {len(mtproto_urls)} MTProto proxies (sorted by ping)")
            created_files.append(mtproto_txt_path)
        except Exception as e:
            log(f"Error creating MTProto.txt: {e}")

        # Create socks.txt with sorted SOCKS5 proxies
        socks_txt_path = f"{self.output_dir}/tg-proxy/socks.txt"
        try:
            with open(socks_txt_path, "w", encoding="utf-8") as f:
                f.write("\n\n".join(socks5_urls))
            log(f"Created {socks_txt_path} with {len(socks5_urls)} SOCKS5 proxies (sorted by ping)")
            created_files.append(socks_txt_path)
        except Exception as e:
            log(f"Error creating socks.txt: {e}")

        return created_files

    def sort_proxies_by_speed(self, proxy_urls: List[str]) -> List[str]:
        """
        Sort proxies by speed (fastest first) using ping testing.
        Only returns working proxies, sorted from fastest to slowest.

        Args:
            proxy_urls: List of proxy URLs to sort

        Returns:
            List of working proxy URLs sorted by speed (fastest first)
        """
        if not proxy_urls:
            return proxy_urls

        try:
            from utils.telegram_proxy_verifier import ProxySpeedTester
            import asyncio

            # Create speed tester instance
            speed_tester = ProxySpeedTester()

            # Run async speed testing
            async def run_speed_test():
                results = await speed_tester.test_proxy_speeds(proxy_urls, timeout=5.0, max_concurrent=100)
                # Filter only working proxies and sort by latency (fastest first)
                working_results = [(proxy_url, latency) for proxy_url, latency, is_working, error_msg in results if is_working and latency is not None]
                # Sort by latency (ascending - fastest first)
                working_results.sort(key=lambda x: x[1])
                # Return only the proxy URLs in order
                return [proxy_url for proxy_url, latency in working_results]

            # Get sorted working proxies
            sorted_working_proxies = asyncio.run(run_speed_test())

            log(f"Sorted {len(proxy_urls)} proxies by speed, {len(sorted_working_proxies)} working proxies identified and sorted (fastest first)")

            return sorted_working_proxies
        except Exception as e:
            log(f"Error sorting proxies by speed: {str(e)}, returning original order")
            return proxy_urls
    
    def process_all_urls(self, all_urls: List[str], verify_mtproto: bool = True, verify_socks5: bool = True) -> List[str]:
        """
        Process ALL URL sources for Telegram proxies and create files.
        Also loads manual proxies from config file.

        Args:
            all_urls: List of all URLs to scan for telegram proxies
            verify_mtproto: Whether to verify MTProto proxies before creating files
            verify_socks5: Whether to verify SOCKS5 proxies before creating files

        Returns:
            List[str]: List of created file paths
        """
        log("Starting Telegram proxy processing from ALL URL sources...")

        # Download and process proxies from all URLs
        mtproto_proxies, socks5_proxies = self.scan_urls_for_proxies(all_urls)
        
        # Load manual proxies from config file
        manual_mtproto, manual_socks5 = self.load_manual_proxies()
        
        # Merge proxies
        if manual_mtproto:
            log(f"Merging {len(manual_mtproto)} manual MTProto proxies")
            mtproto_proxies = list(set(mtproto_proxies + manual_mtproto))
        
        if manual_socks5:
            log(f"Merging {len(manual_socks5)} manual SOCKS5 proxies")
            socks5_proxies = list(set(socks5_proxies + manual_socks5))
        
        log(f"Total proxies after merge: {len(mtproto_proxies)} MTProto, {len(socks5_proxies)} SOCKS5")

        # Create output files (verification and sorting happen inside create_proxy_files)
        created_files = self.create_proxy_files(mtproto_proxies, socks5_proxies, verify_mtproto=verify_mtproto, verify_socks5=verify_socks5)

        log("Telegram proxy processing from ALL URLs completed!")
        return created_files

    def process_all(self, verify_mtproto: bool = True, verify_socks5: bool = True) -> List[str]:
        """
        Process all Telegram proxy sources and create files.

        Args:
            verify_mtproto: Whether to verify MTProto proxies before creating files
            verify_socks5: Whether to verify SOCKS5 proxies before creating files

        Returns:
            List[str]: List of created file paths
        """
        log("Starting Telegram proxy processing...")

        # Download and process proxies
        mtproto_proxies, socks5_proxies = self.scan_urls_for_proxies(TELEGRAM_PROXY_URLS)
        
        # Load manual proxies
        manual_mtproto, manual_socks5 = self.load_manual_proxies()
        
        # Merge
        if manual_mtproto:
            mtproto_proxies = list(set(mtproto_proxies + manual_mtproto))
        if manual_socks5:
            socks5_proxies = list(set(socks5_proxies + manual_socks5))

        # Create output files (verification and sorting happen inside)
        created_files = self.create_proxy_files(mtproto_proxies, socks5_proxies, verify_mtproto=verify_mtproto, verify_socks5=verify_socks5)

        log("Telegram proxy processing completed!")
        return created_files