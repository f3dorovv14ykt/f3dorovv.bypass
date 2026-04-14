"""Main module for VPN config generator with refactored, streamlined logic."""

import os
import sys
import argparse
import signal

os.environ['PYTHONUNBUFFERED'] = '1'
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from utils.logger import log, print_logs
from utils.download_xray import ensure_xray_installed
from processors.config_processor import process_all_configs
from utils.github_handler import GitHubHandler
from utils.proxy_detector import find_active_proxy_port, get_proxy_info
from utils.ip_verifier import verify_protection


def _signal_handler(signum, frame):
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    log("\nInterrupted, cleaning up...")
    from utils.ip_verifier import _cleanup_all_processes
    _cleanup_all_processes()
    sys.exit(0)


# Register signal handlers for graceful shutdown
signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


def main(dry_run: bool = False, output_dir: str = "../githubmirror", skip_xray: bool = False, use_git: bool = False, no_proxy_check: bool = False, proxy_url: str = None, proxy_chain: str = None):
    """Main execution function.
    
    Args:
        dry_run: Only download and save locally, don't upload/commit
        output_dir: Output directory for generated files
        skip_xray: Skip Xray-core download/use (TCP-only verification)
        use_git: Use git commands for committing instead of GitHub API
        no_proxy_check: Skip proxy detection/verification
        proxy_url: Single proxy URL to use
        proxy_chain: Comma-separated proxy chain (proxy1,proxy2)
    """
    log("Starting VPN config generation...")
    
    # Setup proxy if provided
    proxy_socks_port = None
    proxy_cleanup_needed = False
    proxy_monitor = None
    
    if proxy_chain:
        # Proxy chain mode - validate input first
        chain_list = [p.strip() for p in proxy_chain.split(',') if p.strip()]
        if len(chain_list) < 2:
            log("ERROR: --proxy-chain requires at least 2 comma-separated proxy URLs")
            sys.exit(1)
        
        log(f"Setting up proxy chain: {len(chain_list)} hops (EXPERIMENTAL)")
        from utils.ip_verifier import setup_proxy_chain, ProxyMonitor
        result = setup_proxy_chain(chain_list, timeout=8.0)
        
        if result['active']:
            proxy_cleanup_needed = True
            log(f"[OK] Proxy chain SUCCESSFUL: {result['proxy_ip']} ({result.get('country', 'Unknown')})")
            if result.get('socks_port'):
                proxy_socks_port = result['socks_port']
                log(f"[OK] SOCKS proxy on port {proxy_socks_port}")
            
            # Start monitoring (pass real IP to verify it stays hidden)
            proxy_monitor = ProxyMonitor(result['socks_port'], result['real_ip'], check_interval=30)
            proxy_monitor.start()
            
            # DON'T block on monitor - it runs in background
            # Main thread continues with config fetching
            log("\nProxy chain active (EXPERIMENTAL), starting config generation...\n")
        else:
            log(f"[FAIL] FAILED to setup proxy chain!")
            if result.get('error'):
                log(f"  Error: {result['error']}")
            log("")
            log("Possible causes:")
            log("  • One of the proxy servers is offline or unreachable")
            log("  • Network connectivity issues")
            log("  • Invalid proxy configuration")
            log("")
            log("What to do:")
            log("  1. Check that both proxy servers are working")
            log("  2. Try different proxy servers")
            log("  3. Run the command again with new proxies")
            log("")
            log("Example:")
            log("  python main.py --proxy-chain=\"vless://new1@server1:443,vless://new2@server2:443\"")
            sys.exit(1)
            
    elif proxy_url:
        # Single proxy mode
        log(f"Setting up proxy: {proxy_url.split('://')[0]}://***...")
        from utils.ip_verifier import setup_global_proxy
        result = setup_global_proxy(proxy_url, timeout=8.0)
        
        if result['active']:
            proxy_cleanup_needed = True
            log(f"[OK] Proxy connection SUCCESSFUL: {result['proxy_ip']} ({result.get('country', 'Unknown')})")
            if result.get('socks_port'):
                proxy_socks_port = result['socks_port']
                log(f"[OK] SOCKS proxy running on port {proxy_socks_port}")
        else:
            log(f"[FAIL] FAILED to connect through proxy!")
            if result.get('error'):
                log(f"  Error: {result['error']}")
            log("ERROR: Proxy verification failed. Check your config and try again.")
            sys.exit(1)
    elif not no_proxy_check:
        # Auto-detect proxy
        log("Checking for active proxy...")
        proxy_port = find_active_proxy_port()
        
        if proxy_port:
            proxy_info = get_proxy_info()
            log(f"Proxy detected on port {proxy_port}")
            
            # Verify proxy actually hides IP
            log("Verifying proxy protection...")
            protection = verify_protection(proxy_port=proxy_port, timeout=5.0)
            
            if protection['active']:
                log(f"Proxy protection ACTIVE: {protection['proxy_ip']} ({protection.get('country', 'Unknown')})")
            else:
                log(f"WARNING: Proxy not protecting IP!")
                log(f"  Proxy IP: {protection['proxy_ip']}")
                log(f"  IPs are the same - proxy may not be working!")
                log("Continuing anyway (use --no-proxy-check to skip this check)")
        else:
            log("WARNING: No active proxy detected on common ports (10808, 2080, 7890, etc.)")
            log("Connect to VPN first, or use --proxy=<url> or --no-proxy-check")
    
    # Download and install Xray-core if not present (unless skipped)
    if not skip_xray:
        xray_path = ensure_xray_installed()
        if xray_path:
            log(f"Xray-core ready: {xray_path}")
        else:
            log("Warning: Xray-core not installed. Will use TCP-only verification (slower).")

    # Process all configs following the new streamlined approach
    file_pairs = process_all_configs(output_dir)

    # Upload/commit files to GitHub if not in dry-run mode
    try:
        if not dry_run and file_pairs:
            if use_git:
                from utils.git_updater import GitUpdater
                updater = GitUpdater()
                success = updater.commit_and_push_files(file_pairs)
                if not success:
                    log("ERROR: Git update failed")
                    sys.exit(1)
            else:
                github_handler = GitHubHandler()
                failures = github_handler.upload_multiple_files(file_pairs)
                if failures > 0:
                    log(f"ERROR: {failures} upload(s) failed")
                    sys.exit(1)
    except Exception as e:
        log(f"ERROR: GitHub upload failed: {e}")
        sys.exit(1)
    finally:
        # Stop proxy monitor first
        if proxy_monitor:
            proxy_monitor.running = False
            try:
                proxy_monitor.stop()
            except Exception:
                pass
        # Always cleanup proxy resources if proxy was set
        if proxy_cleanup_needed:
            try:
                _cleanup_proxy()
            except Exception as e:
                log(f"Cleanup warning: {e}")
    
    print_logs()
    log("VPN config generation completed!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download configs and upload to GitHub")
    parser.add_argument("--dry-run", action="store_true", help="Only download and save locally, don't upload to GitHub")
    parser.add_argument("--skip-xray", action="store_true", help="Skip Xray-core download/use (TCP-only verification)")
    parser.add_argument("--use-git", action="store_true", help="Use git commands for committing (for GitHub Actions)")
    parser.add_argument("--no-proxy-check", action="store_true", help="Skip proxy detection and IP protection verification")
    parser.add_argument("--proxy", type=str, dest="proxy_url", help="Single proxy URL to use (vless://, socks5://, etc.)")
    parser.add_argument("--proxy-chain", type=str, dest="proxy_chain", help="Proxy chain: comma-separated URLs (proxy1,proxy2) for chained routing")
    args = parser.parse_args()

    main(
        dry_run=args.dry_run,
        skip_xray=args.skip_xray,
        use_git=args.use_git,
        no_proxy_check=args.no_proxy_check,
        proxy_url=args.proxy_url,
        proxy_chain=args.proxy_chain
    )
