"""Test script to measure ping speed for bypass-all configs using main logic."""

import os
import sys
import time
import tempfile

os.environ['PYTHONUNBUFFERED'] = '1'
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from utils.logger import log
from utils.download_xray import ensure_xray_installed
from processors.config_processor import _verify_config_file


def test_ping_speed(config_count: int = 1000):
    """Test ping speed with specified number of configs using main logic."""
    
    # Ensure Xray is installed for current platform
    xray_path = ensure_xray_installed()
    if not xray_path:
        log("❌ Xray not found and couldn't be downloaded")
        return
    
    log(f"✅ Using Xray: {xray_path}")
    
    bypass_all_path = "../githubmirror/bypass/bypass-all.txt"
    output_path = "../githubmirror/bypass/bypass-all-working.txt"
    
    if not os.path.exists(bypass_all_path):
        log(f"Error: {bypass_all_path} not found")
        return
    
    with open(bypass_all_path, 'r', encoding='utf-8') as f:
        all_configs = [line.strip() for line in f if line.strip()]
    
    if len(all_configs) < config_count:
        log(f"Warning: Only {len(all_configs)} configs available, using all")
        config_count = len(all_configs)
    
    test_configs = all_configs[:config_count]
    
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
    temp_file.write('\n'.join(test_configs))
    temp_file.close()
    temp_path = temp_file.name
    
    log(f"Testing {len(test_configs)} configs from bypass-all.txt...")
    log("Using same logic as main: _verify_config_file()")
    
    start_time = time.time()
    
    working_configs = _verify_config_file(temp_path)
    
    elapsed_time = time.time() - start_time
    
    os.unlink(temp_path)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(working_configs))
    
    log(f"\n{'='*60}")
    log(f"RESULTS:")
    log(f"{'='*60}")
    log(f"Total configs tested: {len(test_configs)}")
    log(f"Working configs: {len(working_configs)}")
    log(f"Failed configs: {len(test_configs) - len(working_configs)}")
    log(f"Success rate: {len(working_configs) / len(test_configs) * 100:.1f}%")
    log(f"Total time: {elapsed_time:.2f} seconds")
    log(f"Average time per config: {elapsed_time / len(test_configs):.3f} seconds")
    log(f"Configs per second: {len(test_configs) / elapsed_time:.2f}")
    log(f"Output saved to: {output_path}")
    log(f"{'='*60}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Test ping speed for bypass configs")
    parser.add_argument("--count", type=int, default=1000, help="Number of configs to test")
    args = parser.parse_args()
    
    test_ping_speed(args.count)
