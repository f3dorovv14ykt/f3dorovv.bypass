#!/usr/bin/env python
"""Download Xray-core binary for config testing.

Supports: Windows (x86_64), Linux (x86_64, arm64), macOS (x86_64, arm64)
"""

import os
import sys
import platform
import urllib.request
import zipfile
import tarfile
import stat
from pathlib import Path

# Xray-core version to download
XRAY_VERSION = "v26.2.6"

# Base URL for Xray-core releases
GITHUB_RELEASES_URL = "https://github.com/XTLS/Xray-core/releases/download"


def get_platform_info():
    """Detect current platform and return download info.
    
    Returns:
        tuple: (platform_string, filename, xray_binary_name) or (None, None, None) if unsupported
    """
    system = sys.platform
    machine = platform.machine().lower()
    
    # Map platform to Xray release filename
    platform_map = {
        # Windows
        ("win32", "amd64"): ("windows-64", "Xray-windows-64.zip", "xray.exe"),
        ("win32", "x86_64"): ("windows-64", "Xray-windows-64.zip", "xray.exe"),
        ("win32", "arm64"): ("windows-arm64-v8a", "Xray-windows-arm64-v8a.zip", "xray.exe"),
        
        # Linux
        ("linux", "amd64"): ("linux-64", "Xray-linux-64.zip", "xray"),
        ("linux", "x86_64"): ("linux-64", "Xray-linux-64.zip", "xray"),
        ("linux", "arm64"): ("linux-arm64-v8a", "Xray-linux-arm64-v8a.zip", "xray"),
        ("linux", "aarch64"): ("linux-arm64-v8a", "Xray-linux-arm64-v8a.zip", "xray"),
        
        # macOS
        ("darwin", "amd64"): ("macos-64", "Xray-macos-64.zip", "xray"),
        ("darwin", "x86_64"): ("macos-64", "Xray-macos-64.zip", "xray"),
        ("darwin", "arm64"): ("macos-arm64-v8a", "Xray-macos-arm64-v8a.zip", "xray"),
    }
    
    key = (system, machine)
    if key in platform_map:
        return platform_map[key]
    
    # Fallback for unknown architectures
    if system == "win32":
        return ("windows-64", "Xray-windows-64.zip", "xray.exe")
    elif system == "linux":
        return ("linux-64", "Xray-linux-64.zip", "xray")
    elif system == "darwin":
        return ("macos-64", "Xray-macos-64.zip", "xray")
    
    return None, None, None


def download_file(url, dest_path, show_progress=True):
    """Download file with progress indicator.
    
    Returns:
        bool: True if successful, False otherwise
    """
    def reporthook(blocknum, blocksize, totalsize):
        if totalsize > 0 and show_progress:
            readsofar = blocknum * blocksize
            percent = readsofar * 100 / totalsize
            downloaded_mb = readsofar / 1024 / 1024
            total_mb = totalsize / 1024 / 1024
            print(f"\rProgress: {percent:5.1f}% ({downloaded_mb:.1f}MB / {total_mb:.1f}MB)", end='', flush=True)
    
    try:
        urllib.request.urlretrieve(url, dest_path, reporthook)
        if show_progress:
            print()  # Newline after progress
        return True
    except Exception as e:
        if show_progress:
            print()
        print(f"Download failed: {e}")
        return False


def extract_archive(archive_path, extract_dir):
    """Extract zip or tar.gz archive.
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif archive_path.suffix in [".gz", ".xz"]:
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                tar_ref.extractall(extract_dir)
        else:
            print(f"Unsupported archive format: {archive_path.suffix}")
            return False
        return True
    except Exception as e:
        print(f"Extraction failed: {e}")
        return False


def ensure_xray_installed(version=XRAY_VERSION, xray_dir=None, force=False):
    """Ensure Xray-core is installed, download if missing.
    
    Args:
        version: Xray-core version to download
        xray_dir: Custom installation directory (default: source/xray)
        force: Force re-download even if already installed
    
    Returns:
        Path: Path to xray binary if successful, None otherwise
    """
    # Determine xray directory - always install to source/xray (sibling to utils/)
    if xray_dir is None:
        # This script is at source/utils/download_xray.py
        # Install to source/xray/
        xray_dir = Path(__file__).parent.parent / "xray"
    else:
        xray_dir = Path(xray_dir)
    
    # Get platform info
    platform_name, filename, xray_exe = get_platform_info()
    
    if not platform_name:
        print(f"Error: Unsupported platform: {sys.platform} ({platform.machine()})")
        return None
    
    xray_path = xray_dir / xray_exe
    
    # Check if already installed
    if xray_path.exists() and not force:
        return xray_path
    
    # Create xray directory
    xray_dir.mkdir(parents=True, exist_ok=True)
    
    # Build download URL
    url = f"{GITHUB_RELEASES_URL}/{version}/{filename}"
    
    print(f"Downloading Xray-core {version} for {platform_name}...")
    print(f"URL: {url}")
    
    # Download
    download_path = Path(filename)
    if not download_file(url, download_path):
        return None
    
    # Extract
    print(f"Extracting {filename} to {xray_dir}/...")
    if not extract_archive(download_path, xray_dir):
        return None
    
    # Cleanup
    try:
        download_path.unlink()
    except:
        pass
    
    # Make executable on Unix
    if sys.platform != "win32":
        try:
            os.chmod(xray_path, 0o755)
        except Exception as e:
            print(f"Warning: Could not set executable permission: {e}")
    
    print(f"✓ Xray-core installed: {xray_path.absolute()}")
    return xray_path


def download_xray(version=XRAY_VERSION):
    """Legacy function - use ensure_xray_installed() instead."""
    return ensure_xray_installed(version)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Download Xray-core binary")
    parser.add_argument("--version", default=XRAY_VERSION, help=f"Xray version (default: {XRAY_VERSION})")
    parser.add_argument("--force", action="store_true", help="Force re-download")
    parser.add_argument("--output", help="Custom output directory")
    args = parser.parse_args()
    
    result = ensure_xray_installed(version=args.version, xray_dir=args.output, force=args.force)
    if result:
        print(f"\nSuccess: {result}")
        sys.exit(0)
    else:
        print("\nFailed to install Xray-core")
        sys.exit(1)
