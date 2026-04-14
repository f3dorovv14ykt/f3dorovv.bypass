"""Centralized constants for VPN config validation system."""

# Concurrency settings
V2RAYN_MAX_CONCURRENCY = 1000  # Reference: v2rayN SpeedTestPageSize
MAX_SAFE_CONCURRENCY = 500  # Conservative cap to avoid resource exhaustion
MIN_CONCURRENCY = 100  # Minimum for reasonable performance
CPU_MULTIPLIER = 25  # Multiplier for CPU-based concurrency calculation

# Default concurrency per test stage
TCP_PING_CONCURRENCY = 100
HTTP_PING_CONCURRENCY = 20
SPEED_TEST_CONCURRENCY = 5

# Timeout settings (seconds)
DEFAULT_TCP_TIMEOUT = 3.0
DEFAULT_HTTP_TIMEOUT = 3.0  # Reduced to match VALIDATION_HTTP_TIMEOUT
DEFAULT_SPEED_TEST_TIMEOUT = 30.0
DEFAULT_PING_TIMEOUT = 5.0

# Fast timeout for initial TCP filter
FAST_TCP_TIMEOUT = 0.5

# DNS cache settings
DNS_CACHE_TTL_SECONDS = 60  # Reduced from 300s for dynamic IP support

# Port settings
XRAY_BASE_PORT = 20000
XRAY_PORT_RANGE = 5000  # Increased from 1000 to avoid TIME_WAIT conflicts

# Test URLs (common connectivity endpoints)
SPEED_TEST_URLS = [
    "http://www.gstatic.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://www.google.com/generate_204",
    "http://clients3.google.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt"
]

# Batch processing settings
DEFAULT_BATCH_SIZE = 500
SPEED_TEST_PAGE_SIZE = 1000  # Reference: v2rayN batch size

# Retry settings
MAX_RETRY_ATTEMPTS = 2
RETRY_BATCH_SIZE_DIVISOR = 2  # Divide batch size by this on each retry

# Circuit breaker settings
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5
CIRCUIT_BREAKER_RECOVERY_TIMEOUT = 60  # seconds

# Progress reporting
PROGRESS_REPORT_INTERVAL = 500  # Report every N configs
PROGRESS_PERCENT_INCREMENT = 10  # Report every N percent

# File size limits
MAX_FILE_SIZE_MB = 49.0
MAX_CONFIGS_PER_FILE = 300

# Worker settings
DEFAULT_MAX_WORKERS = 16
MIN_WORKERS = 1
MAX_WORKERS_CAP = 200
