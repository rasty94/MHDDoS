import logging

import psutil
from prometheus_client import Counter, Gauge, start_http_server

logger = logging.getLogger(__name__)

# --- Prometheus Metrics ---
REQUESTS_TOTAL = Counter('mhcheck_requests_total', 'Total number of requests initiated', ['method', 'layer'])
ERRORS_TOTAL = Counter('mhcheck_errors_total', 'Total number of errors encountered', ['type'])
ACTIVE_THREADS = Gauge('mhcheck_active_threads', 'Number of currently active threads')
CPU_USAGE = Gauge('mhcheck_cpu_usage_percent', 'Current CPU Usage Percentage')
RAM_USAGE = Gauge('mhcheck_ram_usage_percent', 'Current RAM Usage Percentage')

_METRICS_SERVER_STARTED = False

def start_metrics_server(port: int = 8000):
    """Start prometheus metrics server on a background thread."""
    global _METRICS_SERVER_STARTED
    if not _METRICS_SERVER_STARTED:
        try:
            start_http_server(port)
            _METRICS_SERVER_STARTED = True
            logger.info(f"Prometheus metrics server started on port {port}")
        except Exception as e:
            logger.error(f"Failed to start prometheus server: {e}")

# --- Resource Limitations & Security ---

class SecurityGuard:
    def __init__(self, max_cpu_percent: float = 95.0, max_ram_percent: float = 95.0, max_threads: int = 2000):
        self.max_cpu_percent = max_cpu_percent
        self.max_ram_percent = max_ram_percent
        self.max_threads = max_threads

    def check_safe_to_run(self, requested_threads: int = 0) -> tuple[bool, str]:
        """
        Verify if the system has enough headroom to start a test.
        Returns (is_safe, reason).
        """
        cpu_current = psutil.cpu_percent(interval=0.1)
        ram_current = psutil.virtual_memory().percent

        # Update metrics
        CPU_USAGE.set(cpu_current)
        RAM_USAGE.set(ram_current)

        if cpu_current >= self.max_cpu_percent:
            return False, f"CPU usage too high ({cpu_current}% >= {self.max_cpu_percent}%)"

        if ram_current >= self.max_ram_percent:
            return False, f"Memory usage too high ({ram_current}% >= {self.max_ram_percent}%)"

        if requested_threads > self.max_threads:
            return False, f"Requested threads exceed safeguard limit ({requested_threads} > {self.max_threads})"

        return True, "Safe"
