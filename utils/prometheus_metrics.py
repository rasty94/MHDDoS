from prometheus_client import start_http_server, Counter, Gauge

# Metrics
OSINT_REQUESTS = Counter('osint_requests_total', 'Total number of OSINT requests sent', ['tool', 'status'])
STRESS_ATTACKS = Counter('stress_attacks_total', 'Total number of stress attacks initiated', ['layer', 'method'])
ACTIVE_THREADS = Gauge('active_stress_threads', 'Current number of active stress threads')
SYSTEM_CPU = Gauge('system_cpu_usage', 'Current CPU usage percentage')
SYSTEM_MEM = Gauge('system_mem_usage', 'Current Memory usage percentage')

def start_metrics_server(port=8000):
    """Start the Prometheus metrics endpoint."""
    try:
        start_http_server(port)
        print(f"[i] Prometheus metrics exposed on port {port}")
    except Exception as e:
        print(f"[!] Failed to start metrics server: {e}")
