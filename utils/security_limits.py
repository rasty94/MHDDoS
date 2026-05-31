import psutil
import time
import threading

class ResourceMonitor:
    def __init__(self, max_cpu=90.0, max_memory=85.0):
        self.max_cpu = max_cpu
        self.max_memory = max_memory
        self.running = False
        self.thread = None

    def _monitor(self):
        while self.running:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent
            
            if cpu > self.max_cpu or mem > self.max_memory:
                print(f"[!] WARNING: High resource usage detected (CPU: {cpu}%, MEM: {mem}%). Throttling execution.")
                # Future: dispatch event to stop heavy threads
            time.sleep(2)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

monitor = ResourceMonitor()
