from datetime import datetime
import time
import psutil
from collections import deque
import threading

#MONITOR BASED SA SYSTEM
class SystemMonitor:
    def __init__(self, history_length=300, socketio=None):
        self.history_length = history_length
        self.cpu_history = deque(maxlen=history_length)
        self.ram_history = deque(maxlen=history_length)
        self.disk_history = deque(maxlen=history_length)
        self.net_history = deque(maxlen=history_length)
        self.timestamps = deque(maxlen=history_length)
        
        # Network specific
        self.last_net_io = None
        self.last_net_time = None
        
        # Socket.IO instance
        self.socketio = socketio
        self.monitoring_thread = None
        self.monitoring_active = False
        
    def get_all_stats(self):
        """Get all system stats and update history"""
        now = datetime.now()
        timestamp = now.strftime("%H:%M:%S")
        
        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory Usage
        mem = psutil.virtual_memory()
        ram_percent = mem.percent
        ram_used = mem.used / (1024 ** 3)  # GB
        ram_total = mem.total / (1024 ** 3)  # GB
        
        # Disk Usage (primary disk)
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        disk_used = disk.used / (1024 ** 3)  # GB
        disk_total = disk.total / (1024 ** 3)  # GB
        
        # Network Usage
        net_io = psutil.net_io_counters()
        current_time = time.time()
        
        kb_sent = 0
        kb_recv = 0
        packets_sent = 0
        packets_recv = 0
        
        if self.last_net_io and self.last_net_time:
            time_elapsed = current_time - self.last_net_time
            if time_elapsed > 0:
                kb_sent = (net_io.bytes_sent - self.last_net_io.bytes_sent) / 1024 / time_elapsed
                kb_recv = (net_io.bytes_recv - self.last_net_io.bytes_recv) / 1024 / time_elapsed
                packets_sent = (net_io.packets_sent - self.last_net_io.packets_sent) / time_elapsed
                packets_recv = (net_io.packets_recv - self.last_net_io.packets_recv) / time_elapsed
        
        self.last_net_io = net_io
        self.last_net_time = current_time
        
        # Update history
        self.timestamps.append(timestamp)
        self.cpu_history.append(cpu_percent)
        self.ram_history.append(ram_percent)
        self.disk_history.append(disk_percent)
        self.net_history.append({
            'kb_sent': kb_sent,
            'kb_recv': kb_recv,
            'packets_sent': packets_sent,
            'packets_recv': packets_recv,
            'total_kb': kb_sent + kb_recv,
            'total_packets': packets_sent + packets_recv
        })
        
        stats = {
            'timestamp': timestamp,
            'cpu': {
                'percent': cpu_percent,
                'cores': psutil.cpu_count(logical=False),
                'threads': psutil.cpu_count(logical=True)
            },
            'memory': {
                'percent': ram_percent,
                'used': round(ram_used, 2),
                'total': round(ram_total, 2),
                'free': round((mem.total - mem.used) / (1024 ** 3), 2)
            },
            'disk': {
                'percent': disk_percent,
                'used': round(disk_used, 2),
                'total': round(disk_total, 2),
                'free': round(disk.free / (1024 ** 3), 2)
            },
            'network': {
                'kb_sent': round(kb_sent, 2),
                'kb_recv': round(kb_recv, 2),
                'total_kb': round(kb_sent + kb_recv, 2),
                'packets_sent': round(packets_sent, 2),
                'packets_recv': round(packets_recv, 2),
                'total_packets': round(packets_sent + packets_recv, 2)
            },
            'history': {
                'timestamps': list(self.timestamps),
                'cpu': list(self.cpu_history),
                'memory': list(self.ram_history),
                'disk': list(self.disk_history),
                'network_kb': [x['total_kb'] for x in self.net_history],
                'network_packets': [x['total_packets'] for x in self.net_history]
            }
        }
        
        return stats
        
    def start_monitoring(self, interval=2):
        """Start real-time monitoring with Socket.IO"""
        if self.socketio is None:
            return False
            
        if self.monitoring_active:
            return True
            
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_task, args=(interval,))
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        return True
        
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1)
            self.monitoring_thread = None
        return True
        
    def _monitoring_task(self, interval):
        """Background task to emit system stats via Socket.IO"""
        while self.monitoring_active:
            try:
                stats = self.get_all_stats()
                # Emit the stats to the 'system_stats_update' event
                if self.socketio:
                    self.socketio.emit('system_stats_update', stats, namespace='/admin')
            except Exception as e:
                print(f"Error in monitoring task: {str(e)}")
            time.sleep(interval)