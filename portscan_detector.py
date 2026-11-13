import time
from collections import defaultdict, deque

'''
Detects vertical port scan (TCP Connect scan, TCP SYN scan) from the same IP address.
Generates alert if number of ports contacted from same ip within time_window is greater than threshold_ports
'''
class PortScanDetector:
    

    def __init__(self, threshold_ports=10, time_window=10):
        self.threshold_ports = threshold_ports
        self.time_window = time_window
        self.connections = defaultdict(lambda: deque())  # key: (src_ip, dst_ip), value: deque of (port, timestamp)
        self.active_alerts = set() 
        self.total_ports = defaultdict(set)
        self.last_seen = {}


    def analyze(self, event):
        if event is None or event["protocol"] != "TCP":
            return None

        src = event["src_ip"]
        dst = event["dst_ip"]
        port = event["dst_port"]
        now = time.time()
        


        key = (src, dst)
        dq = self.connections[key]   # dq is the deque associated to key (one key for src - dst)
                                    
        dq.append((port, now)) 
        self.last_seen[key] = now
        # Removes old events
        while dq and dq[0][1] < (now - self.time_window):  #dq[0] is the oldest element, dq[0][1] is its timestamp
            dq.popleft()

        #Check how many  unique ports
        unique_ports = set(p for p, t in dq)

        if key in self.active_alerts:
            self.total_ports[key].add(port)
        
        if len(unique_ports) >= self.threshold_ports:
            if key not in self.active_alerts:
                self.active_alerts.add(key)
                self.total_ports[key].update(unique_ports)

                return {    #is the alert
                    "type": "PORT_SCAN",
                    "src_ip": src,
                    "dst_ip": dst,
                    "ports scanned by now": list(unique_ports),
                    "severity": "medium"
                }

        
        else:
            if key in self.active_alerts:
                self.active_alerts.remove(key)

        return None
    def check_timeouts(self):
        now = time.time()
        expired_keys = []

        for key in self.active_alerts:
            last = self.last_seen.get(key, 0)
            if now - last > self.time_window:
                expired_keys.append(key)

        for key in expired_keys:
            src, dst = key
            print(f"\nPort scan finished from {src} to {dst}. "
                f"Total ports scanned: {sorted(self.total_ports[key])}")

            self.active_alerts.remove(key)
            self.total_ports.pop(key, None)
            self.connections.pop(key, None)
            self.last_seen.pop(key, None)

