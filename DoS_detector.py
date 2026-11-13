import time
from collections import defaultdict, deque
'''
Detects Denial of Service from TCP Syn/connect or ICMP flood if number of packets from same
source within time_window is bigger than threshold (ICMP_THRESH, TCP_THRESH)
'''

class DoSDetector:


    def __init__(
        self,
        icmp_threshold=100,
        tcp_threshold=200,
        time_window=1,
        syn_only=False
    ):
        self.icmp_threshold = icmp_threshold
        self.tcp_threshold = tcp_threshold
        self.time_window = time_window
        self.syn_only = syn_only
        self.active_alerts = set()
        self.previous_key = set()

        self.icmp_events = defaultdict(lambda: deque())
        self.tcp_events = defaultdict(lambda: deque())

        self.last_seen = {}

    def _cleanup(self, dq, now):
        while dq and dq[0] < now - self.time_window:
            dq.popleft()

    def analyze(self, event):
        if event is None:
            return None

        proto = event["protocol"]
        src = event["src_ip"]
        dst = event["dst_ip"]
        now = time.time()

        
        if proto == "ICMP":
            key = (src, dst)
            dq = self.icmp_events[key]
            dq.append(now)
            self.last_seen[(key, proto)] = now

            self._cleanup(dq, now)

            if len(dq) >= self.icmp_threshold:
                if (key, proto) not in self.active_alerts:
                    self.active_alerts.add((key, proto))

                    return {
                        "type": "ICMP_FLOOD",
                        "src_ip": src,
                        "dst_ip": dst,
                        "packet_count": len(dq),
                        "time_window": self.time_window,
                        "severity": "high"
                    }
            else:
                if (key, proto) in self.active_alerts:
                    print("Flooding is over for now")
                    self.active_alerts.discard((key, proto))

        

        if proto == "TCP":
            if self.syn_only:
                flags = event.get("flags", "")
                # rileva solo SYN senza ACK (tipico SYN flood)
                if "S" not in flags or "A" in flags:
                    return None
            
            key = (src, dst)
            '''
            answer = (dst, src)
            if key not in self.previous_key:
                
                if answer not in self.previous_key:
                    self.previous_key.add(key) 


            if answer in self.previous_key:
                return None

            '''
            dq = self.tcp_events[key]
            dq.append(now)
            self.last_seen[(key, proto)] = now
            self._cleanup(dq, now)

            if len(dq) >= self.tcp_threshold:
                if (key, proto) not in self.active_alerts:
                    self.active_alerts.add((key, proto))
                    return {
                        "type": "TCP_FLOOD",
                        "src_ip": src,
                        "dst_ip": dst,
                        "packet_count": len(dq),
                        "time_window": self.time_window,
                        "severity": "high"
                    }
            else:
                if (key, proto) in self.active_alerts:
                    self.active_alerts.discard((key, proto))

        return None
    def check_timeouts(self):
        now = time.time()
        expired = []

        for (key, proto) in list(self.active_alerts):
            last = self.last_seen.get((key, proto), 0)

            if now - last > self.time_window:
                expired.append((key, proto))

        for (key, proto) in expired:
            src, dst = key
            print(f"{proto} flood finished from {src} to {dst}")

            self.active_alerts.discard((key, proto))
            self.last_seen.pop((key, proto), None)

            if proto == "ICMP":
                self.icmp_events.pop(key, None)
            elif proto == "TCP":
                self.tcp_events.pop(key, None)
