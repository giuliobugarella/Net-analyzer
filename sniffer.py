from scapy.all import sniff
from parser import parse_packet


#sniffs traffic and applies the packet_callback (so parse_packet) to each packet detected

class Sniffer:
    def __init__(self, detectors, interface=None):
        self.detectors = detectors
        self.interface = interface

    def packet_callback(self, packet):
        event = parse_packet(packet)
        if event is None:
            return

        for detector in self.detectors:
            alert = detector.analyze(event)
            if alert:
                print(f"ALERT: {alert}")    

    def start(self, count=0):
        print(f"Sniffing on interface: {self.interface}")
        while True:
            sniff(iface=self.interface,
            prn=self.packet_callback,
            filter="ip",
            store=False,
            timeout=1)

            for detector in self.detectors:
                if hasattr(detector, "check_timeouts"):
                    detector.check_timeouts()

