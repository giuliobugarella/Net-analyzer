from sniffer import Sniffer
from portscan_detector import PortScanDetector
from DoS_detector import DoSDetector



PORT_THRESH = 10
ICMP_THRESH = 100
TCP_THRESH = 200

def main():
    
    portscan = PortScanDetector(threshold_ports=PORT_THRESH, time_window=20)
    dos_detector = DoSDetector(icmp_threshold=ICMP_THRESH,
        tcp_threshold=TCP_THRESH,
        time_window=1,
        syn_only=True)
    detectors = [portscan, dos_detector]
    interface = "my_wifi" #insert here device interface to sniff 
    sniffer = Sniffer(detectors=detectors, interface=interface) 
    sniffer.start()

if __name__ == "__main__":
    main()

 