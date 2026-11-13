from scapy.all import IP, TCP, UDP, ICMP

#transforms each ip packet in a dict

def parse_packet(packet):
   
    if IP not in packet:
        return None

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    if TCP in packet:
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
    elif UDP in packet:
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        flags = None
    elif ICMP in packet:
        proto = "ICMP"
        src_port = None
        dst_port = None
        flags = None
    else:
        proto = str(ip_layer.proto)
        src_port = None
        dst_port = None
        flags = None
    '''
    #debug
    print({
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
        "raw_packet": packet
    })
    '''
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
        "raw_packet": packet
    }
