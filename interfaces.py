from scapy.all import *

print("Avaiable interfaces:")
for i in get_if_list():
    print(i)