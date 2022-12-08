from scapy.all import *

def send_packet(packet):
    if UDP in packet and packet[IP].dst == '127.0.0.1':
        packet[IP].dst="10.0.2.215"
        packet[IP].src="10.0.2.215"
        sendp(packet, verbose=False)

while True:
    sniff(prn=send_packet, iface="lo")
