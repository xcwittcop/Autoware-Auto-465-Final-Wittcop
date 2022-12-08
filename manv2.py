from scapy.all import *
from scapy.utils import rdpcap

def send_packet(packet):
    # sendp(packet, verbose=False, iface="br-95b566e0e766")
    # return
    packet[Ether].src = "00:00:00:00:00:00"
    packet[Ether].dst = "00:00:00:00:00:00"
    packet[UDP].sport = 38080
    packet[IP].src = "127.0.0.1"
    packet[IP].dst = "10.0.2.215"
    packet[IP].ttl = 64
    if packet[UDP].dport == 2368:
        packet[IP].id = 38262
        packet[IP].chksum = 0xa2a2
    else:
        packet[IP].id = 38263
        packet[IP].chksum = 0xa2a1
    packet[UDP].chksum = 0x02d2
    # print(packet.show())
    # exit()
    sendp(packet, verbose=False, iface="ens3")

def real_send(packet):
    # print(packet.show())
    packet[IP].src="127.0.0.1"
    just_send_the_packet(packet)
    return
    newPacket = (Ether(dst="00:00:00:00:00:00")/IP(dst="127.0.0.1", flags='DF', id=0x8069)/UDP(dport=packet[UDP].dport, sport=33318, chksum=0x02d2)/Raw(load=packet[Raw].load))
    # print(newPacket.show2())
    # exit()
    # newPacket = newPacket.__class__(bytes(newPacket))
    print(newPacket[Raw] == packet[Raw])
    exit()
    sendp(newPacket, iface="lo", verbose=False)
    #sendp(packet, iface="lo", verbose=False)

def just_send_the_packet(packet):
    sendp(packet, verbose=False)

while True:
    sniff(offline="route_small_loop_rw-127.0.0.1.pcap", prn=real_send)
    #sniff(prn=real_send, iface="lo")
    #packets = rdpcap("route_small_loop_rw-127.0.0.1.pcap", 100000)
    #sendp(packets)
    #for packet in packets:
    #   sendp(packet, verbose=False)
