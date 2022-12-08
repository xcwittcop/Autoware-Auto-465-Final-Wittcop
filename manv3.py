from scapy.all import *

def write_packet(packet):
    packet[IP].dst = '10.0.2.215'
    del packet[IP].chksum
    packet = packet.__class__(bytes(packet))
    wrpcap("man.pcap", packet, append=True)

def forward_packet(packet):
    #if UDP in packet:
    #    print(packet[UDP].dport)
    #    print(packet[IP].dst)
    #    print("********************************")
    #if UDP in packet and (packet[UDP].dport == 2368 or packet[UDP].dport == 2369):
        packet[IP].dst = '127.0.0.1'
        #packet[IP].id = 130 + packet[UDP].dport
        packet[IP].src = '127.0.0.1'
        del packet[IP].chksum
        #del packet[UDP].chksum
        packet[UDP].chksum = 0x02d2
        #packet = packet.__class__(bytes(packet))
        sendp(packet, verbose=False, iface="lo")
        #wrpcap('test.pcap', packet, append=True)
        #exit()

#sniff(offline="../route_small_loop_rw-127.0.0.1.pcap", prn=write_packet)
sniff(prn=forward_packet, iface="lo", filter="udp and dst net 10.0.2.215")

