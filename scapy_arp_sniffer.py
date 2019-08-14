from scapy.all import *


def passive_arp_sniffer():
    # Very simple Scapy ARP sniffer
    # Listens passively for both requests and replies
    # Displays both MAC and IP addresses collected
    def arp_display(pkt):
        if pkt[0][1].op == 1:
            print("{} with MAC {} is asking where {} is".format(pkt[ARP].psrc, pkt[ARP].hwsrc, pkt[ARP].pdst))
        elif pkt[0][1].op == 2:
            print("{} is at {}".format(pkt[ARP].psrc, pkt[ARP].hwsrc))

    print(sniff(prn=arp_display, filter="arp"))


passive_arp_sniffer()




