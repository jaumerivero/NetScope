import scapy.all as scapy
from termcolor import colored

def arp_scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    boradcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_packet = boradcast_packet/arp_packet

    answered, unanswered = scapy.srp(arp_packet, timeout=1, verbose=False)
    
    print(colored(f"\n[+] Active hosts:\n"))

    for sent, received in answered:
        print(colored(f"\t[+] {received.psrc}\n", "green"))
        print(colored(f"\t\t[+] MAC: {received.hwsrc}\n", 'yellow'))

