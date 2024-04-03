import sys
import shlex
import socket
import signal
import subprocess
import scapy.all as scapy
from termcolor import colored
from itertools import product
from .utils import common_ports
from concurrent.futures import ThreadPoolExecutor

def def_handler(sig ,frame):
    print(colored(f"\n[!] Stopping the scan...", 'red'))
    sys.exit(1)

def arp_ping(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast_packet/arp_packet

    answered, unanswered = scapy.srp(arp_packet, timeout=1, verbose=False)

    print(colored(f"\n[+] Active hosts:\n"))

    for sent, received in answered:
        print(colored(f"\t[+] {received.psrc}\n", "green"))
        print(colored(f"\t\t[+] MAC: {received.hwsrc}\n", 'yellow'))

def icmp_ping(target):
    try:
        ip = scapy.IP(dst=target)
        icmp = scapy.ICMP()
        response = scapy.sr1(ip/icmp, timeout=1, verbose=False)
    
        # Verificando si se recibió respuesta
        if response:
            print(colored(f"\t[+] Host {target}: Active\n", 'green'))
            if 60 <= response.ttl <= 65:
                print(colored(f"\t\t[i] OS: Linux\n", 'yellow'))
            elif 124 <= response.ttl <= 129:
                print(colored(f"\t\t[i] OS: Windows\n", 'yellow'))
        else:
            pass
            # print(colored(f"\t[-] Host {target}: Inactive or ignoring requests\n", 'red')) 
    except Exception as e:
        print(e)

def tcp_ping(target, port):
    try:
        ip = scapy.IP(dst=target)
        tcp = scapy.TCP(dport=port, flags='S')
        response = scapy.sr1(ip/tcp, timeout=1, verbose=False)
        if response and response.haslayer(scapy.TCP):
            tcp_layer = response.getlayer(scapy.TCP)
            
            if tcp_layer.flags == 0x12:
                scapy.sr(scapy.IP(dst=target)/scapy.TCP(dport=port, flags='R'), timeout=1, verbose=False) # Enviar RST para cerrar
                return True
                
            elif tcp_layer.flags == 0x04 or tcp_layer.flags == 0x14:
                return True
        
        else:
            return False
    
    except Exception as e:
        print(colored(f"{e}\n", 'red')) 

def udp_ping(target, port):
    try:
        ip = scapy.IP(dst=target)
        tcp = scapy.UDP(dport=port)
        response = scapy.sr1(ip/tcp, timeout=1, verbose=False)

        if response:
            if response.haslayer(scapy.ICMP) and response.getlayer(scapy.ICMP).type == 3:
                return True
        else:
            return False

    except Exception as e:
        print(e)

def host_scanner(targets, ports, ping_type):
    print(f"\n[+] Active host/s on the network: \n")
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        if ping_type == 'icmp':        
            executor.map(icmp_ping, targets)

    if ping_type == 'tcp':
        for port in ports:
            break_point = False
            if tcp_ping(targets, port):
                print(colored(f"\t[+] Host {''.join(targets)} active, port {port} answered\n", 'green'))
                break_point = True
                return 
        if not break_point:
            print(colored(f"\t[-] Host {''.join(targets)} down, no ports answered (maybe firewall?)\n", 'red'))

    if ping_type == 'udp':
        for port in ports:
            break_point = False
            if udp_ping(targets, port):
                print(colored(f"\t[+] Host {''.join(targets)} active, port {port} answered\n", 'green'))
                break_point = True
                return 
        if not break_point:
            print(colored(f"\t[-] Host {''.join(targets)} down, no ports answered\n", 'red'))

 
        
        
