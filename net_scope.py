#!/usr/bin/env python3

import argparse
import os
from modules.parse_strings import *
from modules.port_scanner import *
from modules.ping_scanner import *
from modules.utils import *
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

logo = """
  _   _      _    _____                      
 | \ | |    | |  / ____|                     
 |  \| | ___| |_| (___   ___ ___  _ __   ___ 
 | . ` |/ _ \ __|\___ \ / __/ _ \| '_ \ / _ |
 | |\  |  __/ |_ ____) | (_| (_) | |_) |  __/
 |_| \_|\___|\__|_____/ \___\___/| .__/ \___|
                                 | |         
                                 |_|        
"""
arp_help = "Perform an ARP scan on the specified target subnet to discover live hosts and their MAC addresses (Ex: -t 192.168.1.0/24 --arp)"
ping_help = "Perform an ICMP scan on the specified target/s (Ex: -t 192.168.1.1-100 --ping)"
ping_type_help = "Choose the type of ping (Ex: -t 192.168.1.1 --ping_type tcp)"
services_help = "Enable banner grabbing to identificate the service and his version running on that port/s (Ex: -t 192.168.1.1 -s)"
syn_scan_help = "Perform a SYN scan on the specified target/s port/s (Ex: -t 192.168.1.1 -sY)"
ack_scan_help = "Perfron a ACK scan on the specified target/s (Ex: -t 192.168.1.1 -aC)"

signal.signal(signal.SIGINT, def_handler)

class CustomHelpParser(argparse.ArgumentParser):
    def print_help(self):
        global logo
        print(colored(logo, 'yellow'))
        super().print_help()

def get_arguments():
    parser = CustomHelpParser()
    parser.add_argument("-t", "--target", dest="target", required=True, help="Set target to scan (Ex: -t 192.168.1.1)")
    parser.add_argument("-p", "--port", dest="port", help="Port range to scan (Ex: -p 1-100)")
    parser.add_argument("--ping", dest="ping", action='store_true', help=ping_help)
    parser.add_argument("--ping_type", dest="ping_type", choices=['icmp', 'udp', 'tcp'], help=ping_type_help)
    parser.add_argument("--arp", dest="arp", action='store_true', help=arp_help)
    parser.add_argument("-s", "--services", dest="services", action='store_true', help=services_help)
    parser.add_argument("-sY", "--syn_scan", dest="syn", action='store_true', help=syn_scan_help)
    parser.add_argument("-aC", "--ack_scan", dest="ack", action='store_true', help=ack_scan_help )
    
    options = parser.parse_args()

    return options.target, options.port, options.ping, options.ping_type, options.arp, options.services, options.syn, options.ack

def main():
    target, ports_str, ping, ping_type, arp, services, syn, ack = get_arguments()
    
    targets = parse_target(target)
    ports = parse_ports(ports_str) if ports_str else common_ports  # Optimizado
    services_param = False if not services else services
    syn_param = False if not syn else syn

    if arp:
        if not os.geteuid() == 0:
            print(colored("\n[!] ARP scan requires root privileges. Please run the script as root.", 'red'))
            sys.exit(1)
        arp_scan(target)

    elif ping or ping_type:  # Maneja tanto --ping como --ping_type
        ping_type = ping_type if ping_type in ['icmp', 'tcp', 'udp'] else 'icmp'
        host_scanner(targets, ports if ping_type in ['tcp', 'udp'] else False, ping_type)
    
    else:  # Escaneo de puertos
        if syn and not os.geteuid() == 0:
            print(colored("\n[!] SYN scan requires root privileges. Please run the script as root.", 'red'))
            sys.exit(1)

        scan_ports(ports, target, services_param, syn_param, ack)

if __name__ == "__main__":
    main()
