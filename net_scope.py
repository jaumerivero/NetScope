#!/usr/bin/env python3
import os
import signal
import argparse
from modules.utils import *
from termcolor import colored
from modules.port_scanner import *
from modules.ping_scanner import *
from modules.parse_strings import *

signal.signal(signal.SIGINT, def_handler)

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
arp_help = "Perform an ARP scan on a target or on a subnet to discover live hosts and their MAC addresses (Ex: -t 192.168.1.0/24 --arp)"
ping_type_help = "Discover live hosts by performing differents types of ping scans (Ex: -t 192.168.1.1 --ping icmp)"
services_help = "Enable service identification to identificate the services information running on that port/s (Ex: -t 192.168.1.1 -s)"
syn_scan_help = "Perform a SYN scan on the specified target/s port/s (Ex: -t 192.168.1.1 -sY)"
ack_scan_help = "Perform a ACK scan on the specified target/s (Ex: -t 192.168.1.1 -aC)"

class CustomHelpParser(argparse.ArgumentParser):
    def print_help(self):
        global logo
        print(colored(logo, 'yellow'))
        super().print_help()

def get_arguments():
    parser = CustomHelpParser()
    parser.add_argument("-t", "--target", dest="target", required=True, help="Set target/s to scan (Ex: -t 192.168.1.1)")
    parser.add_argument("-p", "--port", dest="port", help="Set port or port range to scan (Ex: -p 1-100)")
    parser.add_argument("--ping", dest="ping", choices=['icmp', 'tcp', 'udp'],help=ping_type_help)
    parser.add_argument("--arp", dest="arp", action='store_true', help=arp_help)
    parser.add_argument("-s", "--services", dest="services", action='store_true', help=services_help)
    parser.add_argument("-sY", "--syn_scan", dest="syn", action='store_true', help=syn_scan_help)
    parser.add_argument("-aC", "--ack_scan", dest="ack", action='store_true', help=ack_scan_help )
    
    options = parser.parse_args()

    return options.target, options.port, options.ping, options.arp, options.services, options.syn, options.ack

def main():
    if not os.geteuid() == 0:
        print(colored("\n[!] net_scope.py requires root privileges. Please run the script as root.\n", 'red'))
        sys.exit(1)

    target, ports_str, ping, arp, services, syn, ack = get_arguments()

    targets = parse_target(target)
    ports = parse_ports(ports_str) if ports_str else common_ports
    services_param = False if not services else services
    syn_param = False if not syn else syn
    
    if arp:
        arp_ping(target)

    elif ping:
        ping_type = ping
        host_scanner(targets, ports if ping_type in ['tcp', 'udp'] else False, ping_type)
    
    else:
        scan_ports(ports, target, services_param, syn_param, ack)

if __name__ == "__main__":
    main()
