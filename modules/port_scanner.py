import sys
import socket
import signal
import logging
from scapy.all import *
from .get_banners import *
from .parse_strings import *
from termcolor import colored
from scapy.volatile import RandShort
from concurrent.futures import ThreadPoolExecutor 

# Evitar advertencas scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

open_sockets = []

def def_handler(sig, frame):
    print(colored("\n[!] Stopping the scan...", 'red'))

    for sock in open_sockets:
        sock.close()
   
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def create_tcp_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    open_sockets.append(s)
    return s

def tcp_connect(port, target, services):
    s = create_tcp_socket()

    try:
        s.connect((target, port)) 
        
        if services:
            # Banner grabbing
            if port == 80:
                # Realizar una solicitud GET a un sitio web
                url = f"http://{target}"
                headers = get_http_headers(url)
            
            elif port == 443:
                url = f"https://{target}/"
                headers = get_http_headers(url)

            elif port in [445]:  # SMB
                # Suggest using a specialized tool for SMB services
                headers = get_smb_info(target)
            else:
                try:
                    response = s.recv(1024)
                    headers = response.decode(errors='ignore')
                    headers = parse_banner(headers)
                
                except:
                    pass
       
        # Print port is open message
        print(colored(f"\t[+] Port {port} is open\n", 'green'))
        
        if headers:
            # Print service information
            print(f"\t\t{headers}\n")     
                  
    except (socket.timeout, ConnectionRefusedError):
        pass  # Ignore closed or non-responsive ports within timeout

    finally:
        s.close()

def syn_scan(port, target, services):
    # Crear paquete IP con el objetivo
    ip = IP(dst=target)
    # Crear paquete TCP con el puerto objetivo y la bandera SYN activada
    tcp = TCP(dport=port, flags='S')
    # Enviar el paquete y esperar por la primera respuesta
    response = sr1(ip/tcp, timeout=5, verbose=0)  
    
    if response:
        # Verificar si la respuesta es un SYN-ACK
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 'SA':

            if services:
                s = create_tcp_socket()

                if port == 80:
                    url = f"http://{target}"
                    headers= get_http_headers(url)
                
                elif port == 443:
                    url = f"https://{target}"
                    headers= get_http_headers(url)

                else:
                    try:
                        s.connect((target, port))
                        response = s.recv(1024)
                        headers = response.decode(errors='ignore')
                        headers = parse_banner(headers)

                    except (socket.timeout, ConnectionRefusedError):
                        pass

                    finally:
                        s.close()
            
            print(colored(f"\t[+] Port {port} is open\n", 'green'))

            if headers:
                print(f"\t\t{headers}\n") 

def ack_scan(target, port):
        # Construye un paquete IP/TCP con la bandera ACK
        packet = IP(dst=target)/TCP(dport=port, flags="A")
        # Envía el paquete y espera por una respuesta
        response = sr1(packet, timeout=1, verbose=0)

        # Análisis de la respuesta
        if response is None:
            print(colored(f"\n\t[*] Port {port}: closed | filtered (No response)", 'red'))
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x4:  # Bandera RST/ACK
                print(colored(f"\n\t[+] Port {port}: Unfiltered (RST/ACK flag received)", 'green'))
        elif response.haslayer(ICMP):
            if int(response[ICMP].type) == 3 and int(response[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                print(colored(f"\n\t[*] Port {port}: Filtered (ICMP unreachable error received)", 'red'))


def scan_ports(ports, target, services, syn, ack):
    print(f"\n[+] Open ports:\n")
    
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        if syn:
            executor.map(lambda port: syn_scan(port, target, services), ports)
        elif ack:
            executor.map(lambda port: ack_scan(target, port), ports)
        else:
            executor.map(lambda port: tcp_connect(port, target, services), ports) 

