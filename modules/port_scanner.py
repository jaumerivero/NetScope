import sys
import socket
import signal
import logging
import scapy.all as scapy
from .get_banners import *
from .parse_strings import *
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed 

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
    s.settimeout(1)
    open_sockets.append(s)
    return s

def tcp_connect(port, target, services):
    try:
        headers = None

        ip = scapy.IP(dst=target)
        tcp = scapy.TCP(dport=port, flags='S')
        response = scapy.sr1(ip/tcp, timeout=2, verbose=0)   

        if response and response.haslayer(scapy.TCP):
            flags = response.getlayer(scapy.TCP).flags
            if flags == 0x12:
                if services:
                    s = create_tcp_socket()
                    if port == 80:
                        url = f"http://{target}"
                        headers = get_http_headers(url)
        
                    elif port == 443:
                        url = f"https://{target}/"
                        headers = get_http_headers(url)

                    elif port in [445]:
                        headers = get_smb_info(target)
                    else:
                        try:
                            s.connect((target, port))
                            response = s.recv(1024)
                            headers = response.decode(errors='ignore')
                        except:
                            pass
                        finally:
                            s.close()

                print(colored(f"\t[+] Port {port} is open\n", 'green'))
                if headers:
                    print(f"\t\t[i] {headers}\n")
                 

                scapy.send(scapy.IP(dst=target)/scapy.TCP(dport=port, flags='F'), verbose=False)

            elif flags == 0x04 or flags == 0x014:
                pass
        else:
            pass  
    except Exception as e:
        print(colored(f"[!] {e}\n", 'red')) 
        

def syn_scan(port, target, services):
    try:
        headers = None

        ip = scapy.IP(dst=target)
        tcp = scapy.TCP(dport=port, flags='S')
        response = scapy.sr1(ip/tcp, timeout=2, verbose=0)   

        if response and response.haslayer(scapy.TCP):
            flags = response.getlayer(scapy.TCP).flags
            if flags == 0x12:
                if services:             
                    s = create_tcp_socket()

                    if port == 80:                 
                        url = f"http://{target}"
                        headers = get_http_headers(url)
            
                    elif port == 443:
                        url = f"https://{target}/"
                        headers = get_http_headers(url)

                    elif port in [445]:  # SMB             
                        headers = get_smb_info(target)
                    else:
                        try:
                            s.connect((target, port))
                            response = s.recv(1024)
                            headers = response.decode(errors='ignore')
                        except:
                            pass
                        finally:
                            s.close()
         
                print(colored(f"\t[+] Port {port} is open\n", 'green'))
                if headers:              
                    print(f"\t\t[i] {headers}\n")           
           
                scapy.send(scapy.IP(dst=target)/scapy.TCP(dport=port, flags='R'), verbose=False)

            elif flags == 0x04 or flags == 0x014:
                pass
        else:
            pass  
    except Exception as e:
        print(colored(f"[!] {e}\n", 'red')) 

def ack_scan(target, port):
    try:

        ip = scapy.IP(dst=target)    
        tcp = scapy.TCP(dport=port, flags='A')
        response = scapy.sr1(ip/tcp, timeout=2, verbose=0)  
     
        if response and response.haslayer(scapy.TCP):
            flags = response.getlayer(scapy.TCP).flags
            if flags == 0x04 or flags == 0x014:
                return True
        else:
            return False

    except Exception as e:
        print(colored(f"[!] {e}\n", 'red')) 

def scan_ports(ports, target, services, syn, ack):
    try:
        print(f"\n[i] Checking Filtered and Unfiltered ports:\n") if ack else print(f"\n[i] Open ports:\n")
    
        if syn:
            with ThreadPoolExecutor(max_workers=100) as executor:
                executor.map(lambda port: syn_scan(port, target, services), ports)

        elif ack: 
            ports_filtered = 0
            ports_unfiltered = 0
        
            with ThreadPoolExecutor(max_workers=100) as executor:        
                future_to_port = {executor.submit(ack_scan, target, port): port for port in ports} if ack else {}
        
                for future in as_completed(future_to_port):
                    is_unfiltered = future.result()
                    if is_unfiltered:
                        ports_unfiltered += 1
                    else:
                        ports_filtered += 1
        
            print(colored(f"\t[+] Unfiltered ports: {ports_unfiltered}", 'green'))
            if ports_unfiltered != 0:
                print(colored(f"\n\t[!] FIREWALL DETECTED:", 'red'))
                print(colored(f"\n\t\t[-] Filtered ports: {ports_filtered}\n", 'yellow'))

        else:
            with ThreadPoolExecutor(max_workers=100) as executor:
                executor.map(lambda port: tcp_connect(port, target, services), ports) 
    
    except Exception as e:
        print(colored(f"[!] {e}\n", 'red')) 

