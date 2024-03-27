import sys
import socket
import signal
import subprocess
import shlex
import scapy.all as scapy
from termcolor import colored
from itertools import product
from .utils import common_ports
from concurrent.futures import ThreadPoolExecutor, as_completed

def def_handler(sig ,frame):
    print(colored(f"\n[!] Parando del escaneo...", 'red'))
    
    sys.exit(1)

def arp_scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    boradcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_packet = boradcast_packet/arp_packet

    answered, unanswered = scapy.srp(arp_packet, timeout=1, verbose=False)
    
    print(colored(f"\n[+] Active hosts:\n"))

    for sent, received in answered:
        print(colored(f"\t[+] {received.psrc}\n", "green"))
        print(colored(f"\t\t[+] MAC: {received.hwsrc}\n", 'yellow'))

def icmp_ping(target):
    try:
        ping = subprocess.run(["ping", "-c", "1", target], capture_output=True, text=True, timeout=1)
                
        if ping.returncode == 0:
               
            ttl_line = [line for line in ping.stdout.split('\n') if "ttl" in line.lower()]
            ttl = ttl_line[0].split("ttl=")[1].split(" ")[0] if ttl_line else "Desconocido"
                
            print(colored(f"\t[+] {target}: Active", 'green'))

            if int(ttl) == 64 or int(ttl) == 63:

                print(colored(f"\n\t\t[i] OS: Linux (TTL={ttl})\n", 'yellow'))

            elif int(ttl) == 128 or int(ttl) == 127:

                print(colored(f"\n\t\t[i] OS: Windows (TTL={ttl})\n", 'yellow'))
                
    except subprocess.TimeoutExpired:                
        pass
    # print(colored(f"\t[-] Host {target} seems to be down\n", 'red'))

def tcp_ping(target, port):
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    try:
        if s.connect_ex((target, port)) == 0:
            # print(colored(f"\t[+] Host {target} is active (Port {port} is open)\n", 'green'))
            return True  # Detiene el escaneo después de encontrar el primer puerto abierto

    except socket.error as e:
        print(colored(f"Socket error: {e}", 'red'))

    finally:
            s.close()

    return False

def udp_ping(target, port):
    command = f"nc -u -v -z {target} {port}"
    command_args = shlex.split(command)
    
    try:
        # Aumenta el timeout si es necesario
        result = subprocess.run(command_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5.5)
        
        stderr_lines = result.stderr.splitlines()
        
        if len(stderr_lines) >= 2:
            stderr_outpu = stderr_lines[1]
        else:
            stderr_output = stderr_lines[0] 

        if '?' not in result.stderr and result.returncode == 0:
            # print(colored(f"\n\t[+] Host active (Port {port} open)", 'green'))
            # print(colored(f"\n\n\t\t[i] {stderr_output}", 'yellow'))
            return True
        else:
            pass
            # print(colored(f"\n\t[-] Host {target} port {port} closed or filtered", 'red'))

    except subprocess.TimeoutExpired:
        pass
        # print(colored(f"\n\t[!] Timeout: Host {target} port {port}", 'yellow'))
    except Exception as e:
        pass
        # print(f"Error running command: {e}")


def host_scanner(targets, ports, ping_type):
    print(f"\n[+] Active host/s on the network: \n")
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []

        # Preparar las tareas para TCP o UDP
        if ping_type in ['tcp', 'udp']:
            for target in targets:
                for port in ports:
                    if ping_type == 'tcp':
                        future = executor.submit(tcp_ping, target, port)
                    elif ping_type == 'udp':
                        future = executor.submit(udp_ping, target, port)
                    # Almacenamos el futuro junto con el target y el puerto para posterior referencia
                    futures.append((future, target, port))
        
        # Aquí se extraen solo los objetos Future para as_completed
        futures_only = [future for future, _, _ in futures]
        
        # Iterar sobre los futuros a medida que se completan
        for future in as_completed(futures_only):
            # Encuentra el target y el puerto correspondiente a este futuro completado
            _, target, port = futures[futures_only.index(future)]
            if future.result():
                print(colored(f"\t[+] Host {target} is active ({ping_type.upper()} Port {port} responded)\n", 'green'))
                # Salir después de encontrar el primer puerto abierto
                break
            else:
                pass
                #print(colored(f"\t[-] No response from Host {target} on {ping_type.upper()} Port {port}\n", 'red'))

        else:
            # Para el ping ICMP, solo se necesita el target.
            # Nota: Aquí se asume que icmp_ping está definida para aceptar un solo argumento.
            if ping_type == 'icmp':
                for target in targets:
                    executor.submit(icmp_ping, target)
