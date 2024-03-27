import re
from termcolor import colored

def parse_ports(ports_str):
    
    if '-' in ports_str:
        start, end = map(int, ports_str.split('-'))
        return range(start, end+1)
    
    elif ',' in ports_str:
        return list(map(int, ports_str.split(',')))
    
    else:
        return (int(ports_str),)

def parse_target(target_str):

    # 192.168.1.1-100
    target_str_splitted = target_str.split('.') # ["192", "168", "1", "1-100"]
    first_three_octets = '.'.join(target_str_splitted[:3]) # 192.168.1

    if len(target_str_splitted) == 4:
        if "-" in target_str_splitted[3]:
            start, end = target_str_splitted[3].split('-'
                                                      )
            return [f"{first_three_octets}.{i}" for i in range(int(start), int(end)+1)]
        
        else:
            return [target_str]
    else:
        print(colored(f"\n[!] El formato de ip no es válido\n", 'red'))

def parse_banner(banner):
    ssh_match = re.search(r"SSH-(?P<protocol>\d+\.\d+)-OpenSSH_(?P<version>\d+\.\d+)", banner)
    
    if ssh_match:
        service = "ssh"
        version = match.group("version")
        protocol = match.group("protocol")
    
        # Formatear y mostrar el anuncio
        announcement = f"[i] Service: {service}\n\t\t[i] Version: OpenSSH {version} \n\t\t[i] Protocol: {protocol}"
        return announcement

    # Buscar coincidencia para FTP
    ftp_match = re.search(r"220 \(vsFTPd (?P<version>\d+\.\d+\.\d+)\)", banner)
    if ftp_match:
        service = "FTP"
        version = ftp_match.group("version")
        announcement = f"[i] Service: {service}\n\t\t[i] Version: vsFTPd {version}"
        return announcement

    else:
        error = f"[!] Not matches"
        return f"[i] {banner}"
