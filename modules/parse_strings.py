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
            start, end = target_str_splitted[3].split('-')

            return [f"{first_three_octets}.{i}" for i in range(int(start), int(end)+1)]
        
        else:
            return [target_str]
    else:
        print(colored(f"\n[!] IP format is not valid\n", 'red'))
