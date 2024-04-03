import re
import requests
import subprocess
from bs4 import BeautifulSoup
from termcolor import colored

# Ignorando certificados autofirmados
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def get_page_title(response):
    soup = BeautifulSoup(response, 'html.parser')
    title_tag = soup.find('title')
        
    if title_tag:
        return title_tag.text     
    else:
        return "Title not found"


def parse_http_headers(headers, title, redirects, service):
    server_value = headers.get('Server', 'Not Found')
    powered_by_value = headers.get('X-Powered-By', 'Not Found')
    
    headers_str = f"Service: {service}\n"
    if title:
        headers_str += f"\t\t[i] Title: {title}\n"
    if server_value != 'Not Found':
        headers_str += f"\t\t[i] HttpServer: {server_value}\n"
    if powered_by_value != 'Not Found':
        headers_str += f"\t\t[i] X-Powered-By: {powered_by_value}\n"
    if redirects:
        headers_str += f"\t\t[!] {redirects}"
    
    return headers_str

def get_http_headers(url):
    response = requests.get(url, verify=False)
    service = 'http' if not 'https' in url else 'https'
    redirects = ""

    if response.history:
        for resp in response.history:
            redirects += f"Redirected from: {resp.url} to {response.url}"
    else:
        pass
    
    page_title = get_page_title(response.text)
    headers = parse_http_headers(response.headers, page_title, redirects, service)

    return headers

def get_smb_info(target):
    try:
        result = subprocess.run(["nmap", "-p", "445", "--script=smb-os-discovery", target], capture_output=True, text=True)
        output = result.stdout
        match = re.search(r"Samba\s(\S+)[^\)]*", output)
        if match:
            version = match.group(1).replace("(", "").replace(")", "")
            sentence = f"Service: SMB\n"
            sentence += f"\t\t[i] Samba Version: {version}"
            return sentence
        else:
            return "Samba version not found."

    except Exception as e:
        return f"Error: {e}"
