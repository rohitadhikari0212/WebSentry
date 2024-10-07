import requests
import socket
from colorama import Fore, Style, init
import builtwith
import subprocess
import argparse


init(autoreset=True)


BOLD = '\033[1m'
RESET = '\033[0m'


def is_port_open(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((host, port)) == 0


def get_technologies_builtwith(url):
    try:
        technologies = builtwith.parse(url)
        return technologies
    except Exception as e:
        print(Fore.RED + f"Error retrieving technologies from BuiltWith: {e}")
        return {}


def get_technologies_whatweb(url):
    try:
        result = subprocess.run(['whatweb', url], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        return output
    except Exception as e:
        print(Fore.RED + f"Error retrieving technologies from WhatWeb: {e}")
        return ""


def format_whatweb_output(output):
    formatted_output = []
    for line in output.splitlines():
        if line.strip():  # Skip empty lines
            # Split each detection on commas and format them for output
            detections = line.split(', ')
            for detection in detections:
                detection = detection.strip()
                # Highlight and format each detection
                formatted_output.append(f"- {detection}")

    return '\n'.join(formatted_output)


def check_security_headers(url):
    expected_headers = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Feature-Policy",
        "Permissions-Policy"
    ]

    try:
        response = requests.get(url)
        headers = response.headers
        header_status = {}
        
        for header in expected_headers:
            if header in headers:
                header_status[header] = "is present."
            else:
                header_status[header] = "is missing."

        return header_status
    except requests.RequestException as e:
        print(Fore.RED + f"Error retrieving headers: {e}")
        return {}


def get_allowed_methods(url):
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    allowed_methods = []

    for method in methods:
        try:
            response = requests.request(method, url)
            if response.status_code == 200:
                allowed_methods.append(method)
        except requests.RequestException as e:
            print(Fore.YELLOW + f"Error sending {method} request: {e}")

    return allowed_methods


def check_firewall_technology(url):
    firewall_indicators = {
        'Cloudflare': ['CF-RAY', 'Server: cloudflare'],
        'AWS WAF': ['x-amzn-RequestId', 'X-Amz-Date'],
        'F5': ['X-F5-URI', 'X-F5-Forwarded-For', 'X-F5-Client-Ip'],
        'Imperva': ['X-Correlation-ID', 'X-Content-Type-Options'],
        'Sucuri': ['X-Sucuri-ID', 'X-Sucuri-Cache'],
        'Fortinet': ['Server: FortiWeb']
    }

    try:
        response = requests.get(url)
        detected_firewalls = {}
        
       
        for firewall, indicators in firewall_indicators.items():
            count = 0
            for indicator in indicators:
                if indicator in response.headers:
                    count += 1
            if count > 0:
                detected_firewalls[firewall] = {
                    'count': count,
                    'confidence': count / len(indicators) * 100  # Confidence percentage
                }

        
        if response.status_code in [403, 429]:
            detected_firewalls['Possible WAF'] = {'count': 1, 'confidence': 75}  # Arbitrary confidence

        return detected_firewalls
    except requests.RequestException as e:
        print(Fore.RED + f"Error retrieving headers: {e}")
        return {}


def print_boxed_output(title, content):
    border = "=" * 70
    print(Fore.BLUE + f"\n{BOLD}{title}{RESET}\n")
    print(border)
    print(content)
    print(border)


def main():
    parser = argparse.ArgumentParser(description="Web Server Vulnerability Scanner")
    
    # Define arguments
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., http://example.com)')
    parser.add_argument('-b', '--builtwith', action='store_true', help='Detect technologies using BuiltWith')
    parser.add_argument('-w', '--whatweb', action='store_true', help='Detect technologies using WhatWeb')
    parser.add_argument('-m', '--missing-headers', action='store_true', help='Check for missing security headers')
    parser.add_argument('-a', '--allowed-methods', action='store_true', help='Check allowed HTTP methods')
    parser.add_argument('-f', '--firewall', action='store_true', help='Check for firewall technologies')
    parser.add_argument('-A', '--all', action='store_true', help='Run all features')

    args = parser.parse_args()

    url = args.url

    if args.all or args.builtwith:
        technologies_builtwith = get_technologies_builtwith(url)
        if technologies_builtwith:
            builtwith_output = f"{'Technology':<30} | {'Details'}\n" + "=" * 70 + "\n"
            for tech, details in technologies_builtwith.items():
                builtwith_output += f"{Fore.CYAN + f'{BOLD}{tech}{RESET}':<30} | {', '.join(details)}\n"
            print_boxed_output("Technologies Detected by BuiltWith", builtwith_output)
        else:
            print_boxed_output("Technologies Detected by BuiltWith", "No technologies found.")

    if args.all or args.whatweb:
        technologies_whatweb = get_technologies_whatweb(url)
        formatted_whatweb_output = format_whatweb_output(technologies_whatweb)
        if formatted_whatweb_output:
            print_boxed_output("Technologies Detected by WhatWeb", formatted_whatweb_output)
        else:
            print_boxed_output("Technologies Detected by WhatWeb", "No technologies found.")

    if args.all or args.missing_headers:
        header_status = check_security_headers(url)
        if header_status:
            header_output = f"{'Header':<50} | {'Status'}\n" + "=" * 70 + "\n"
            for header, status in header_status.items():
                if "is missing." in status:
                    header_output += Fore.RED + f"{BOLD}{header:<50}{RESET} | {status}\n"
                else:
                    header_output += Fore.GREEN + f"{BOLD}{header:<50}{RESET} | {status}\n"
            print_boxed_output("Missing Security Headers", header_output)
        else:
            print_boxed_output("Missing Security Headers", "No headers information found.")

    if args.all or args.allowed_methods:
        allowed_methods = get_allowed_methods(url)
        if allowed_methods:
            methods_output = f"{'Allowed Methods':<30} | {'Status'}\n" + "=" * 70 + "\n"
            methods_output += ', '.join(Fore.GREEN + f"{BOLD}{method}{RESET}" for method in allowed_methods) + "\n"
            print_boxed_output("Allowed HTTP Methods", methods_output)
        else:
            print_boxed_output("Allowed HTTP Methods", "No allowed methods found or server did not respond.")

    if args.all or args.firewall:
        firewalls = check_firewall_technology(url)
        if firewalls:
            firewall_output = f"{'Firewall Technology':<30} | {'Confidence (%)'}\n" + "=" * 70 + "\n"
            for fw, details in firewalls.items():
                firewall_output += f"{Fore.RED + f'{BOLD}{fw}{RESET}':<30} | {details['confidence']:.2f}%\n"
            print_boxed_output("Firewall Technology Detected", firewall_output)
        else:
            print_boxed_output("Firewall Technology Detected", "No firewall technology detected.")

if __name__ == "__main__":
    main()
