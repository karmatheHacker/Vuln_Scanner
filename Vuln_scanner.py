import nmap
import requests
import argparse
import socket
import json
import logging
import threading
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Custom headers to avoid being blocked
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# Function to scan open ports using nmap with advanced options
def port_scan(target, ports, options="-sV"):
    nm = nmap.PortScanner()
    logging.info(f"[*] Scanning {target} for open ports with options: {options}...")
    nm.scan(target, ports, arguments=options)
    if target in nm.all_hosts():
        return nm[target]
    else:
        logging.error(f"[!] Target {target} not found in scan results.")
        return {}

# Function to grab service banner and version information
def banner_grab(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')  # Send a simple HTTP request
        banner = s.recv(1024)
        return banner.decode(errors='ignore').strip()
    except Exception as e:
        logging.error(f"Error grabbing banner for port {port}: {e}")
        return f"Error: {str(e)}"

# Function to query Exploit-DB for known vulnerabilities
def query_exploit_db(service_name, version):
    url = f"https://www.exploit-db.com/search?q={service_name}+{version}"
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        exploits = []
        for row in soup.find_all('tr'):
            columns = row.find_all('td')
            if columns and len(columns) > 1:
                exploit_name = columns[1].get_text(strip=True)
                if exploit_name:
                    exploits.append(exploit_name)
        return exploits
    except requests.RequestException as e:
        logging.error(f"Error querying Exploit-DB: {e}")
        return []

# Function to query CVE database for vulnerabilities
def query_cve_database(service_name, version):
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={service_name}+{version}"
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        cves = []
        for row in soup.find_all('tr')[1:]:  # Skip header row
            columns = row.find_all('td')
            if columns and len(columns) > 1:
                cve_id = columns[0].get_text(strip=True)
                description = columns[1].get_text(strip=True)
                cves.append(f"{cve_id}: {description}")
        return cves
    except requests.RequestException as e:
        logging.error(f"Error querying CVE database: {e}")
        return []

# Function to perform vulnerability scanning on open ports
def scan_vulnerabilities(open_ports):
    vulnerabilities = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {
            executor.submit(query_exploit_db, open_ports[port]['name'], open_ports[port]['version']): port
            for port in open_ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                exploits = future.result()
                if exploits:
                    vulnerabilities[port] = exploits
            except Exception as e:
                logging.error(f"Error scanning vulnerabilities for port {port}: {e}")
    return vulnerabilities

# Function to scan the network
def scan_network(target, ports="1-1024", options="-sV"):
    logging.info(f"[*] Starting scan on {target}...")

    # Step 1: Port scan
    scan_result = port_scan(target, ports, options)
    open_ports = scan_result.get('tcp', {})
    if not open_ports:
        logging.warning("[!] No open TCP ports found!")
        return {}, {}

    logging.info(f"[*] Open ports on {target}: {', '.join(str(port) for port in open_ports)}")

    # Step 2: Banner grabbing
    logging.info("[*] Grabbing service banners...")
    for port in open_ports:
        banner = banner_grab(target, port)
        open_ports[port]['banner'] = banner
        logging.info(f"  Port {port} - {banner}")

    # Step 3: Check vulnerabilities
    logging.info("[*] Checking vulnerabilities...")
    vulnerabilities = scan_vulnerabilities(open_ports)
    return open_ports, vulnerabilities

# Function to save results to a JSON file
def save_results(target, open_ports, vulnerabilities, format="json"):
    result = {
        "target": target,
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities
    }
    if format == "json":
        output_filename = f"{target}_scan_results.json"
        with open(output_filename, 'w') as f:
            json.dump(result, f, indent=4)
        logging.info(f"[*] Results saved to {output_filename}")
    elif format == "csv":
        output_filename = f"{target}_scan_results.csv"
        with open(output_filename, 'w') as f:
            f.write("Port,Service,Version,Banner,Vulnerabilities\n")
            for port, data in open_ports.items():
                vulns = vulnerabilities.get(port, [])
                f.write(f"{port},{data['name']},{data['version']},{data.get('banner', 'No banner')},{'; '.join(vulns)}\n")
        logging.info(f"[*] Results saved to {output_filename}")
    else:
        logging.error(f"Unsupported format: {format}")

# Main function to parse arguments and start the scan
def main():
    parser = argparse.ArgumentParser(description="Advanced Network Vulnerability Scanner")
    parser.add_argument("target", help="Target IP or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (default: 1-1024)")
    parser.add_argument("-o", "--options", default="-sV", help="Nmap scan options (default: -sV)")
    parser.add_argument("-f", "--format", default="json", choices=["json", "csv"], help="Output format (default: json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Step 1: Perform the network scan
    open_ports, vulnerabilities = scan_network(args.target, args.ports, args.options)

    # Step 2: Print results
    logging.info("\nScan Results:")
    logging.info(f"Open Ports for {args.target}:")
    for port, data in open_ports.items():
        logging.info(f"  Port {port}: {data['name']} {data['version']} - {data.get('banner', 'No banner')}")

    logging.info("\nVulnerabilities found:")
    if vulnerabilities:
        for port, vuln_list in vulnerabilities.items():
            logging.info(f"  Port {port}:")
            for vuln in vuln_list:
                logging.info(f"    {vuln}")
    else:
        logging.info("  No vulnerabilities detected.")

    # Step 3: Save results to a file
    save_results(args.target, open_ports, vulnerabilities, args.format)

if __name__ == "__main__":
    main()

