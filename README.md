# Basic usage 
python Vuln_scanner <target>
Replace <target> with the IP address or hostname of the target you want to scan (e.g., example.com or 192.168.1.1)
# Advance Option 
python Vuln_scanner <target> -p 1-1000 port scan
python  Vuln_scanner <target> -o "-sV -O" ( -sV for version detection ) ( OS detection may require elevated privileges. Run the script with sudo if needed )
sudo python Vuln_Scanner <target>
# OUTPUT FORMAT 
python main.py <target> -f csv save in CSV
# Example Commands 
python Vuln_Scanner example.com
python Vuln_Scanner <TARGET> -p 1-500 -f csv ( Scans for the ports and save the results in CSV format )
# NOTE 
Ensure you have permission to scan the target. Unauthorized scanning of systems is illegal and unethical.

