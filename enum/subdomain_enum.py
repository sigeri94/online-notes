import socket
import sublist3r
from ipwhois import IPWhois
from datetime import datetime

# Function to get the IP address of a domain
def get_ip_address(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "IP address not found"

# Function to find the IP range using IPWhois
def get_ip_range(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        network = results.get('network', {})
        cidr = network.get('cidr', 'Range not found')
        return cidr
    except Exception as e:
        return f"Range not found ({e})"

# Function to get subdomains using Sublist3r
def get_subdomains(domain):
    print(f"Finding subdomains for {domain}...")
    subdomains = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains

# Function to read domain list from a file
def read_domain_list(file_path):
    with open(file_path, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    return domains

# Function to generate an HTML file
def generate_html(domains_with_info, output_file):
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Subdomains, IPs, and IP Ranges</title>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>Subdomains, IP Addresses, and IP Ranges</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <table>
            <tr>
                <th>Domain</th>
                <th>Subdomain</th>
                <th>IP Address</th>
                <th>IP Range</th>
            </tr>
    """
    
    for domain, subdomains_info in domains_with_info.items():
        for subdomain, (ip, ip_range) in subdomains_info.items():
            html_content += f"""
            <tr>
                <td>{domain}</td>
                <td>{subdomain}</td>
                <td>{ip}</td>
                <td>{ip_range}</td>
            </tr>
            """
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    print(f"HTML file saved as {output_file}")

# Main function
def main():
    input_file = "domains.txt"  # Input file containing the domain list
    output_file = "subdomains_ip_ranges.html"  # Output HTML file
    
    # Read domains from file
    domains = read_domain_list(input_file)
    
    domains_with_info = {}
    
    for domain in domains:
        # Get subdomains
        subdomains = get_subdomains(domain)
        
        subdomains_info = {}
        
        for subdomain in subdomains:
            # Get IP address
            ip = get_ip_address(subdomain)
            
            # Get IP range
            if ip != "IP address not found":
                ip_range = get_ip_range(ip)
            else:
                ip_range = "Range not found"
            
            subdomains_info[subdomain] = (ip, ip_range)
        
        domains_with_info[domain] = subdomains_info
    
    # Generate the HTML output
    generate_html(domains_with_info, output_file)

if __name__ == "__main__":
    main()
