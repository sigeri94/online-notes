import subprocess
import os

def get_nameservers(domain):
    """Use dig to get the authoritative nameservers for a domain."""
    print(f"[INFO] Enumerating nameservers for {domain} using dig...")
    try:
        result = subprocess.run(['dig', '+noall', '+answer', 'NS', domain], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] Failed to get nameservers for {domain}")
            return []

        # Parse the nameserver response
        nameservers = [line.split()[-1] for line in result.stdout.splitlines()]
        print(f"[SUCCESS] Found nameservers for {domain}: {', '.join(nameservers)}")
        return nameservers
    except Exception as e:
        print(f"[ERROR] Error during nameserver enumeration for {domain}: {e}")
        return []

def perform_axfr(domain, ns_server):
    """Use dig to attempt an AXFR (DNS zone transfer) from the specified nameserver."""
    print(f"[INFO] Attempting AXFR for {domain} on nameserver {ns_server} using dig...")
    try:
        result = subprocess.run(['dig', f'@{ns_server}', domain, 'AXFR'], capture_output=True, text=True)
        if "Transfer failed" in result.stdout or result.returncode != 0:
            print(f"[ERROR] Failed to perform AXFR for {domain} from {ns_server}")
            return None
        print(f"[SUCCESS] Zone transfer successful for {domain} on {ns_server}")
        return result.stdout
    except Exception as e:
        print(f"[ERROR] Error during AXFR for {domain} from {ns_server}: {e}")
        return None

def save_to_html(domain, axfr_results, output_dir="axfr_results"):
    """Save the AXFR result to an HTML file."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    filename = os.path.join(output_dir, f"{domain}_axfr_output.html")

    html_content = f"<html><head><title>AXFR Output for {domain}</title></head><body>"
    html_content += f"<h1>AXFR Results for {domain}</h1><pre>{axfr_results}</pre>"
    html_content += "</body></html>"

    with open(filename, "w") as f:
        f.write(html_content)

    print(f"[INFO] AXFR results saved to {filename}")

def process_domains(domain_file):
    """Read domains from file, attempt zone transfer on each nameserver, and save output."""
    try:
        with open(domain_file, "r") as file:
            domains = [line.strip() for line in file if line.strip()]

        print(f"[INFO] Found {len(domains)} domains to process.")

        for domain in domains:
            nameservers = get_nameservers(domain)
            if nameservers:
                for ns_server in nameservers:
                    axfr_output = perform_axfr(domain, ns_server)
                    if axfr_output:
                        save_to_html(domain, axfr_output)
                    else:
                        print(f"[WARNING] No AXFR results to save for {domain}.")
            else:
                print(f"[WARNING] No nameservers found for {domain}.")

    except FileNotFoundError:
        print(f"[ERROR] The file {domain_file} does not exist.")
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")

if __name__ == "__main__":
    domain_file = "domains.txt"  # File containing list of domains (one per line)
    process_domains(domain_file)
