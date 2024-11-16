from lxml import etree
import argparse
import pandas as pd
import socket
import struct
from datetime import datetime

def parse_nessus_file_for_vuln(nessus_file, vuln_name_filter):
    vulnerabilities = []

    # Parse the .nessus file
    tree = etree.parse(nessus_file)

    # Extract hosts and vulnerabilities
    for report_host in tree.xpath("//ReportHost"):
        ip_address = report_host.attrib.get("name")

        for report_item in report_host.xpath(".//ReportItem"):
            vuln_name = report_item.attrib.get("pluginName")
            plugin_output = report_item.findtext("plugin_output", "No output provided")

            # Check if the vulnerability name matches the filter
            if vuln_name_filter.lower() in vuln_name.lower():
                vulnerabilities.append((vuln_name, ip_address, plugin_output))

    return vulnerabilities

def ip_to_int(ip):
    """Convert an IP address from string to integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def save_to_csv(vulnerabilities, output_filename):
    # Convert to DataFrame
    df = pd.DataFrame(vulnerabilities, columns=["Vulnerability Name", "IP Address", "Plugin Output"])

    # Sort by IP Address numerically
    df['IP Numeric'] = df['IP Address'].apply(ip_to_int)
    df = df.sort_values(by='IP Numeric').drop(columns=['IP Numeric'])

    df.to_csv(output_filename, index=False)
    print(f"Saved CSV file to: {output_filename}")

def save_to_html(vulnerabilities, output_filename):
    # Convert to DataFrame
    df = pd.DataFrame(vulnerabilities, columns=["Vulnerability Name", "IP Address", "Plugin Output"])

    # Sort by IP Address numerically
    df['IP Numeric'] = df['IP Address'].apply(ip_to_int)
    df = df.sort_values(by='IP Numeric').drop(columns=['IP Numeric'])

    # Save to HTML
    with open(output_filename, 'w') as f:
        f.write(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f9f9f9;
            color: #333;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        table th, table td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        table th {{
            background-color: #f2f2f2;
        }}
        table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        table tr:hover {{
            background-color: #f1f1f1;
        }}
        pre {{
            background-color: #f4f4f4;
            padding: 10px;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
    </style>
    <title>Vulnerability Report</title>
</head>
<body>
    <h1>Vulnerability Report</h1>
            """)
        # Format plugin output with <pre> tags
        df['Plugin Output'] = df['Plugin Output'].apply(lambda x: f"<pre>{x}</pre>")
        f.write(df.to_html(index=False, escape=False))
        f.write("""
</body>
</html>
        """)
    print(f"Saved HTML file to: {output_filename}")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Process a .nessus file and extract specific vulnerabilities.")
    parser.add_argument("nessus_file", help="Path to the .nessus file to be processed")
    parser.add_argument("vuln_name_filter", help="Name of the vulnerability to filter")
    args = parser.parse_args()

    # Parse the .nessus file for the specified vulnerability name
    vulnerabilities = parse_nessus_file_for_vuln(args.nessus_file, args.vuln_name_filter)

    if not vulnerabilities:
        print("No matching vulnerabilities found.")
        return

    # Generate timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d%H%M")

    # Define filenames
    csv_filename = f"vulnerabilities_{args.vuln_name_filter.replace(' ', '_')}_{timestamp}.csv"
    html_filename = f"vulnerabilities_{args.vuln_name_filter.replace(' ', '_')}_{timestamp}.html"

    # Save results to CSV and HTML
    save_to_csv(vulnerabilities, csv_filename)
    save_to_html(vulnerabilities, html_filename)

if __name__ == '__main__':
    main()
