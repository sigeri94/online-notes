from lxml import etree
import argparse
import pandas as pd
import socket
import struct
from datetime import datetime

def parse_nessus_file_for_vulns(nessus_file, vuln_name_filters):
    vulnerabilities = []

    # Parse the .nessus file
    tree = etree.parse(nessus_file)

    # List of keywords to mark as skipped
    skipped_keywords = ["ms09-050", "redis"]

    # Extract hosts and vulnerabilities
    for report_host in tree.xpath("//ReportHost"):
        ip_address = report_host.attrib.get("name")

        for report_item in report_host.xpath(".//ReportItem"):
            vuln_name = report_item.attrib.get("pluginName", "Unknown Vulnerability")
            severity_code = report_item.attrib.get("severity", "0")
            solution = report_item.findtext("solution", "No solution provided")
            plugin_output = report_item.findtext("plugin_output", "No plugin output provided")

            # Convert severity code to readable format
            severity_mapping = {
                "0": "Informational",
                "1": "Low",
                "2": "Medium",
                "3": "High",
                "4": "Critical"
            }
            severity = severity_mapping.get(severity_code, "Unknown")

            # Check if the plugin output should be marked as skipped
            if any(keyword in vuln_name.lower() for keyword in skipped_keywords):
                plugin_output = "Skipped"

            # Wrap Plugin Output in <pre> tag for specific vulnerability
            if vuln_name.lower() == "browsable web directories":
                plugin_output = f"<pre>{plugin_output}</pre>"

            # Check if the vulnerability name matches any of the filters
            if any(filter_name.lower() in vuln_name.lower() for filter_name in vuln_name_filters):
                vulnerabilities.append((ip_address, vuln_name, plugin_output, solution))

    return vulnerabilities

def ip_to_int(ip):
    """Convert an IP address from string to integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def save_to_csv(vulnerabilities, output_filename):
    # Convert to DataFrame
    df = pd.DataFrame(vulnerabilities, columns=["IP Address", "Vulnerability Name", "Plugin Output", "Solution"])

    # Sort by IP Address numerically
    df['IP Numeric'] = df['IP Address'].apply(ip_to_int)
    df = df.sort_values(by='IP Numeric').drop(columns=['IP Numeric'])

    # Save to CSV
    df.to_csv(output_filename, index=False)
    print(f"Saved CSV file to: {output_filename}")

def save_to_html(vulnerabilities, output_filename):
    # Convert to DataFrame
    df = pd.DataFrame(vulnerabilities, columns=["IP Address", "Vulnerability Name", "Plugin Output", "Solution"])

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
        # Render DataFrame to HTML and ensure escaped=False for plugin output
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
    parser.add_argument("vuln_name_filters", nargs="+", help="Names of the vulnerabilities to filter (multiple allowed)")
    args = parser.parse_args()

    # Parse the .nessus file for the specified vulnerability names
    vulnerabilities = parse_nessus_file_for_vulns(args.nessus_file, args.vuln_name_filters)

    if not vulnerabilities:
        print("No matching vulnerabilities found.")
        return

    # Generate timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d%H%M")

    # Define filenames
    filters_str = "_"
    csv_filename = f"vulnerabilities_{filters_str}_{timestamp}.csv"
    html_filename = f"vulnerabilities_{filters_str}_{timestamp}.html"

    # Save results to CSV and HTML
    save_to_csv(vulnerabilities, csv_filename)
    save_to_html(vulnerabilities, html_filename)

if __name__ == '__main__':
    main()
