from lxml import etree
import pandas as pd
import argparse
import socket
import struct

def parse_nessus_file(nessus_file):
    vulnerabilities = []

    # Parse the .nessus file
    tree = etree.parse(nessus_file)

    # Extract hosts and vulnerabilities
    for report_host in tree.xpath("//ReportHost"):
        ip_address = report_host.attrib.get("name")

        for report_item in report_host.xpath(".//ReportItem"):
            vuln_name = report_item.attrib.get("pluginName")
            severity = report_item.attrib.get("severity")
            plugin_output = report_item.findtext("plugin_output", "No output provided")

            # Map severity values to descriptive names
            severity_mapping = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Info"}
            severity = severity_mapping.get(severity, "Unknown")

            # Skip plugin_output for specific vulnerabilities
            if any(keyword in vuln_name.lower() for keyword in ["redis","oracle","jboss","java","version", "cgi", "xss", "html injection", "apache", "php","hsts","ssl","tls","openssl","browsable","trace","clickjacking","disclosure","telnet","ssh","openssh","mDNS","identification","xxe","jenkins"]):
                plugin_output = "skipped"

            # Only include Critical, High, and Medium severities
            if severity in {"Critical", "High", "Medium"}:
                vulnerabilities.append((vuln_name, ip_address, severity, plugin_output))

    return vulnerabilities

def ip_to_int(ip):
    """Convert an IP address from string to integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def create_vuln_table(vulnerabilities):
    # Convert the vulnerabilities list to a Pandas DataFrame
    df = pd.DataFrame(vulnerabilities, columns=['Vulnerability Name', 'IP Address', 'Severity', 'Plugin Output'])

    # Sort by Vulnerability Name and then by IP Address (numeric sorting)
    severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
    df['Severity Rank'] = df['Severity'].map(severity_order)
    df['IP Numeric'] = df['IP Address'].apply(ip_to_int)

    # Sort by Vulnerability Name, then by IP Address, and finally by Severity (descending)
    df_sorted = df.sort_values(by=['Vulnerability Name', 'IP Numeric', 'Severity Rank'], ascending=[True, True, False])

    # Drop unnecessary columns
    df_sorted = df_sorted.drop(columns=['Severity Rank', 'IP Numeric'])

    return df_sorted

def save_to_html_by_severity(df_sorted):
    # Group vulnerabilities by severity
    severities = df_sorted['Severity'].unique()
    for severity in severities:
        severity_df = df_sorted[df_sorted['Severity'] == severity].reset_index(drop=True)
        
        # Add a column for row numbers restarting at 1 for each severity
        severity_df.insert(0, 'No', range(1, len(severity_df) + 1))

        filename = f"vulnerabilities_{severity.lower()}.html"

        # Save to HTML with custom CSS
        with open(filename, 'w') as f:
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
    <title>Vulnerability Report - {severity}</title>
</head>
<body>
    <h1>Vulnerability Report - {severity}</h1>
            """)
            # Convert plugin_output to be wrapped in <pre> tags
            severity_df['Plugin Output'] = severity_df['Plugin Output'].apply(lambda x: f"{x}")
            f.write(severity_df.to_html(index=False, escape=False))
            f.write("""
</body>
</html>
            """)
        print(f"Saved HTML file to: {filename}")

def save_to_csv(df_sorted, csv_file):
    # Save to CSV
    df_sorted.to_csv(csv_file, index=False)
    print(f"Saved CSV file to: {csv_file}")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Process a .nessus file and extract vulnerabilities.")
    parser.add_argument("nessus_file", help="Path to the .nessus file to be processed")
    args = parser.parse_args()

    # Parse the .nessus file
    vulnerabilities = parse_nessus_file(args.nessus_file)

    if not vulnerabilities:
        print("No vulnerabilities found or failed to parse the file.")
        return

    # Create a sorted table of vulnerabilities
    vuln_table = create_vuln_table(vulnerabilities)

    if vuln_table.empty:
        print("Failed to create vulnerability table.")
        return

    # Save results to separate HTML files by severity
    save_to_html_by_severity(vuln_table)

    # Save results to a CSV file
    csv_output_file = 'vulnerabilities_output.csv'
    save_to_csv(vuln_table, csv_output_file)

if __name__ == '__main__':
    main()
