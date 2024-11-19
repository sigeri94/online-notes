import os
import argparse
from lxml import etree
from datetime import datetime

def convert_nmap_xml_to_html(xml_file, output_html):
    try:
        # Parse the Nmap XML file
        tree = etree.parse(xml_file)
        root = tree.getroot()

        # Start the HTML content with external CSS
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Nmap Scan Report</title>
            <link rel="stylesheet" href="nmap_report.css">
        </head>
        <body>
            <h1>Nmap Scan Report</h1>
            <p>Generated: {}</p>
        """.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Extract scan details
        for host in root.findall("host"):
            address = host.find("address").get("addr") if host.find("address") is not None else "Unknown"
            hostname = host.find("hostnames/hostname").get("name") if host.find("hostnames/hostname") is not None else "Unknown"
            status = host.find("status").get("state") if host.find("status") is not None else "Unknown"

            html_content += f"""
            <h2>Host: {address} ({hostname})</h2>
            <p>Status: {status}</p>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>SSL Details</th>
                    </tr>
                </thead>
                <tbody>
            """

            # Extract port and SSL details
            for port in host.findall("ports/port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                state = port.find("state").get("state") if port.find("state") is not None else "Unknown"

                # Check for SSL script output
                script_output = ""
                script = port.find("script[@id='ssl-enum-ciphers']")
                if script is not None:
                    script_output = script.get("output", "Details not available")
                    script_output = script_output.replace("\n", "<br>")  # Format line breaks

                html_content += f"""
                    <tr>
                        <td>{port_id}</td>
                        <td>{protocol}</td>
                        <td>{state}</td>
                        <td>{script_output}</td>
                    </tr>
                """

            html_content += """
                </tbody>
            </table>
            """

        # Close the HTML content
        html_content += """
        </body>
        </html>
        """

        # Write the HTML file with UTF-8 encoding
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"HTML report successfully generated: {output_html}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Setup argument parser
    parser = argparse.ArgumentParser(description="Convert Nmap XML output to HTML.")
    parser.add_argument("xml_file", help="Path to the Nmap XML file")
    parser.add_argument("output_html", help="Path to save the generated HTML file")
    args = parser.parse_args()

    # Run the conversion function
    if not os.path.exists(args.xml_file):
        print(f"Error: The file '{args.xml_file}' does not exist.")
    else:
        convert_nmap_xml_to_html(args.xml_file, args.output_html)
