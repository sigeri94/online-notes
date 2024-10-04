import re
import os
import gzip
import argparse
from collections import defaultdict
from datetime import datetime

# Set up argument parser
parser = argparse.ArgumentParser(description='Process Apache access log file.')
parser.add_argument('log_file', help='Path to the Apache access log file (can be .gz or plain text)')
args = parser.parse_args()

# Get the log file from the arguments
log_file = args.log_file

# Regex pattern to extract relevant fields (IP, time, URL, status code, size, user agent)
log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>.+?)\] "(?P<method>\S+) (?P<url>\S+) .+?" (?P<status>\d+) (?P<size>\d+) ".+?" "(?P<user_agent>.+?)"')

# Dictionary to store download details by date
downloads_by_date = defaultdict(lambda: defaultdict(lambda: {"bytes": 0, "urls": set(), "user_agents": set()}))

# Helper function to extract date in 'YYYY-MM-DD' format
def extract_date(log_time):
    return datetime.strptime(log_time.split()[0], "%d/%b/%Y:%H:%M:%S").strftime("%Y-%m-%d")

# Helper function to open either a regular or gzipped log file
def open_log_file(log_file):
    if log_file.endswith('.gz'):
        return gzip.open(log_file, 'rt')  # Open gzipped file in text mode
    else:
        return open(log_file, 'r')  # Open regular text file

# Parse the log file
with open_log_file(log_file) as f:
    for line in f:
        match = log_pattern.match(line)
        if match:
            ip = match.group('ip')
            log_time = match.group('time')
            url = match.group('url')
            status = match.group('status')
            size = int(match.group('size'))
            user_agent = match.group('user_agent')
            date = extract_date(log_time)

            # Only consider requests with HTTP status code 200
            if status == '200':
                downloads_by_date[date][ip]["bytes"] += size
                downloads_by_date[date][ip]["urls"].add(url)
                downloads_by_date[date][ip]["user_agents"].add(user_agent)

# Sort dates in chronological order
sorted_dates = sorted(downloads_by_date.keys())

# Generate HTML content
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Top 15 IPs by Downloads (HTTP 200)</title>
    <style>
        table {{ width: 100%; border-collapse: collapse; }}
        table, th, td {{ border: 1px solid black; }}
        th, td {{ padding: 8px; text-align: left; }}
    </style>
</head>
<body>
    <h1>Top 15 IP Addresses by Total Bytes Downloaded with HTTP 200, Grouped by Date</h1>
    {date_sections}
</body>
</html>
"""

# Generate sections for each date
date_sections = ""

for date in sorted_dates:
    # Sort IPs by total bytes downloaded in descending order and select the top 15
    sorted_ips = sorted(downloads_by_date[date].items(), key=lambda x: x[1]['bytes'], reverse=True)[:15]

    # Generate rows for the table
    ip_rows = ""
    for ip, details in sorted_ips:
        urls = "<br>".join(details["urls"])  # URLs hit by the IP
        user_agents = "<br>".join(details["user_agents"])  # User agents used by the IP
        ip_rows += f"<tr><td>{ip}</td><td>{details['bytes']}</td><td>{urls}</td><td>{user_agents}</td></tr>"

    # Section for this date
    date_section = f"""
    <h2>Top 15 IP Addresses for {date}</h2>
    <table>
        <tr><th>IP Address</th><th>Total Bytes Downloaded</th><th>URLs Hit</th><th>User Agents</th></tr>
        {ip_rows}
    </table>
    """
    
    date_sections += date_section

base_name = os.path.basename(log_file)
output_file_name = f"top_15_ip_downloads_by_date_{base_name}.html"

# Write to an HTML file
with open(output_file_name, 'w') as f:
    f.write(html_content.format(date_sections=date_sections))

print(f"HTML report '{output_file_name}' generated successfully.")