import os
import re
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

# Regex pattern to extract relevant fields (IP, time, URL, status code, user agent)
log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>.+?)\] "(?P<method>\S+) (?P<url>\S+) .+?" (?P<status>\d+) \d+ ".+?" "(?P<user_agent>.+?)"')

# Dictionary to store hits and details by date
hits_by_date = defaultdict(lambda: defaultdict(lambda: {"count": 0, "urls": set(), "user_agents": set()}))

# Helper function to extract date in 'YYYY-MM-DD' format
def extract_date(log_time):
    return datetime.strptime(log_time.split()[0], "%d/%b/%Y:%H:%M:%S").strftime("%Y-%m-%d")

# Helper function to open either a regular or gzipped log file
def open_log_file(log_file):
    if log_file.endswith('.gz'):
        return gzip.open(log_file, 'rt')  # Open gzipped file in text mode
    else:
        return open(log_file, 'r')  # Open regular text file

# Function to check if a URL is for an excluded file type
def is_excluded_url(url):
    excluded_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.svg', 
                           '.woff', '.woff2', '.ttf', '.js', '.css')
    return url.lower().endswith(excluded_extensions)

# Parse the log file
with open_log_file(log_file) as f:
    for line in f:
        match = log_pattern.match(line)
        if match:
            ip = match.group('ip')
            log_time = match.group('time')
            url = match.group('url')
            status = match.group('status')
            user_agent = match.group('user_agent')
            date = extract_date(log_time)

            # Only count hits with HTTP status code 200 and not excluded URLs
            if status == '200' and not is_excluded_url(url):
                hits_by_date[date][ip]["count"] += 1
                hits_by_date[date][ip]["urls"].add(url)
                hits_by_date[date][ip]["user_agents"].add(user_agent)

# Sort dates in chronological order
sorted_dates = sorted(hits_by_date.keys())

# Generate HTML content
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Top 15 IPs by Hits (HTTP 200)</title>
    <style>
        table {{ width: 100%; border-collapse: collapse; }}
        table, th, td {{ border: 1px solid black; }}
        th, td {{ padding: 8px; text-align: left; }}
    </style>
</head>
<body>
    <h1>Top 15 IP Addresses by Hits with HTTP 200, Grouped by Date</h1>
    {date_sections}
</body>
</html>
"""

# Generate sections for each date
date_sections = ""

for date in sorted_dates:
    # Sort IPs by hit count in descending order and select the top 15
    sorted_ips = sorted(hits_by_date[date].items(), key=lambda x: x[1]['count'], reverse=True)[:15]

    # Generate rows for the table
    ip_rows = ""
    for ip, details in sorted_ips:
        urls = "<br>".join(details["urls"])  # URLs hit by the IP
        user_agents = "<br>".join(details["user_agents"])  # User agents used by the IP
        ip_rows += f"<tr><td>{ip}</td><td>{details['count']}</td><td>{urls}</td><td>{user_agents}</td></tr>"

    # Section for this date
    date_section = f"""
    <h2>Top 15 IP Addresses for {date}</h2>
    <table>
        <tr><th>IP Address</th><th>Hit Count</th><th>URLs Hit</th><th>User Agents</th></tr>
        {ip_rows}
    </table>
    """
    
    date_sections += date_section

# Create output filename based on the log file name
base_name = os.path.basename(log_file)
output_file_name = f"top_15_ip_hits_by_date_{base_name}.html"

# Write to an HTML file
with open(output_file_name, 'w') as f:
    f.write(html_content.format(date_sections=date_sections))

print(f"HTML report '{output_file_name}' generated successfully.")
