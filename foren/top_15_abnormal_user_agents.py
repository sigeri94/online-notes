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
threshold = 2  # Define threshold for abnormal user agents

# Regex pattern to extract relevant fields (IP, time, URL, status code, size, user agent)
log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>.+?)\] "(?P<method>\S+) (?P<url>\S+) .+?" (?P<status>\d+) (?P<size>\d+) ".+?" "(?P<user_agent>.+?)"')

# Dictionary to store hits and user agents by date
hits_by_date = defaultdict(lambda: defaultdict(lambda: {"count": 0, "user_agents": defaultdict(int)}))

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
            status = match.group('status')
            user_agent = match.group('user_agent')
            date = extract_date(log_time)

            # Only consider requests with HTTP status code 200
            if status == '200':
                hits_by_date[date][ip]["count"] += 1
                hits_by_date[date][ip]["user_agents"][user_agent] += 1

# Identify abnormal user agents
abnormal_users_by_date = defaultdict(lambda: defaultdict(list))

for date, ip_data in hits_by_date.items():
    for ip, data in ip_data.items():
        for user_agent, count in data["user_agents"].items():
            if count < threshold:
                abnormal_users_by_date[date][ip].append(user_agent)

# Generate HTML content
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Top 15 Abnormal User Agents (HTTP 200)</title>
    <style>
        table {{ width: 100%; border-collapse: collapse; }}
        table, th, td {{ border: 1px solid black; }}
        th, td {{ padding: 8px; text-align: left; }}
    </style>
</head>
<body>
    <h1>Top 15 IP Addresses with Abnormal User Agents (HTTP 200)</h1>
    {date_sections}
</body>
</html>
"""

# Generate sections for each date
date_sections = ""

for date in sorted(abnormal_users_by_date.keys()):
    # Sort IPs by the total hit count in descending order and select the top 15
    sorted_ips = sorted(abnormal_users_by_date[date].items(), key=lambda x: hits_by_date[date][x[0]]["count"], reverse=True)[:15]

    # Generate rows for the table
    ip_rows = ""
    for ip, user_agents in sorted_ips:
        user_agents_list = ", ".join(user_agents)  # User agents for the IP
        ip_count = hits_by_date[date][ip]["count"]
        ip_rows += f"<tr><td>{ip}</td><td>{ip_count}</td><td>{user_agents_list}</td></tr>"

    # Section for this date
    date_section = f"""
    <h2>Top Abnormal User Agents for {date}</h2>
    <table>
        <tr><th>IP Address</th><th>Total Hits</th><th>Abnormal User Agents</th></tr>
        {ip_rows}
    </table>
    """
    
    date_sections += date_section

base_name = os.path.basename(log_file)
output_file_name = f"top_15_abnormal_user_agents_{base_name}.html"

# Write to an HTML file
with open(output_file_name, 'w') as f:
    f.write(html_content.format(date_sections=date_sections))

print(f"HTML report '{output_file_name}' generated successfully.")