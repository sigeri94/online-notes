import re
import os
import gzip
import argparse
import geoip2.database
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Static variable for the GeoLite2 City database path
GEOIP_DB_PATH = '/cygdrive/d/pelindo/GeoLite2-City.mmdb'

# Set up argument parser
parser = argparse.ArgumentParser(description='Parse Apache access logs and generate an HTML report of IP addresses hitting the /tasks URL with a specific referer.')
parser.add_argument('log_files', nargs='+', help='Paths to the Apache access log files (can be .gz or plain text)')
args = parser.parse_args()

log_files = args.log_files

# Load the GeoLite2-City database
reader = geoip2.database.Reader(GEOIP_DB_PATH)

# Regex pattern to extract IP, time, URL, referer, and status code
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>.+?)\] "(?P<method>\S+) (?P<url>\S+) .+?" (?P<status>\d+) (?P<size>\d+) "(?P<referer>.+?)" ".+"'
)

# Function to process a single log file
def process_log_file(log_file):
    hits_by_date = defaultdict(lambda: defaultdict(int))  # Track hits by date and IP

    # Helper function to extract date in 'YYYY-MM-DD' format
    def extract_date(log_time):
        return datetime.strptime(log_time.split()[0], "%d/%b/%Y:%H:%M:%S").strftime("%Y-%m-%d")

    # Helper function to open gzipped or plain text log files
    def open_log_file(log_file):
        if log_file.endswith('.gz'):
            return gzip.open(log_file, 'rt')  # Open gzipped file in text mode
        else:
            return open(log_file, 'r')  # Open regular text file

    with open_log_file(log_file) as f:
        for line in f:
            match = log_pattern.match(line)
            if match:
                ip = match.group('ip')
                log_time = match.group('time')
                url = match.group('url')
                referer = match.group('referer')

                # Check for /tasks URL and referer from the specific URL
                if url == '/tasks' and referer == 'https://prima.pelindo.co.id/auth':
                    date = extract_date(log_time)
                    hits_by_date[date][ip] += 1  # Increment hit count for the date and IP

    return hits_by_date

# Process log files concurrently
hits_by_date_combined = defaultdict(lambda: defaultdict(int))

with ThreadPoolExecutor(max_workers=5) as executor:
    future_to_file = {executor.submit(process_log_file, log_file): log_file for log_file in log_files}

    for future in as_completed(future_to_file):
        log_file = future_to_file[future]
        try:
            hits_by_date = future.result()
            # Combine results into hits_by_date_combined
            for date, ip_data in hits_by_date.items():
                for ip, count in ip_data.items():
                    hits_by_date_combined[date][ip] += count
        except Exception as exc:
            print(f'{log_file} generated an exception: {exc}')

# Sort dates in chronological order
sorted_dates = sorted(hits_by_date_combined.keys())

# Generate HTML content
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hits on /tasks URL</title>
    <style>
        body {{
            font-family: 'Arial', sans-serif;
            background-color: #f7f9fc;
            color: #333;
            margin: 0;
            padding: 0;
        }}
        h1 {{
            background-color: #4b6584;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        h2 {{
            color: #4b6584;
            margin: 20px;
        }}
        table {{
            width: 600px;
            margin: 0 auto 20px auto;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 10px;
            border: 1px solid #ccc;
            text-align: left;
        }}
        th {{
            background-color: #f0f5f9;
            color: #4b6584;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        tr:hover {{
            background-color: #e3f2fd;
        }}
        .non-indonesia {{
            background-color: orange;
            color: white;
        }}
        .footer {{
            text-align: center;
            padding: 10px;
            background-color: #f0f5f9;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <h1>IP Addresses Hitting /tasks URL</h1>
    {date_sections}
    <div class="footer">
        <p>Generated by Apache Log Parser</p>
    </div>
</body>
</html>
"""

# Generate sections for each date
date_sections = ""

for date in sorted_dates:
    # Sort IPs by total hits in descending order
    sorted_ips = sorted(hits_by_date_combined[date].items(), key=lambda x: x[1], reverse=True)

    # Prepare IP rows for the HTML table
    ip_rows = ""
    for ip, total_hits in sorted_ips:
        try:
            response = reader.city(ip)
            city = response.city.name if response.city.name else "Unknown"
            country = response.country.name if response.country.name else "Unknown"
        except geoip2.errors.AddressNotFoundError:
            city = "Unknown"
            country = "Unknown"

        # Determine if the row should be colored for non-Indonesian IPs
        row_class = "non-indonesia" if country != "Indonesia" else ""

        ip_rows += f"<tr class='{row_class}'><td>{ip}</td><td>{total_hits}</td><td>{city}</td><td>{country}</td></tr>"

    # Add section for this date
    date_section = f"""
    <h2>Hits for {date}</h2>
    <table>
        <tr><th>IP Address</th><th>Total Hits</th><th>City</th><th>Country</th></tr>
        {ip_rows}
    </table>
    """
    
    date_sections += date_section

# Output filename based on the first log file's name
base_name = os.path.basename(log_files[0])
output_file_name = f"hits_on_tasks_url_{base_name}.html"

# Write to an HTML file
with open(output_file_name, 'w') as f:
    f.write(html_content.format(date_sections=date_sections))

# Close the GeoLite2 reader
reader.close()

print(f"HTML report '{output_file_name}' generated successfully.")