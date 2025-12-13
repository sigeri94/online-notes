import requests
from bs4 import BeautifulSoup
from stem import Signal
from stem.control import Controller
from urllib.parse import urljoin
import time
import json
import csv
import re
import logging
import sys
from requests.exceptions import RequestException, ConnectionError

# ANSI color codes for colored output
class Colors:
    RED = '\033[1;31m'        # Bold Red
    NEON_GREEN = '\033[1;92m' # Neon Green
    RESET = '\033[0m'         # Reset color

# Tool banner and descriptions with colors
def print_banner():
    banner = f"""
{Colors.RED}██████╗ ███████╗███████╗██████╗ ██╗    ██╗███████╗██████╗ ██╗  ██╗ █████╗ ██████╗ ██╗   ██╗███████╗███████╗████████╗███████╗██████╗ 
██╔══██╗██╔════╝██╔════╝██╔══██╗██║    ██║██╔════╝██╔══██╗██║  ██║██╔══██╗██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██║  ██║█████╗  █████╗  ██████╔╝██║ █╗ ██║█████╗  ██████╔╝███████║███████║██████╔╝██║   ██║█████╗  ███████╗   ██║   █████╗  ██████╔╝
██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ ██║███╗██║██╔══╝  ██╔══██╗██╔══██║██╔══██║██╔══██╗╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝███████╗███████╗██║     ╚███╔███╔╝███████╗██████╔╝██║  ██║██║  ██║██║  ██║ ╚████╔╝ ███████╗███████║   ██║   ███████╗██║  ██║
╚═════╝ ╚══════╝╚══════╝╚═╝      ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{Colors.RESET}
"""
    description = f"""
{Colors.NEON_GREEN}Welcome to DarkCrawler - a stealthy Python dark web scraper using Tor.
Crawl .onion sites anonymously, with retries, rate-limiting, and automatic Tor circuit renewal.
Created for ethical OSINT with a hacker vibe. Handle pages, extract links, save data safely.{Colors.RESET}
"""
    creator = f"{Colors.RED}Creator: Tech Enthusiast{Colors.RESET}"
    print(banner)
    print()
    print(description)
    print()
    print(creator)
    print()


# Setup logging for traceability
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Constants
TOR_SOCKS_PROXY = 'socks5h://127.0.0.1:9050'  # Use socks5h for DNS over Tor
TOR_CONTROL_PORT = 9051
CRAWL_DELAY = 7          # seconds delay between requests; increase as needed
MAX_DEPTH = 2            # maximum crawl depth
MAX_PAGES = 20           # max pages per site to avoid resource exhaustion
RETRY_COUNT = 3          # retry attempts on failure
BACKOFF_FACTOR = 4       # backoff multiplier in seconds
RENEW_CIRCUIT_EVERY = 10 # renew Tor circuit every N pages

# Regex to validate Tor v3 onion URLs (56 base32 chars + .onion)
ONION_URL_REGEX = re.compile(r'^http[s]?://[a-z2-7]{56}\.onion')

# Pages to avoid repeatedly scraping (often cause errors, require login, or are pointless)
BLACKLIST_PATHS = set(['/register.php', '/login.php'])


def renew_tor_identity(password):
    """Signal Tor to get new identity (new circuit)"""
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate(password=password)
            controller.signal(Signal.NEWNYM)
            logging.info("Tor circuit renewed for anonymity")
            time.sleep(5)  # Wait for new circuit establishment
    except Exception as e:
        logging.error(f"Failed to renew Tor identity: {e}")


def create_tor_session():
    """Create a requests session routed through Tor SOCKS5 proxy with headers"""
    session = requests.Session()
    session.proxies = {
        'http': TOR_SOCKS_PROXY,
        'https': TOR_SOCKS_PROXY
    }
    # Realistic headers to mimic a real browser
    session.headers.update({
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/115.0 Safari/537.36'),
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Connection': 'keep-alive',
        'Accept-Encoding': 'gzip, deflate',
    })
    return session


def is_valid_onion_url(url):
    """Check if URL looks like a valid v3 onion address"""
    return bool(ONION_URL_REGEX.match(url))


def extract_onion_links(base_url, soup):
    """Extract and resolve valid .onion links from a page"""
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        full_url = urljoin(base_url, href)
        if is_valid_onion_url(full_url):
            links.add(full_url)
    return links


def get_with_retries(url, session, retries=RETRY_COUNT, backoff=BACKOFF_FACTOR):
    """HTTP GET with retry and exponential backoff"""
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            response = session.get(url, timeout=30)
            response.raise_for_status()
            return response
        except (RequestException, ConnectionError) as e:
            logging.warning(f"Attempt {attempt} for {url} failed: {e}")
            last_exc = e
            sleep_time = backoff * (2 ** (attempt - 1))
            logging.info(f"Sleeping {sleep_time}s before retrying...")
            time.sleep(sleep_time)
    logging.error(f"All {retries} attempts failed for {url}. Skipping this URL.")
    raise last_exc


def scrape_onion_url(url, session):
    """Scrape a single .onion URL, return title, text, soup or None on failure"""
    try:
        if any(url.endswith(path) for path in BLACKLIST_PATHS):
            logging.info(f"Skipping blacklisted URL path: {url}")
            return None, None, None

        logging.info(f"Fetching URL: {url}")
        response = get_with_retries(url, session)
        soup = BeautifulSoup(response.text, 'lxml')
        title = soup.title.string.strip() if soup.title and soup.title.string else 'No Title Found'
        text = soup.get_text(separator='\n', strip=True)
        return title, text, soup
    except Exception as e:
        logging.error(f"Failed to scrape {url}: {e}")
        return None, None, None


def crawl_site(start_url, session, max_depth=MAX_DEPTH, max_pages=MAX_PAGES, tor_password=None):
    """Breadth-first crawl on .onion site up to max_depth and max_pages"""
    crawled = set()
    to_crawl = [(start_url, 0)]
    results = []

    while to_crawl and len(crawled) < max_pages:
        current_url, depth = to_crawl.pop(0)
        if current_url in crawled or depth > max_depth:
            continue

        title, text, soup = scrape_onion_url(current_url, session)
        if title and text:
            results.append({
                'url': current_url,
                'title': title,
                'text': text
            })
            crawled.add(current_url)

            if depth < max_depth and soup:
                links = extract_onion_links(current_url, soup)
                for link in links:
                    if link not in crawled:
                        to_crawl.append((link, depth + 1))

            logging.info(f"Crawled {len(crawled)} page(s) so far.")

            # Rate limit delay
            time.sleep(CRAWL_DELAY)

            # Periodically renew Tor circuit for anonymity
            if tor_password and len(crawled) % RENEW_CIRCUIT_EVERY == 0 and len(crawled) > 0:
                renew_tor_identity(tor_password)

    return results


def save_results_json(results, filename="darkweb_crawl_results.json"):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        logging.info(f"Results saved to JSON file: {filename}")
    except Exception as e:
        logging.error(f"Failed to save JSON results: {e}")


def save_results_csv(results, filename="darkweb_crawl_results.csv"):
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Title', 'Content'])
            for item in results:
                # Replace newlines in text with spaces for CSV readability
                clean_text = item['text'].replace('\n', ' ').replace('\r', ' ')
                writer.writerow([item['url'], item['title'], clean_text])
        logging.info(f"Results saved to CSV file: {filename}")
    except Exception as e:
        logging.error(f"Failed to save CSV results: {e}")


if __name__ == "__main__":
    print_banner()
    # Your plain text Tor ControlPort password here
    TOR_CONTROL_PASSWORD = "your_password_here"

    # Entry point .onion URLs to crawl (replace/add your targets)
    onion_start_urls = [
        "Add your onion URL here",
        # Add other .onion URLs as needed
    ]

    session = create_tor_session()
    all_results = []

    for url in onion_start_urls:
        if not is_valid_onion_url(url):
            logging.warning(f"Invalid .onion URL skipped: {url}")
            continue
        logging.info(f"Starting crawl on: {url}")
        site_data = crawl_site(url, session, tor_password=TOR_CONTROL_PASSWORD)
        all_results.extend(site_data)

    save_results_json(all_results)
    save_results_csv(all_results)

    print(f"\n{Colors.NEON_GREEN}Scraping complete! Results saved in JSON and CSV formats.{Colors.RESET}\n")
