import os
import time
import signal
import logging
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from threading import Lock
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
import sys

VERSION = 'v1.4'

# Suppress unnecessary logs
os.environ['WDM_LOG_LEVEL'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# Configure logging
logging.basicConfig(level=logging.ERROR)  # Only show errors
logging.getLogger('selenium').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)
logging.getLogger('chromedriver').setLevel(logging.ERROR)

# Initialize colorama
init(autoreset=True)
console = Console()

driver_pool = Queue()
driver_lock = Lock()

# Global variables to store scan state
scan_state = {
    'vulnerability_found': False,
    'vulnerable_urls': [],
    'total_found': 0,
    'total_scanned': 0,
    'start_time': time.time(),
    'interrupted': False  # Flag to track if the scan was interrupted
}

def signal_handler(sig, frame):
    """
    Handle Ctrl+C interruption gracefully.
    """
    if scan_state['interrupted']:
        return  # Prevent multiple interruptions

    scan_state['interrupted'] = True
    print(Fore.RED + "\n[!] Scan interrupted by the user.")
    print_scan_summary(scan_state['total_found'], scan_state['total_scanned'], scan_state['start_time'])
    # save_results(scan_state['vulnerable_urls'], scan_state['total_found'], scan_state['total_scanned'], scan_state['start_time'])
    # sys.exit(1)
    print(f"{Fore.RED}Exiting...")
    os._exit(0)

# Register the signal handler for Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

def load_payloads(payload_file):
    try:
        with open(payload_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error loading payloads: {e}")
        os._exit(0)

def generate_payload_urls(url, payload):
    url_combinations = []
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    if not scheme:
        scheme = 'http'
    query_params = parse_qs(query_string, keep_blank_values=True)
    for key in query_params.keys():
        modified_params = query_params.copy()
        modified_params[key] = [payload]
        modified_query_string = urlencode(modified_params, doseq=True)
        modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
        url_combinations.append(modified_url)
    return url_combinations

def create_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--log-level=3")  # Suppress ChromeDriver logs
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])  # Suppress DevTools logs

    driver_service = Service(ChromeDriverManager().install())
    return webdriver.Chrome(service=driver_service, options=chrome_options)

def get_driver():
    try:
        return driver_pool.get_nowait()
    except:
        with driver_lock:
            return create_driver()

def return_driver(driver):
    driver_pool.put(driver)

def check_vulnerability(url, payload, vulnerable_urls, total_scanned, timeout, scan_state):
    driver = get_driver()
    try:
        payload_urls = generate_payload_urls(url, payload)
        if not payload_urls:
            return

        for payload_url in payload_urls:
            try:
                start_time = time.time()
                driver.get(payload_url)
                
                total_scanned[0] += 1
                
                try:
                    alert = WebDriverWait(driver, timeout).until(EC.alert_is_present())
                    alert_text = alert.text

                    if alert_text:
                        ## Vulnerable case
                        # print(f"{Fore.YELLOW}[→] Scanning with payload: {payload}")
                        print(f"{Fore.YELLOW}[✓] Vulnerable: {Fore.LIGHTGREEN_EX}{payload_url} {Fore.GREEN}")
                        vulnerable_urls.append(payload_url)
                        if scan_state:
                            scan_state['vulnerability_found'] = True
                            scan_state['vulnerable_urls'].append(payload_url)
                            scan_state['total_found'] += 1
                        alert.accept()
                    else:
                        ## Not Vulnerable case
                        # print(f"{Fore.YELLOW}[→] Scanning with payload: {payload}")
                        print(f"{Fore.RED}[✗] Not Vulnerable: {Fore.CYAN}{payload_url} {Fore.RED}")

                except TimeoutException:
                    ## Not Vulnerable case (timeout)
                    # print(f"{Fore.YELLOW}[→] Scanning with payload: {payload}")
                    print(f"{Fore.RED}[✗] Not Vulnerable: {Fore.CYAN}{payload_url} {Fore.RED}")

            except UnexpectedAlertPresentException:
                pass
    finally:
        return_driver(driver)

def run_scan(urls, payload_file, timeout, scan_state):
    payloads = load_payloads(payload_file)
    vulnerable_urls = []
    total_scanned = [0]
    
    for _ in range(3):
        driver_pool.put(create_driver())
    
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = []
            for url in urls:
                for payload in payloads:
                    futures.append(
                        executor.submit(
                            check_vulnerability,
                            url,
                            payload,
                            vulnerable_urls,
                            total_scanned,
                            timeout,
                            scan_state
                        )
                    )
            
            for future in as_completed(futures):
                try:
                    future.result(timeout)
                except Exception as e:
                    print(Fore.RED + f"[!] Error during scan: {e}")
                    
    finally:
        while not driver_pool.empty():
            driver = driver_pool.get()
            driver.quit()
            
        return vulnerable_urls, total_scanned[0]

def print_scan_summary(total_found, total_scanned, start_time):
    summary = [
        "→ Scanning finished.",
        f"• Total found: {Fore.GREEN}{total_found}{Fore.YELLOW}",
        f"• Total scanned: {total_scanned}",
        f"• Time taken: {int(time.time() - start_time)} seconds"
    ]
    for line in summary:
        print(Fore.YELLOW + line)

    if total_found > 0:
        print(Fore.YELLOW + "\n[+] Vulnerable URLs:")
        for url in scan_state['vulnerable_urls']:
            print(Fore.GREEN + f"    {url}")


def save_html_report(scan_type, total_found, total_scanned, time_taken, vulnerable_urls):
    """
    Generate an HTML report for the scan results with the new styling.
    """
    # Group vulnerable URLs by domain
    domain_groups = {}
    for url in vulnerable_urls:
        domain = urlsplit(url).netloc
        if domain not in domain_groups:
            domain_groups[domain] = []
        domain_groups[domain].append(url)

    # Generate HTML for grouped vulnerable URLs
    grouped_urls_html = ""
    for domain, urls in domain_groups.items():
        grouped_urls_html += f"""
        <div class="domain-group">
            <div class="domain-title">{domain}</div>
            <ul class="vulnerable-list">
                {"".join(f'<li class="vulnerable-item"><a href="{url}" target="_blank">{url}</a></li>' for url in urls)}
            </ul>
        </div>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XSS Scan Report</title>
        <style>
            /* Global Styles */
            body {{
                font-family: 'Arial', sans-serif;
                margin: 0;
                padding: 0;
                background-color: #121212; /* Dark background */
                color: #fff;
                line-height: 1.5;
            }}

            h1, h2 {{
                text-align: center;
                font-size: 2.5rem;
                color: #fff;
                margin-bottom: 20px;
            }}

            /* Container */
            .container {{
                max-width: 1000px;
                margin: 2rem auto;
                padding: 1.5rem;
                background-color: #1e1e1e;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
            }}

            /* Summary Section */
            .summary {{
                margin-bottom: 2rem;
                border-bottom: 1px solid #333;
                padding-bottom: 1rem;
            }}

            .summary-item {{
                display: flex;
                justify-content: space-between;
                margin-bottom: 1rem;
                font-size: 1.1rem;
            }}

            .summary-label {{
                font-weight: bold;
                color: #ff4500; /* Red color for labels */
            }}

            .summary-value {{
                color: #ffcc00; /* Yellow for values */
            }}

            /* Stats Grid */
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 2rem;
                margin-bottom: 3rem;
            }}

            .stat-card {{
                background-color: #2a2a2a;
                padding: 2rem;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
                transition: transform 0.2s ease;
            }}

            .stat-card:hover {{
                transform: scale(1.05);
            }}

            .stat-value {{
                font-size: 2.5rem;
                color: #00bfae; /* Teal for values */
                font-weight: bold;
            }}

            .stat-label {{
                font-size: 1.1rem;
                color: #ff4500; /* Red for labels */
            }}

            /* Timeline Section */
            .timeline {{
                display: flex;
                flex-direction: column;
                gap: 1.5rem;
            }}

            .timeline-item {{
                padding: 1rem;
                background-color: #333;
                border-radius: 8px;
                box-shadow: 0 0 5px rgba(0, 0, 0, 0.3);
            }}

            .timeline-item h3 {{
                color: #ffcc00; /* Yellow for titles */
                margin: 0;
            }}

            .timeline-item p {{
                color: #bbb;
            }}

            /* Grouped URLs Section */
            .domain-group {{
                margin-top: 2rem;
                padding: 1rem;
                background-color: #333;
                border-radius: 8px;
            }}

            .domain-title {{
                font-size: 1.8rem;
                color: #00bfae; /* Teal color for domain titles */
                font-weight: bold;
                margin-bottom: 1rem;
            }}

            .vulnerable-list {{
                list-style-type: none;
                padding: 0;
            }}

            .vulnerable-item {{
                background-color: #444;
                color: #fff;
                padding: 1rem;
                margin-bottom: 1rem;
                border-radius: 8px;
                box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                transition: transform 0.2s ease;
            }}

            .vulnerable-item a {{
                word-wrap: break-word; /* Break long words if necessary */
                overflow-wrap: break-word; /* Modern alternative to word-wrap */
                white-space: normal; /* Allow text to wrap */
                display: inline-block; /* Ensure the link behaves like a block element */
                max-width: 100%; /* Ensure the link does not exceed its container's width */
            }}

            .vulnerable-item:hover {{
                transform: scale(1.03);
            }}

            /* Link Styling */
            a {{
                color: #ffcc00; /* Yellow for links */
                text-decoration: none;
            }}

            a:hover {{
                text-decoration: underline;
            }}

            /* Media Queries for Responsiveness */
            @media (max-width: 768px) {{
                .stats-grid {{
                    grid-template-columns: 1fr 1fr;
                }}

                h1 {{
                    font-size: 2rem;
                }}

                h2 {{
                    font-size: 1.8rem;
                }}
            }}
        </style>
    </head>
    <body>

        <div class="container">
            <h1>XSS Scan Report</h1>
            
            <!-- Summary -->
            <div class="summary">
                <div class="summary-item">
                    <span class="summary-label">Scan Type:</span>
                    <span class="summary-value">{scan_type}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Total Vulnerabilities Found:</span>
                    <span class="summary-value">{total_found}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Total URLs Scanned:</span>
                    <span class="summary-value">{total_scanned}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Time Taken:</span>
                    <span class="summary-value">{time_taken} seconds</span>
                </div>
            </div>

            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{total_found}</div>
                    <div class="stat-label">Vulnerabilities Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_scanned}</div>
                    <div class="stat-label">URLs Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{time_taken}s</div>
                    <div class="stat-label">Scan Duration</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_found / total_scanned:.2%}</div>
                    <div class="stat-label">Vulnerability Rate</div>
                </div>
            </div>

            <!-- Timeline -->
            <h2>Scan Timeline</h2>
            <div class="timeline">
                <div class="timeline-item">
                    <h3>Scan Initiated</h3>
                    <p>Scan started at {time.strftime('%H:%M:%S')}</p>
                </div>
                <div class="timeline-item">
                    <h3>Scanning Process</h3>
                    <p>{total_scanned} URLs analyzed</p>
                </div>
                <div class="timeline-item">
                    <h3>Vulnerabilities Detected</h3>
                    <p>{total_found} vulnerabilities found</p>
                </div>
                <div class="timeline-item">
                    <h3>Scan Completed</h3>
                    <p>Scan finished at {time.strftime('%H:%M:%S')}</p>
                </div>
            </div>

            <!-- Grouped Vulnerable URLs by Domain -->
            <h2>Vulnerable URLs Grouped by Domain</h2>
            {grouped_urls_html}
        </div>

    </body>
    </html>
    """
    return html_content


def save_results(vulnerable_urls, total_found, total_scanned, start_time):
    """
    Save the scan results to an HTML report.
    """
    action = input(Fore.CYAN + "[?] Do you want to generate an HTML report? (y/n): ").strip().lower()
    if action == 'y':
        html_content = save_html_report(
            "Cross-Site Scripting (XSS)",
            total_found,
            total_scanned,
            int(time.time() - start_time),
            vulnerable_urls
        )
        
        filename = input(Fore.CYAN + "[?] Enter the filename for the HTML report or press Enter to use 'xssreport.html': ").strip()
        if not filename:
            filename = 'xssreport.html'
            print(Fore.YELLOW + "[i] No filename provided. Using 'xssreport.html'.")

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(Fore.GREEN + f"[✓] HTML report saved as {filename}")
        except Exception as e:
            print(Fore.RED + f"[✗] Failed to save HTML report: {e}")
    else:
        print(Fore.RED + "\nExiting...")
        os._exit(0)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_file_path(prompt_text):
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def prompt_for_urls():
    while True:
        try:
            url_input = get_file_path("[?] Enter the path to the input file containing URLs (or press Enter to enter a single URL): ")
            if url_input:
                if not os.path.isfile(url_input):
                    raise FileNotFoundError(f"File not found: {url_input}")
                with open(url_input) as file:
                    urls = [line.strip() for line in file if line.strip()]
                return urls
            else:
                single_url = input(Fore.CYAN + "[?] Enter a single URL to scan: ").strip()
                if single_url:
                    return [single_url]
                else:
                    print(Fore.RED + "[!] You must provide either a file with URLs or a single URL.")
                    input(Fore.YELLOW + "\n[i] Press Enter to try again...")
                    clear_screen()
                    print(Fore.GREEN + "Welcome to the XSS Scanner!\n")
        except Exception as e:
            print(Fore.RED + f"[!] Error reading the input file. Exception: {str(e)}")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_screen()
            print(Fore.GREEN + "Welcome to the XSS Scanner!\n")

def prompt_for_valid_file_path(prompt_text):
    while True:
        file_path = get_file_path(prompt_text).strip()
        if not file_path:
            print(Fore.RED + "[!] You must provide a file containing the payloads.")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_screen()
            print(Fore.GREEN + "Welcome to the XSS Scanner!\n")
            continue
        if os.path.isfile(file_path):
            return file_path
        else:
            print(Fore.RED + "[!] Error reading the input file.")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_screen()
            print(Fore.GREEN + "Welcome to the XSS Scanner!\n")

def main():
    clear_screen()
    time.sleep(0.1)
    clear_screen()
    panel = Panel(r"""
_  __________  ____________   _  ___  __________
   | |/_/ __/ __/ / __/ ___/ _ | / |/ / |/ / __/ _  |
   >  <_\ \_\ \  _\ \/ /__/ __ |/    /    / _// , _/
  /_/|_/___/___/ /___/\___/_/ |_/_/|_/_/|_/___/_/|_|  
                """,
                    style="bold green",
                    border_style="blue",
                    expand=False
                )

    console.print(panel, "\n")
    print(Fore.GREEN + "Welcome to the XSS Testing Tool!\n")
    urls = prompt_for_urls()

    payload_file = prompt_for_valid_file_path("[?] Enter the path to the payloads file: ")
    
    try:
        timeout = float(input(Fore.CYAN + "Enter the timeout duration for each request (Press Enter for 0.5): "))
    except ValueError:
        timeout = 0.5

    clear_screen()
    print(f"{Fore.CYAN}[i] Starting scan...\n")

    scan_state['start_time'] = time.time()

    try:
        for url in urls:
            box_content = f" → Scanning URL: {url} "
            box_width = max(len(box_content) + 2, 40)
            print(Fore.YELLOW + "\n┌" + "─" * (box_width - 2) + "┐")
            print(Fore.YELLOW + f"│{box_content.center(box_width - 2)}│")
            print(Fore.YELLOW + "└" + "─" * (box_width - 2) + "┘\n")

            vulnerable_urls, scanned = run_scan([url], payload_file, timeout, scan_state)
            scan_state['vulnerable_urls'].extend(vulnerable_urls)
            scan_state['total_scanned'] += scanned

    except KeyboardInterrupt:
        # Handle Ctrl+C interruption
        signal_handler(None, None)

    print_scan_summary(scan_state['total_found'], scan_state['total_scanned'], scan_state['start_time'])
    save_results(scan_state['vulnerable_urls'], scan_state['total_found'], scan_state['total_scanned'], scan_state['start_time'])
    os._exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        signal_handler(None, None)