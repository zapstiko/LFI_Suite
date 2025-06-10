import asyncio
import aiohttp
import argparse
import random
import re
import subprocess
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import init, Fore, Style

init(autoreset=True)

ascii_art = f"""{Fore.LIGHTCYAN_EX}
🎯 LFI_Suite
⚡ Created by zapstiko
🐍 Fast. Focused. Functional.
{Style.RESET_ALL}
"""

DEFAULT_BATCH_SIZE = 150
DEFAULT_BATCH_DELAY = 1.5
DEFAULT_TIMEOUT = 1.8
DEFAULT_RETRY_COUNT = 1
RESPONSE_SIZE_LIMIT = 1024 * 10  # 10 KB

successful_attempts = 0
failed_attempts = 0
timeout_attempts = 0
total_processed = 0

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.6167.160 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
]

def extract_lfi_parameters(file_path):
    print(f"{Fore.YELLOW}[+] Extracting LFI parameters from: {file_path}")
    try:
        result = subprocess.run(['gf', 'lfi'], input=open(file_path, 'rb').read(), stdout=subprocess.PIPE)
        raw_urls = result.stdout.decode().splitlines()
    except Exception as e:
        print(f"{Fore.RED}[!] gf lfi failed: {e}")
        return []

    urls = []
    for url in raw_urls:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for key in query:
            new_query = query.copy()
            new_query[key] = ['FUZZ']
            fuzzed_query = urlencode(new_query, doseq=True)
            fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fuzzed_query, parsed.fragment))
            urls.append((fuzzed_url, key))  # store URL and parameter
    return urls

def match_vulnerability(content, patterns):
    for pattern in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

async def send_request(session, method, url, param, payload, matcher_patterns, timeout, retry_count):
    global successful_attempts, failed_attempts, timeout_attempts, total_processed

    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if param not in query:
        return

    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    full_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

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
                print(f"{Fore.GREEN}[VULNERABLE] Param: {param} => {full_url}")
                with open("output.txt", "a") as f:
                    f.write(f"{param} => {full_url}\n")
                break
            else:
                failed_attempts += 1
                break
        except asyncio.TimeoutError:
            timeout_attempts += 1
        except Exception:
            failed_attempts += 1
            break

async def process_batch(session, method, targets, payloads, matcher_patterns, batch_size, batch_delay, timeout, retry_count):
    batch = []
    for fuzzed_url, param in targets:
        for payload in payloads:
            batch.append(send_request(session, method, fuzzed_url, param, payload, matcher_patterns, timeout, retry_count))
            if len(batch) >= batch_size:
                await asyncio.gather(*batch)
                print(f"{Fore.BLUE}Batch done. Sleeping {batch_delay}s...\n")
                batch = []
                await asyncio.sleep(batch_delay)
    if batch:
        await asyncio.gather(*batch)

async def main(args):
    print(ascii_art)

    # Extract LFI-prone parameters from raw URLs
    fuzzed_targets = extract_lfi_parameters(args.domains)
    if not fuzzed_targets:
        print(f"{Fore.RED}[!] No LFI parameters found.")
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
        await process_batch(session, method, fuzzed_targets, payloads, matcher_patterns, args.batch_size, args.batch_delay, args.timeout, args.retry_count)
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
    parser.add_argument("-p", "--payloads", required=True, help="Path to file with payloads")
    parser.add_argument("-m", "--matchers", default="root:x|/bin/bash|No such file|open_basedir|include_path|Permission denied|Warning: include|on line [0-9]+|failed to open stream|500 Internal Server Error", help="Custom matcher patterns separated by '|'")
    parser.add_argument("--post", action="store_true", help="Use POST instead of GET")
    parser.add_argument("--proxy", help="Proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-b", "--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("-bd", "--batch-delay", type=float, default=DEFAULT_BATCH_DELAY)
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("-r", "--retry-count", type=int, default=DEFAULT_RETRY_COUNT)
    args = parser.parse_args()

    asyncio.run(main(args))
