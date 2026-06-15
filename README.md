# passault
A dictionary attack tool for web applications

## Usage
```
python passault.py [-h] [-t THREADS] [-w WAIT] [--timeout TIMEOUT]
                   [-f FAIL_STRING] [-s SUCCESS_STRING] [-c STATUS_CODE]
                   [--user-field USER_FIELD] [--pass-field PASS_FIELD] [--json]
                   [-x] [-o OUTPUT] [-A USER_AGENT] [-H KEY:VALUE] [-p PROXY]
                   [--https-only] [-v]
                   url username_file password_file
```

## Arguments

| Argument | Default | Description |
|---|---|---|
| `url` | — | Target login URL |
| `username_file` | — | File containing usernames (one per line) |
| `password_file` | — | File containing passwords (one per line) |
| `-t`, `--threads` | `4` | Number of concurrent threads |
| `-w`, `--wait` | `0` | Seconds to wait between attempts per thread |
| `--timeout` | `10` | Request timeout in seconds |
| `-f`, `--fail-string` | `Login failed` | Response text indicating a failed login |
| `-s`, `--success-string` | — | Response text indicating success (overrides `--fail-string`) |
| `-c`, `--status-code` | — | HTTP status code indicating success (overrides string checks) |
| `--user-field` | `username` | Form field name for the username |
| `--pass-field` | `password` | Form field name for the password |
| `--json` | — | Send credentials as a JSON body instead of form-encoded |
| `-x`, `--stop-on-success` | — | Stop all threads as soon as one valid credential is found |
| `-o`, `--output` | `successful_logins.txt` | File to write successful credentials to |
| `-A`, `--user-agent` | — | Custom User-Agent header |
| `-H`, `--header` | — | Extra HTTP header, repeatable (e.g. `-H 'X-CSRF-Token: abc'`) |
| `-p`, `--proxy` | — | Proxy URL (e.g. `http://127.0.0.1:8080`) |
| `--https-only` | — | Abort if the target URL is not HTTPS |
| `-v`, `--verbose` | — | Print every attempt instead of a rolling progress counter |

## Examples

Basic usage:
```
python passault.py http://example.com/login usernames.txt passwords.txt
```

Custom failure string, 8 threads, 0.5s delay between attempts:
```
python passault.py -t 8 -w 0.5 -f "Invalid credentials" http://example.com/login usernames.txt passwords.txt
```

Match on HTTP 302 redirect as success indicator, stop on first hit, route through Burp:
```
python passault.py -c 302 -x -p http://127.0.0.1:8080 https://example.com/login usernames.txt passwords.txt
```

JSON body, custom field names, extra header:
```
python passault.py --json --user-field email --pass-field pass -H "X-CSRF-Token: abc123" https://example.com/api/login usernames.txt passwords.txt
```
