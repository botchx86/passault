# passault
A dictionary attack tool for web applications

## Usage
```
python passault.py [-h] [-t THREADS] [-w WAIT] [--timeout TIMEOUT]
                   [-f FAIL_STRING] [-s SUCCESS_STRING]
                   [--user-field USER_FIELD] [--pass-field PASS_FIELD]
                   [-o OUTPUT]
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
| `-s`, `--success-string` | — | Response text indicating a successful login (overrides `--fail-string`) |
| `--user-field` | `username` | Form field name for the username |
| `--pass-field` | `password` | Form field name for the password |
| `-o`, `--output` | `successful_logins.txt` | File to write successful credentials to |

## Example
```
python passault.py -t 8 -w 0.5 -f "Invalid credentials" http://example.com/login usernames.txt passwords.txt
```
