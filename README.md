# nosqlprobe

**Nosqlprobe** is a tool to pentest NoSQL databases, MongoDB and CouchDB, and identify NoSQL injection vulnerabilities in web applications.

---

## 🚀 Features

* **Database module** (`nosqlprobe db`):

  * Anon access checks for single hosts or CIDR scans.
  * Support for MongoDB and CouchDB.
  * Auto detection of MongoDB HTTP UI (port 28017) and CouchDB Fauxton (`_utils/`).
  * Enumeration of databases and collections.
  * Common MongoDB databases fallback for PyMongo wire-version mismatch failures.
  * Enumeration results in CSV format.
  * Controlled access through `--creds user:pass`.

* **Web module** (`nosqlprobe web`):

  * Automatic replay of Burp raw requests using `-r`.
  * Testing HTTP(S) using: URL (`-u`), form/JSON data (`-d`), custom headers (`-H`).
  * Automatic detection and exploitation of:

    * NoSQL **operator injection**: `$ne`, `$regex`, `$in`.
    * **Syntax injection**: single-quote, quote-plus, syntax fuzzy strings.
    * **Boolean-based** injections: `&&0&&`, `&&1&&`, `||1||`.
    * **Null-byte** termination.
    * **Time-based** JavaScript injection: `$where`, top-level `$where`.
  * **Authentication bypass** on `/login` using operator payloads.
  * Successful injections have their full HTTP requests, responses, and PoCs printed alongside the used payloads.

---

## 📦 Setup Guide

1. Clone the repository or download `nosqlprobe.py`

   ```bash
   git clone https://github.com/youruser/nosqlprobe.git
   cd nosqlprobe
   ```
2. Install dependencies

   ```bash
   pip3 install pymongo couchdb requests colorama validators
   ```

---

## 🔧 Execution

### Test The Database

```bash
# Testing for anonymous access on a single MongoDB host
python3 nosqlprobe.py db -t 127.0.0.1:27017 --check-anonymous

# Enumerate access with provided credentials
python3 nosqlprobe.py db -t 10.0.0.5:5984 --creds admin:secret --enum

# Scan a whole /24 subnet for CouchDB anonymous access
python3 nosqlprobe.py db -e couchdb -t 10.0.0.0/24 --anonymous

# Enumerate a CouchDB and output results to CSV
python3 nosqlprobe.py db -t 127.0.0.1:27017 -c root:pass --enum -o db_list.csv
```

### Test The Web

```bash
# Execute a Burp request replay file
python3 nosqlprobe.py web -r burp_request.txt

# Validate URL with form input for authentication
python3 nosqlprobe.py web -u http://example.com/login \
  -d "username=admin&password=admin" \
  -H "User-Agent: custom;Referer:http://example.com"

# Test JSON API endpoints
python3 nosqlprobe.py web -u https://api.test.local/lookup \
  -d '{"user":"alice","id":1}' \
  -H "Content-Type: application/json"
```

---

## 📝 Additional Command Options

### `db` Subcommand Options

| Flag                      | Description                              |
| ------------------------- | ---------------------------------------- |
| `-e, --engine`            | `mongodb` (default) or `couchdb`         |
| `-t, --target` **(req.)** | Host\:port or CIDR block                 |
| `-a, --anonymous`         | Check for anonymous access               |
| `--check-anonymous`       | Same as `-a`                             |
| `-n, --enum`              | Enumerate databases, collections & users |
| `-c, --creds`             | Credentials in `user:pass` format        |
| `-o, --output`            | Write enumeration output to CSV file     |

### Web Subcommand Options

| Flag            | Description                                       |
| --------------- | ------------------------------------------------- |
| `-u, --url`     | Target URL (must include `http://` or `https://`) |
| `-d, --data`    | POST data: URL‐encoded form or raw JSON           |
| `-H, --headers` | Custom headers, semicolon-separated (`Key:Val;…`) |
| `-r, --request` | Path to Burp raw request file to replay           |

---

### 🛡️ Examples

**Bypass MongoDB auth** via `$ne` / `$regex` operators on a login form:

```bash
python3 nosqlprobe.py web -u https://app.test/login \
  -d '{"username":"wiener","password":"peter"}'
```

The script will automatically test payloads like:

```json
{"username":{"$ne":""},"password":"peter"}
```

and report if one succeeds.

**NoSQL injection PoC** in a GET endpoint:

```bash
python3 nosqlprobe.py web -r burp_insecure_get.txt
```

Outputs the request/response showing how `?email[$ne]=foo@bar` returns all records.

---

## 🛠️ Contributing

Fork the repo
Open a Pull Request

---

## 📄 License

This work is published under the MIT License.
Feel free to incorporate it into your pentesting workflows!
