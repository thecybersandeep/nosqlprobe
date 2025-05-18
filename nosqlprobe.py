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
from pymongo.errors import ConfigurationError, ServerSelectionTimeoutError
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
    db.add_argument('-e', '--engine', choices=['mongodb','couchdb'],
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

    web = sub.add_parser('web', help='NoSQL injection tests')
    web.add_argument('-u', '--url', help='Target URL (http:// or https://)')
    web.add_argument('-d', '--data', help='POST data (form or raw JSON)')
    web.add_argument('-H', '--headers', help='Custom headers; semicolon-separated')
    web.add_argument('-r', '--request', help='Burp raw request file to replay')

    return p.parse_args()


def test_db_access(host, port, engine, creds=None):
    if engine == 'mongodb':
        try:
            opts = {'host': host, 'port': port,
                    'serverSelectionTimeoutMS': 5000,
                    'connectTimeoutMS': 5000}
            if creds:
                opts.update(username=creds[0], password=creds[1], authSource='admin')
            client = MongoClient(**opts)
            client.admin.command('ping')
            version = client.server_info().get('version','unknown')
            return True, version, None

        except ConfigurationError as e:
            msg = str(e)
            if 'wire version' in msg:
                # server is old but reachable
                return True, '<4.0 (wire mismatch)', None
            return False, None, msg

        except ServerSelectionTimeoutError as e:
            return False, None, f'Timeout: {e}'

        except mongo_errors.OperationFailure as e:
            return False, None, str(e)

        except Exception as e:
            return False, None, str(e)

    else:
        try:
            base = f'http://{host}:{port}/'
            if creds:
                base = f'http://{creds[0]}:{creds[1]}@{host}:{port}/'
            s = couchdb.Server(base)
            return True, s.version(), None
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
    """
    Connect and list databases, with full fallback on wire-version mismatches.
    """
    # 1) Attempt initial connection
    try:
        opts = {'host': host, 'port': port, 'serverSelectionTimeoutMS': 5000}
        if creds:
            opts.update(username=creds[0], password=creds[1], authSource='admin')
        client = MongoClient(**opts)
    except Exception as e:
        msg = str(e)
        if 'wire version' in msg:
            print(Fore.YELLOW +
                  '[!] ConfigurationError on connect (wire mismatch); '
                  'falling back to common DB list')
            client = None
            dbs = COMMON_MONGO_DBS.copy()
        else:
            print(Fore.RED + f'[!] MongoDB enumeration failed: {e}')
            return
    else:
        # 2) Try listing databases
        try:
            dbs = client.list_database_names()
        except Exception as e:
            msg = str(e)
            if 'wire version' in msg or isinstance(e, mongo_errors.OperationFailure):
                print(Fore.YELLOW +
                      '[!] listDatabases refused; using common DB list')
                dbs = COMMON_MONGO_DBS.copy()
            else:
                print(Fore.RED + f'[!] listDatabases error: {e}')
                return

    # 3) Enumerate each database’s collections
    for db in dbs:
        print(Fore.CYAN + f'Database: {db}')
        cols = []
        if client:
            try:
                cols = client[db].list_collection_names()
            except Exception as e:
                print(Fore.YELLOW +
                      '  [-] list_collection_names failed; skipping')
        for col in cols:
            print('  -', col)
            if csvw:
                csvw.writerow([db, col])


def enumerate_couchdb(host, port, creds, csvw=None):
    try:
        base = f'http://{host}:{port}/'
        if creds:
            base = f'http://{creds[0]}:{creds[1]}@{host}:{port}/'
        s = couchdb.Server(base)
        dbs = list(s)
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
        uri = f'https://{host}{uri}'
    return method.upper(), uri, hdrs, body


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

    # CIDR scanning for anonymous
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

    # anonymous check
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

    # enumeration
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
    # [ your existing web‐testing code goes here unchanged ]
    raise NotImplementedError('Web module not included in this snippet')


def main():
    args = parse_args()
    if args.command == 'web':
        handle_web(args)
    else:
        handle_db(args)


if __name__ == '__main__':
    main()
