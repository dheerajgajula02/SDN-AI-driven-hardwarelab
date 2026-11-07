#!/usr/bin/env python3
"""External JSON Verdict Service + Blocked-Page Web Server for Lab 9 (A3).

Why this exists (Objective 3):
  "The good/bad decision must come from an external check: your team must find
   or build a way to send a URL to a site that returns a JSON verdict (good or
   bad), work out how to query it from the controller, and justify your choice.
   The lookup must be initiated from the controller, not from the end hosts."

What this service does:
  1. JSON Verdict API (runs on the controller VM, default port 8053):
     - GET  /check?domain=<name>
       Returns JSON:
         {"domain": "malware.lab9.lan", "verdict": "bad",
          "reason": "exact match in blacklist", "source": "lab9-verdict-service"}
     - GET  /blacklist
       Returns the current list of blocked domains and suffixes.
     - POST /blacklist
       Body: {"domain": "bad.com", "action": "add" | "remove"}
       Updates the blacklist live (saved to blacklist.json).

  2. Optional Upstream Threat-Intel Lookup (Cloudflare 1.1.1.3 Family/Malware DoH):
     - If `UPSTREAM_DOH=1` is set and the controller has Internet access, unknown
       domains not in the local list are also checked against Cloudflare's
       malware-blocking DNS-over-HTTPS JSON endpoint.

  3. Blocked Landing Page (can also run on srv1 port 80 inside Mininet):
     - GET / (for any Host header)
       Returns an HTML "Access Blocked by SDN Controller" page showing which
       domain was requested, so `curl http://bad.lab9.lan` or a browser displays
       the blocked page when the controller returns its modified DNS reply.
"""

import json
import os
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
BLACKLIST_FILE = os.path.join(HERE, 'blacklist.json')

DEFAULT_BLACKLIST = [
    'bad.lab9.lan',
    'malware.lab9.lan',
    'phishing.lab9.lan',
    'evil.com',
    'malware.testcategory.com',
]

# Real external JSON Threat-Intelligence endpoint (Cloudflare 1.1.1.3 Malware Filter).
# Returns application/dns-json; blocked malware/phishing domains return Answer data
# "0.0.0.0" and Comment ["EDE(16): Censored"].
CLOUDFLARE_SECURITY_DOH = 'https://security.cloudflare-dns.com/dns-query'


def load_blacklist():
    """Load the domain blacklist from disk, creating the default file if missing."""
    if not os.path.exists(BLACKLIST_FILE):
        save_blacklist(DEFAULT_BLACKLIST)
    with open(BLACKLIST_FILE) as f:
        data = json.load(f)
    return [d.strip().lower().rstrip('.') for d in data.get('blocked_domains', []) if d.strip()]


def save_blacklist(domains):
    """Save the sorted unique domain blacklist to blacklist.json."""
    clean = sorted(set(d.strip().lower().rstrip('.') for d in domains if d.strip()))
    with open(BLACKLIST_FILE, 'w') as f:
        json.dump({'blocked_domains': clean}, f, indent=2)
    return clean


def evaluate_domain(domain):
    """Decide whether `domain` is 'good' or 'bad' and explain why.

    Matches both exact domain names (e.g. 'evil.com') and subdomains of a
    blocked domain (e.g. 'login.evil.com' matches 'evil.com').
    """
    q = (domain or '').strip().lower().rstrip('.')
    if not q:
        return {'domain': q, 'verdict': 'bad', 'reason': 'empty domain',
                'source': 'lab9-verdict-service'}

    blocked = load_blacklist()
    for bad in blocked:
        if q == bad or q.endswith('.' + bad):
            return {
                'domain': q,
                'verdict': 'bad',
                'reason': 'matched custom blacklist (%s)' % bad,
                'source': 'lab9-custom-blacklist',
            }

    # Local lab test domains (.lab9.lan) skip external Internet lookup
    if q.endswith('.lab9.lan'):
        return {
            'domain': q,
            'verdict': 'good',
            'reason': 'local lab domain not in blacklist',
            'source': 'lab9-verdict-service',
        }

    # Query Cloudflare 1.1.1.3 Malware/Phishing JSON API over HTTPS
    try:
        url = '%s?name=%s&type=A' % (CLOUDFLARE_SECURITY_DOH, urllib.parse.quote(q))
        req = urllib.request.Request(url, headers={'Accept': 'application/dns-json'})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            cf = json.loads(resp.read().decode('utf-8'))
        answers = cf.get('Answer') or []
        comments = ' '.join(cf.get('Comment') or [])
        for ans in answers:
            if ans.get('data') in ('0.0.0.0', '::'):
                return {
                    'domain': q,
                    'verdict': 'bad',
                    'reason': 'Cloudflare 1.1.1.3 Malware Filter (%s)' % (comments or '0.0.0.0 sinkhole'),
                    'source': 'cloudflare-1.1.1.3-json',
                }
        return {
            'domain': q,
            'verdict': 'good',
            'reason': 'clean in Cloudflare 1.1.1.3 + custom blacklist',
            'source': 'cloudflare-1.1.1.3-json',
        }
    except Exception as e:
        return {
            'domain': q,
            'verdict': 'good',
            'reason': 'not in custom blacklist (upstream offline: %s)' % e,
            'source': 'lab9-verdict-service',
        }


BLOCKED_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Site Blocked - SDN DNS Filter</title>
  <style>
    body {{ font-family: sans-serif; background: #1a1d24; color: #f0f4f8;
           display: flex; align-items: center; justify-content: center; height: 90vh; margin: 0; }}
    .card {{ background: #252a34; border: 2px solid #e05252; border-radius: 8px;
            padding: 28px 36px; max-width: 520px; text-align: center; }}
    h1 {{ color: #ff6b6b; margin-top: 0; }}
    code {{ background: #14171d; padding: 3px 8px; border-radius: 4px; color: #ffd166; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>ACCESS BLOCKED</h1>
    <p>The SDN Controller DNS Blacklist Application blocked access to:</p>
    <p><code>{host}</code></p>
    <p>Verdict: <strong>BAD</strong> (redirected via modified OpenFlow DNS reply).</p>
  </div>
</body>
</html>
"""


class VerdictHandler(BaseHTTPRequestHandler):
    def _send_json(self, code, payload):
        body = json.dumps(payload, indent=2).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # 1. External JSON verdict lookup: GET /check?domain=example.com
        if parsed.path == '/check':
            domain = params.get('domain', params.get('url', ['']))[0]
            self._send_json(200, evaluate_domain(domain))
            return

        # 2. Read current blacklist: GET /blacklist
        if parsed.path == '/blacklist':
            self._send_json(200, {'blocked_domains': load_blacklist()})
            return

        # 3. Otherwise serve the HTML "ACCESS BLOCKED" landing page
        host = self.headers.get('Host', 'unknown-domain')
        body = BLOCKED_HTML.format(host=host).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != '/blacklist':
            self._send_json(404, {'error': 'not found'})
            return
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length).decode('utf-8') if length else '{}'
        data = json.loads(raw or '{}')
        domain = (data.get('domain') or '').strip().lower().rstrip('.')
        action = (data.get('action') or 'add').strip().lower()
        current = load_blacklist()
        if action == 'add' and domain:
            current.append(domain)
        elif action == 'remove' and domain:
            current = [d for d in current if d != domain]
        updated = save_blacklist(current)
        self._send_json(200, {'blocked_domains': updated})

    def log_message(self, fmt, *args):
        # Keep stdout clean unless verbose logging is wanted.
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8053
    load_blacklist()
    server = HTTPServer(('0.0.0.0', port), VerdictHandler)
    print('DNS Verdict & Blocked-Page server listening on 0.0.0.0:%d' % port)
    sys.stdout.flush()
    server.serve_forever()


if __name__ == '__main__':
    main()
