#!/usr/bin/env python3
"""A6: every Part A application works through the controller's REST API.

Calls every endpoint the apps expose on Ryu's port 8080, checks the answers,
and leaves everything as it found it (test domain removed, apps re-enabled).

Run on the laptop (no passwords needed, REST only):
  python3 lab9/applications/tests/test_rest_api.py
"""

import json
import sys
import urllib.error
import urllib.request

API = 'http://100.110.3.67:8080'
results = []


def check(name, passed, detail=''):
    results.append((name, bool(passed)))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('  [%s]' % detail) if detail else ''))


def call(method, path, body=None):
    """One REST call; returns (status, parsed JSON or text)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw, status, ctype = r.read().decode(), r.status, r.headers.get('Content-Type', '')
    except urllib.error.HTTPError as e:
        raw, status, ctype = e.read().decode(), e.code, e.headers.get('Content-Type', '')
    return status, (json.loads(raw) if 'json' in ctype else raw)


def main():
    # ---- the console and the NSOT summary -------------------------------------
    for path in ('/lab9/ui', '/lab9/dns/ui', '/lab9/dhcp/ui'):
        s, body = call('GET', path)
        check('GET %s serves the console' % path, s == 200 and 'Lab 9 controller' in body)
    # Every JSON endpoint must say it is JSON (clients such as the Part B AI
    # layer rely on it; it was missing before the json_response() fix).
    for path in ('/lab9/nsot/summary', '/lab9/dns/status', '/lab9/dhcp/status',
                 '/lab9/dns/check?domain=example.com', '/lab9/trace?src=pc1&dst=srv1', '/lab9/trace'):
        try:
            with urllib.request.urlopen(API + path, timeout=15) as r:
                ctype = r.headers.get('Content-Type', '')
        except urllib.error.HTTPError as e:
            ctype = e.headers.get('Content-Type', '')
        check('%s declares Content-Type: application/json' % path.split('?')[0], 'application/json' in ctype,
              ctype or 'no Content-Type header')

    s, nsot = call('GET', '/lab9/nsot/summary')
    check('GET /lab9/nsot/summary: 6 switches + topology', s == 200 and len(nsot['switches']) == 6
          and nsot['topology']['router']['name'] == 'r1')

    # ---- OpenFlow view (ofctl_rest) agrees with the NSOT ----------------------
    s, dpids = call('GET', '/stats/switches')
    check('GET /stats/switches: the 6 NSOT switches are connected',
          s == 200 and sorted(dpids) == sorted(int(d) for d in nsot['switches']), dpids)

    # ---- A3 DNS filter ----------------------------------------------------------
    s, st = call('GET', '/lab9/dns/status')
    check('GET /lab9/dns/status', s == 200 and {'enabled', 'stats', 'blocked_domains', 'recent_queries'} <= set(st))
    s, v = call('GET', '/lab9/dns/check?domain=evil.com')
    check('GET /lab9/dns/check evil.com -> bad', s == 200 and v['verdict'] == 'bad', v.get('reason'))
    s, v = call('GET', '/lab9/dns/check?domain=example.com')
    check('GET /lab9/dns/check example.com -> good', s == 200 and v['verdict'] == 'good', v.get('reason'))
    test_dom = 'rest-api-test.lab9.lan'
    s, r = call('POST', '/lab9/dns/blacklist', {'domain': test_dom, 'action': 'add'})
    added = s == 200 and test_dom in r['blocked_domains']
    s, v = call('GET', '/lab9/dns/check?domain=' + test_dom)
    check('POST /lab9/dns/blacklist add -> listed and now "bad"', added and v['verdict'] == 'bad')
    s, r = call('POST', '/lab9/dns/blacklist', {'domain': test_dom, 'action': 'remove'})
    check('POST /lab9/dns/blacklist remove -> gone again', s == 200 and test_dom not in r['blocked_domains'])
    s, r = call('POST', '/lab9/dns/config', {'enabled': False})
    off = s == 200 and r['enabled'] is False
    s, r = call('POST', '/lab9/dns/config', {'enabled': True})
    check('POST /lab9/dns/config turns filtering off and back on', off and r['enabled'] is True)

    # ---- A4 DHCP to router -------------------------------------------------------
    s, st = call('GET', '/lab9/dhcp/status')
    check('GET /lab9/dhcp/status: router target from the NSOT',
          s == 200 and st['router_mac'] == '00:00:00:00:01:01' and st['router_port'] == 1, st.get('stats'))
    s, r = call('POST', '/lab9/dhcp/config', {'enabled': False})
    off = s == 200 and r['enabled'] is False
    s, r = call('POST', '/lab9/dhcp/config', {'enabled': True})
    check('POST /lab9/dhcp/config turns unicast forcing off and back on', off and r['enabled'] is True)

    # ---- A5 trace ------------------------------------------------------------------
    s, t = call('GET', '/lab9/trace?src=pc1&dst=srv1')
    check('GET /lab9/trace pc1 -> srv1 answers with hops and printed lines',
          s == 200 and 'lines' in t and t['hops'] and t['hops'][0]['name'] == 'arista1',
          'complete' if t.get('complete') else t.get('stopped'))
    s, t = call('GET', '/lab9/trace')
    check('GET /lab9/trace without src/dst -> 400 with a hint', s == 400 and 'src' in t.get('error', ''))

    # ---- everything left as found ----------------------------------------------------
    s, d = call('GET', '/lab9/dns/status')
    s2, h = call('GET', '/lab9/dhcp/status')
    check('left as found: filtering on, forcing on, test domain gone',
          d['enabled'] and h['enabled'] and test_dom not in d['blocked_domains'])

    passed = sum(1 for _, ok in results if ok)
    print('\n%d/%d checks passed' % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
