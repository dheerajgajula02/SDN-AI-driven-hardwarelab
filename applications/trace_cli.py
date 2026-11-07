#!/usr/bin/env python3
"""Lab 9 Objective 5 (A5): command-line SDN trace.

Asks the controller's REST API (GET /lab9/trace) and prints the path:
every switch's DPID with its ingress and egress port, plus the router hop.

Usage (any machine that can reach the controller; Python 3, standard library):
  python3 trace_cli.py pc1 srv1
  python3 trace_cli.py pc1 8.8.8.8
  python3 trace_cli.py pc2 srv1 --details         also show each matched rule
  python3 trace_cli.py pc1 srv1 --json            raw JSON
  python3 trace_cli.py pc1 srv1 --controller 10.224.78.132:8080

Exit code: 0 = destination reached, 1 = trace stopped early, 2 = error.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
NSOT = os.environ.get('LAB9_NSOT', os.path.join(HERE, '..', 'part_a', 'nsot.json'))


# ===========================================================================
# Function 1: where is the controller?
# ===========================================================================

def default_controller():
    """The controller's IP and REST port from the NSOT, e.g. '10.224.78.132:8080'."""
    try:
        with open(NSOT) as f:
            c = json.load(f)['controller']
        return '%s:%s' % (c['ip'], c['rest_port'])
    except (OSError, KeyError, ValueError):
        return '127.0.0.1:8080'


# ===========================================================================
# Function 2: ask the controller for the trace
# ===========================================================================

def get_trace(controller, src, dst):
    """GET /lab9/trace?src=..&dst=.. ; returns (status, json body)."""
    url = 'http://%s/lab9/trace?%s' % (controller, urllib.parse.urlencode({'src': src, 'dst': dst}))
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return r.status, json.loads(r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:          # 400: bad input, with a message
        return e.code, json.loads(e.read().decode('utf-8') or '{}')


# ===========================================================================
# Function 3: print it
# ===========================================================================

def main():
    p = argparse.ArgumentParser(description='Trace the path between two hosts through the OpenFlow network.')
    p.add_argument('src', help='source host, e.g. pc1')
    p.add_argument('dst', help='destination host, host IP, inet, or an Internet IP')
    p.add_argument('--controller', default=default_controller(), help='controller IP:port (default from the NSOT)')
    p.add_argument('--details', action='store_true', help='also print the rule matched at each switch')
    p.add_argument('--json', action='store_true', help='print the raw JSON')
    args = p.parse_args()

    try:
        status, res = get_trace(args.controller, args.src, args.dst)
    except Exception as e:
        print('cannot reach the controller at %s: %s' % (args.controller, e))
        return 2
    if status != 200:
        print('error: %s' % res.get('error', 'HTTP %s' % status))
        return 2
    if args.json:
        print(json.dumps(res, indent=2))
        return 0 if res['complete'] else 1

    for line in res['lines']:
        print(line)
    if args.details:
        print('\nrules matched:')
        for h in res['hops']:
            if h['kind'] == 'switch':
                n = h['rule_packets']
                used = '' if n is None else '   (used by %d packet%s so far)' % (n, '' if n == 1 else 's')
                print('  %-8s %s%s' % (h['name'], h['rule'] or '(none)', used))
            else:
                print('  %-8s %s' % (h['name'], h['decision']))
    return 0 if res['complete'] else 1


if __name__ == '__main__':
    sys.exit(main())
