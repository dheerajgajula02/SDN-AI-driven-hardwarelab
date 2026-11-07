#!/usr/bin/env python3
"""Tests the A5 SDN trace on the live network, and proves two things about
the flows it reads:

  1. Traffic INSTALLS rules: after the first ping, the switches on the path
     hold learned rules (cookie 0x10), and the trace follows them.
  2. After that, traffic does NOT go to the controller: a second round of
     pings leaves every table-miss counter ("send to controller") unchanged
     while the learned rules' counters go up.

It also proves the trace itself is read-only (no rule added, nothing sent to
the controller), and covers same VLAN, routed, OVS servers, the Internet, a
cut cable, missing rules, bad input and the CLI.

Needs: network (lab9_net.py) + Ryu running. Run on the laptop:
  SSHPASS=<mininet password> python3 lab9/applications/tests/test_trace.py
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from mininet_host import on_host, on_root

API = 'http://100.110.3.67:8080'
SWITCHES = ['cisco1', 'arista1', 'arista2', 'hp1', 'ovs1', 'ovs2']
HERE = os.path.dirname(os.path.abspath(__file__))
results = []


def check(name, passed, detail=''):
    results.append((name, bool(passed)))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('\n        ' + str(detail)) if detail else ''))
    sys.stdout.flush()


# ===========================================================================
# Helpers: the trace REST API, and the switches' own counters
# ===========================================================================

def trace(src, dst):
    """GET /lab9/trace; returns (HTTP status, JSON)."""
    url = '%s/lab9/trace?%s' % (API, urllib.parse.urlencode({'src': src, 'dst': dst}))
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


def hops(res):
    """'arista1 2>1, cisco1 2>1, r1, ...' for comparing paths."""
    return ', '.join('%s %s>%s' % (h['name'], h['in_port'], h['out_port']) if h['kind'] == 'switch'
                     else h['name'] for h in res['hops'])


def counters():
    """Read every switch's rules straight from OVS (not through the trace).

    Waits 2 s first: OVS forwards in its fast path and copies the packet
    counts back onto the OpenFlow rules only about once a second. Reading
    right after traffic undercounts (seen in run 1: 38 instead of 40), and
    could also hide a late packet that went to the controller.

    Returns"""
    time.sleep(2)
    return _read_counters()


def _read_counters():
    """Returns
    {switch: {'miss': table-miss packets, 'rules': number of rules,
              'learned': {(in_port, dl_dst): packets}}}"""
    out = on_root('for b in %s; do echo "== $b"; ovs-ofctl -O OpenFlow13 dump-flows $b; done'
                  % ' '.join(SWITCHES))
    snap = {}
    for block in out.split('== ')[1:]:
        name, _, body = block.partition('\n')
        s = {'miss': 0, 'rules': 0, 'learned': {}}
        for l in body.splitlines():
            n = re.search(r'n_packets=(\d+)', l)
            if not n:
                continue
            s['rules'] += 1
            if 'priority=0 ' in l and 'CONTROLLER' in l:
                s['miss'] = int(n.group(1))
            if 'cookie=0x10' in l:
                src = re.search(r'dl_src=([0-9a-f:]+)', l)
                key = (re.search(r'in_port=(\d+)', l).group(1), src.group(1) if src else '',
                       re.search(r'dl_dst=([0-9a-f:]+)', l).group(1))
                s['learned'][key] = int(n.group(1))
        snap[name.strip()] = s
    return snap


def wipe_learned():
    """Delete every learned rule (cookie 0x10) on every switch, so the next
    packet really is a "first" packet. Protected rules stay."""
    on_root(' ; '.join('ovs-ofctl -O OpenFlow13 del-flows %s "cookie=0x10/-1"' % b for b in SWITCHES))


def ping(src, dst_ip, count):
    out = on_host(src, 'ping -c %d -i 0.2 -W 1 %s' % (count, dst_ip))
    m = re.search(r'(\d+) received', out)
    return int(m.group(1)) if m else 0


# ===========================================================================
# The tests
# ===========================================================================

def main():
    # ---- T1: bad input is refused with a clear message ---------------------
    for src, dst, why in (('pc9', 'srv1', 'unknown host'), ('pc1', 'pc1', 'same host'),
                          ('pc1', '10.10.20.99', 'IP inside a VLAN that is no host')):
        status, res = trace(src, dst)
        check('T1 refuses %s (%s -> %s): HTTP 400 with a reason' % (why, src, dst),
              status == 400 and res.get('error'), res.get('error'))

    # ---- T2: no learned rules -> the trace stops and says why ---------------
    wipe_learned()
    time.sleep(1)
    status, res = trace('pc1', 'srv1')
    check('T2 with no learned rules, the trace stops at the first switch and says why',
          status == 200 and not res['complete'] and res['hops'][0]['name'] == 'arista1'
          and 'no rule yet' in (res['stopped'] or ''), res.get('stopped'))

    # ---- T3: the trace is read-only -----------------------------------------
    before = counters()
    for _ in range(5):
        trace('pc1', 'srv1')
        trace('vm1', 'vm2')
    after = counters()
    added = {s: after[s]['rules'] - before[s]['rules'] for s in SWITCHES if after[s]['rules'] != before[s]['rules']}
    to_ctl = {s: after[s]['miss'] - before[s]['miss'] for s in SWITCHES if after[s]['miss'] != before[s]['miss']}
    check('T3 10 traces add no rule on any switch', not added, added or 'rule counts unchanged on all 6')
    check('T3 10 traces send nothing to the controller (table-miss counters unchanged)', not to_ctl,
          to_ctl or 'table-miss counters unchanged on all 6')

    # ---- T4: the first pings INSTALL rules on the path ----------------------
    before = counters()
    got = ping('pc1', '10.10.20.21', 5)
    after = counters()
    path = ['arista1', 'cisco1', 'hp1']
    new_rules = {s: len(after[s]['learned']) for s in path}
    first_to_ctl = {s: after[s]['miss'] - before[s]['miss'] for s in path}
    check('T4 pc1 -> srv1 ping works (%d/5)' % got, got == 5)
    check('T4 the first packets went to the controller (table-miss counters rose on the path)',
          all(v > 0 for v in first_to_ctl.values()), first_to_ctl)
    check('T4 the controller installed learned rules on every switch of the path',
          all(v > 0 for v in new_rules.values()), new_rules)
    status, res = trace('pc1', 'srv1')
    want = 'arista1 2>1, cisco1 2>1, r1, cisco1 1>4, hp1 1>2'
    check('T4 the trace follows those rules: %s' % want, res.get('complete') and hops(res) == want, hops(res))
    # cross-check every hop against OVS's own dump (not through the trace)
    ok = True
    for h in [h for h in res['hops'] if h['kind'] == 'switch']:
        src = re.search(r'dl_src=([0-9a-f:]+)', h['rule']).group(1)
        dst = re.search(r'dl_dst=([0-9a-f:]+)', h['rule']).group(1)
        dump = on_root('ovs-ofctl -O OpenFlow13 dump-flows %s | grep "cookie=0x10" | grep "in_port=%d," '
                       '| grep "dl_src=%s" | grep "dl_dst=%s"' % (h['name'], h['in_port'], src, dst))
        ok = ok and ('output:%d' % h['out_port']) in dump
    check('T4 every hop matches the rule OVS itself reports (ovs-ofctl dump-flows)', ok)

    # ---- T5: the SECOND round does NOT reach the controller ------------------
    before = counters()
    got = ping('pc1', '10.10.20.21', 20)
    after = counters()
    to_ctl = {s: after[s]['miss'] - before[s]['miss'] for s in path}
    in_switch = {s: sum(after[s]['learned'].values()) - sum(before[s]['learned'].get(k, 0)
                                                           for k in after[s]['learned']) for s in path}
    check('T5 20 more pings all answered (%d/20)' % got, got == 20)
    check('T5 none of them went to the controller (table-miss +0 on arista1, cisco1, hp1)',
          all(v == 0 for v in to_ctl.values()), to_ctl)
    check('T5 the switches forwarded them with the learned rules (40+ packets per switch: requests + replies)',
          all(v >= 40 for v in in_switch.values()), in_switch)
    status, res2 = trace('pc1', 'srv1')
    first_hop = [h for h in res2['hops'] if h['kind'] == 'switch'][0]
    check('T5 the trace shows the rule being used (arista1 rule packet count went up)',
          first_hop['rule_packets'] >= res['hops'][0]['rule_packets'] + 20,
          '%s -> %s packets' % (res['hops'][0]['rule_packets'], first_hop['rule_packets']))

    # ---- T6: same VLAN, no router --------------------------------------------
    # pc2's address may have come from DHCP (earlier tests), so ping the
    # address it has now; the switches' rules are keyed on its MAC anyway.
    pc2_ip = re.search(r'inet ([\d.]+)', on_host('pc2', 'ip -4 -o addr show pc2-eth0')).group(1)
    ping('pc1', pc2_ip, 2)
    status, res = trace('pc1', 'pc2')
    want = 'arista1 2>1, cisco1 2>3, arista2 1>2'
    check('T6 same VLAN pc1 -> pc2: %s (no router)' % want, res.get('complete') and hops(res) == want, hops(res))

    # ---- T6b: regression test for the "never learned" bug ---------------------
    # pc1 <-> srv1 rules exist (T4/T5). Before rules matched the source MAC,
    # pc2's replies to pc1 rode the existing "to pc1" rule at arista1, the
    # controller never learned pc2 there, and EVERY pc1 -> pc2 packet was
    # flooded through the controller. Now a second round must stay in the
    # switches.
    before = counters()
    got = ping('pc1', pc2_ip, 20)
    after = counters()
    to_ctl = {s: after[s]['miss'] - before[s]['miss'] for s in ('arista1', 'cisco1', 'arista2')}
    check('T6b second round pc1 -> pc2 (20/20 answered: %d) never reaches the controller' % got,
          got == 20 and all(v == 0 for v in to_ctl.values()), to_ctl)

    # ---- T7: VLAN 20 between the two OVS servers ------------------------------
    ping('vm1', '10.10.20.32', 2)
    status, res = trace('vm1', 'vm2')
    want = 'ovs1 2>1, arista1 3>1, cisco1 2>3, arista2 1>3, ovs2 1>2'
    check('T7 vm1 -> vm2 across both OVS servers: %s' % want, res.get('complete') and hops(res) == want, hops(res))

    # ---- T8: to the Internet --------------------------------------------------
    ping('pc1', '203.0.113.2', 2)
    status, res = trace('pc1', 'inet')
    check('T8 pc1 -> inet ends at the router, out to the Internet',
          res.get('complete') and hops(res) == 'arista1 2>1, cisco1 2>1, r1'
          and 'Internet' in res['hops'][-1]['decision'], ' | '.join(res.get('lines', [])))

    # ---- T9: a cut cable: the trace follows the new rules ----------------------
    try:
        on_root('ip link set cisco1-eth3 down; ip link set arista2-eth1 down')
        time.sleep(3)
        # The cut makes the controller forget all learned paths; they are
        # relearned from new traffic. Ping until it gets through (max 2
        # rounds) so the trace has rules to read. (Run 2 traced right after
        # an unchecked ping and found no rule yet; see t9_debug.txt.)
        got = ping('pc2', '10.10.20.21', 3)
        if got < 3:
            got = ping('pc2', '10.10.20.21', 3)
        time.sleep(1)
        status, res = trace('pc2', 'srv1')
        want = 'arista2 2>4, arista1 4>1, cisco1 2>1, r1, cisco1 1>4, hp1 1>2'
        standby = [h['name'] for h in res['hops'] if h.get('standby')]
        check('T9 cable cut: pc2 -> srv1 goes over the standby link: %s' % want,
              res.get('complete') and hops(res) == want and standby == ['arista2'],
              '%s   (last ping round: %d/3 answered)' % (hops(res), got))
    finally:
        on_root('ip link set cisco1-eth3 up; ip link set arista2-eth1 up')
    time.sleep(3)
    ping('pc2', '10.10.20.21', 3)
    status, res = trace('pc2', 'srv1')
    check('T9 cable restored: back to arista2 out 1',
          res.get('complete') and hops(res).startswith('arista2 2>1, cisco1 3>1'), hops(res))

    # ---- T10: the CLI on the controller VM (Python 3.5, default address) -------
    #   Controller password from CONTROLLER_SSHPASS (never stored in this file).
    if not os.environ.get('CONTROLLER_SSHPASS'):
        print('SKIP  T10 CLI on the controller (set CONTROLLER_SSHPASS to run it)')
    else:
        ping('pc1', '10.10.20.21', 2)
        out = subprocess.run(
            ['sshpass', '-e', 'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'PubkeyAuthentication=no',
             'sdn@100.110.3.67', 'cd /home/sdn/lab9 && python3 applications/trace_cli.py pc1 srv1; echo "exit=$?"'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
            env=dict(os.environ, SSHPASS=os.environ['CONTROLLER_SSHPASS']), timeout=60).stdout
        check('T10 CLI on the controller prints the path and exits 0',
              'arista1 (dpid 11)  in 2 -> out 1' in out and 'srv1 reached' in out and 'exit=0' in out,
              '\n        '.join(l for l in out.splitlines() if 'X11' not in l))

    passed = sum(1 for _, ok in results if ok)
    print('\n%d/%d checks passed' % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
