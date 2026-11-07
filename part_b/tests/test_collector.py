#!/usr/bin/env python3
"""Tests part_b/collector.py against the live network.

Every check compares what the collector reports (through the controller's
REST API) with an independent source, and has a control, so nothing can
pass by accident:
  - flow tables       vs  ovs-ofctl dump-flows on the switch itself
  - packet rates      vs  a ping flood of known speed (idle first = control)
  - link failure      vs  a cable we cut ourselves (all up first = control)
  - drop / unauthorized rules  vs  a rule we plant and then remove

Needs: network (lab9_net.py) + Ryu running. Leaves everything as found.
Run on the laptop:
  SSHPASS=<mininet password> python3 lab9/part_b/tests/test_collector.py
"""

import json
import os
import re
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(HERE, '..', '..', 'applications', 'tests'))

import collector                                  # noqa: E402
from mininet_host import on_host, on_root         # noqa: E402

BASE = 'http://100.110.3.67:8080'
NSOT = collector.load_nsot()
results = []


def check(name, passed, detail=''):
    results.append((name, bool(passed)))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('\n        %s' % (detail,)) if detail != '' else ''))
    sys.stdout.flush()


def snapshot(seconds=2.0):
    return collector.collect_network_state(NSOT, BASE, seconds)


def link(state, name):
    return [l for l in state['links'] if l['link'] == name][0]


def rest_post(path, body):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode(), {'Content-Type': 'application/json'})
    return urllib.request.urlopen(req, timeout=10).status


def main():
    # ---- C1: connected switches = the NSOT -----------------------------------
    s = snapshot()
    check('C1 all 6 NSOT switches reported connected, none missing or unknown',
          len(s['switches']['connected']) == 6 and not s['switches']['missing'] and not s['switches']['unknown_dpids'],
          s['switches'])
    check('C1 the 4 hardware switches are cisco1, arista1, arista2, hp1',
          s['hardware_switches'] == ['arista1', 'arista2', 'cisco1', 'hp1'], s['hardware_switches'])

    # ---- C2: flow tables = what the switch itself holds -------------------------
    on_host('pc1', 'ping -c 3 -i 0.2 10.10.20.21 > /dev/null')       # create learned rules
    s = snapshot()
    truth = on_root('for b in %s; do echo "== $b $(ovs-ofctl -O OpenFlow13 dump-flows $b | grep -c cookie=)"; done'
                    % ' '.join(sorted(NSOT['switches'])))
    ovs = dict((m.group(1), int(m.group(2))) for m in re.finditer(r'== (\S+) (\d+)', truth))
    ours = dict((n, len(r)) for n, r in s['flows'].items())
    # learned rules can expire between the two readings: allow 1 difference
    check('C2 rule count per switch equals ovs-ofctl dump-flows (+-1 for expiring rules)',
          set(ovs) == set(ours) and all(abs(ovs[n] - ours[n]) <= 1 for n in ovs),
          'collector %s | ovs-ofctl %s' % (ours, ovs))
    owners = set(r['owner'] for rules in s['flows'].values() for r in rules)
    check('C2 every rule has a known owner (no unauthorized rules on a clean network)',
          'unauthorized' not in owners and 'learned' in owners, sorted(owners))
    check('C2 control: no drop rules on a clean network', not any(s['drop_rules'].values()))

    # ---- C3: packet rates against a flood of known speed --------------------------
    idle = snapshot()['port_rates']['arista1']['2']
    check('C3 control: pc1\'s port (arista1:2) is idle (< 5 pps)', idle['valid'] and idle['rx_pps'] < 5, idle)
    out = {}
    flood = threading.Thread(target=lambda: out.update(
        ping=on_host('pc1', 'ping -q -i 0.01 -c 1000 10.10.20.21', timeout=60)))
    flood.start()
    time.sleep(2)                                  # let the flood settle
    s = snapshot(3.0)
    flood.join()
    m = re.search(r'(\d+) packets transmitted, (\d+) received.*time (\d+)ms', out.get('ping', ''))
    sent_pps = int(m.group(1)) / (int(m.group(3)) / 1000.0) if m else 0
    p = s['port_rates']['arista1']['2']
    check('C3 flood measured on arista1:2 within 20%% of ping\'s own rate (%.0f pps)' % sent_pps,
          p['valid'] and sent_pps > 0 and abs(p['rx_pps'] - sent_pps) <= 0.2 * sent_pps,
          'collector rx %.1f pps, tx %.1f pps | ping sent %s in %s ms' % (p['rx_pps'], p['tx_pps'],
                                                                         m.group(1) if m else '?', m.group(3) if m else '?'))
    pc1 = NSOT['hosts']['pc1']['mac']
    busy = [r for r in s['flows']['arista1'] if r['owner'] == 'learned' and r['pps']]
    top = max(busy, key=lambda r: r['pps']) if busy else None
    check('C3 the busiest rule on arista1 names the sender (eth_src = pc1)',
          top is not None and top['match'].get('dl_src') == pc1 and top['pps'] >= 0.8 * sent_pps,
          top and '%s at %.1f pps' % (top['match'], top['pps']))

    # ---- C4: the standby link fails --------------------------------------------------
    check('C4 control: every NSOT link is up', all(l['state'] == 'up' for l in snapshot(1)['links']))
    try:
        on_root('ip link set arista2-eth4 down')
        time.sleep(2)
        s = snapshot(1)
        sb = link(s, 'arista1:4-arista2:4')
        others = [l['link'] for l in s['links'] if l['state'] != 'up' and l['link'] != sb['link']]
        check('C4 standby link cut: reported down and marked standby, every other link up',
              sb['state'] == 'down' and sb['standby'] and not others, '%s (%s)' % (sb['state'], sb['why']))
    finally:
        on_root('ip link set arista2-eth4 up')
    time.sleep(2)
    check('C4 standby link restored: reported up again',
          link(snapshot(1), 'arista1:4-arista2:4')['state'] == 'up')

    # ---- C5: a main link fails, traffic moves to the standby link ------------------
    try:
        on_root('ip link set cisco1-eth3 down; ip link set arista2-eth1 down')
        time.sleep(3)
        on_host('pc2', 'ping -c 3 -i 0.2 -W 1 10.10.20.21 > /dev/null; ping -c 3 -i 0.2 -W 1 10.10.20.21 > /dev/null')
        s = snapshot(1)
        main_l, sb = link(s, 'cisco1:3-arista2:1'), link(s, 'arista1:4-arista2:4')
        check('C5 main link cisco1-arista2 cut: reported down; standby up and now carrying traffic',
              main_l['state'] == 'down' and sb['state'] == 'up' and sb['learned_rules_using_it'] > 0,
              'main %s (%s) | standby %s, %d rules use it' % (main_l['state'], main_l['why'], sb['state'],
                                                             sb['learned_rules_using_it']))
    finally:
        on_root('ip link set cisco1-eth3 up; ip link set arista2-eth1 up')
    time.sleep(3)
    s = snapshot(1)
    check('C5 restored: all links up', all(l['state'] == 'up' for l in s['links']))

    # ---- C6: a drop rule nobody owns ----------------------------------------------
    planted = {'dpid': NSOT['switches']['hp1']['dpid'], 'cookie': 0x99, 'priority': 30, 'table_id': 0,
               'match': {'eth_type': 2048, 'ipv4_dst': '10.10.20.250'}, 'actions': []}
    try:
        rest_post('/stats/flowentry/add', planted)
        time.sleep(1)
        s = snapshot(1)
        drops, unauth = s['drop_rules']['hp1'], s['unauthorized_rules']['hp1']
        check('C6 planted drop rule (cookie 0x99) on hp1: found as a drop rule AND as unauthorized',
              len(drops) == 1 and len(unauth) == 1 and drops[0]['cookie'] == 0x99 and drops[0]['priority'] == 30,
              drops)
        check('C6 nothing else flagged on the other switches',
              not any(v for n, v in s['drop_rules'].items() if n != 'hp1')
              and not any(v for n, v in s['unauthorized_rules'].items() if n != 'hp1'))
    finally:
        rest_post('/stats/flowentry/delete_strict', planted)
    time.sleep(1)
    s = snapshot(1)
    check('C6 removed again: no drop or unauthorized rules anywhere',
          not any(s['drop_rules'].values()) and not any(s['unauthorized_rules'].values()))

    passed = sum(1 for _, ok in results if ok)
    print('\n%d/%d checks passed' % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
