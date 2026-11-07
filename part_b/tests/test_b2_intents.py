#!/usr/bin/env python3
"""B2 demonstration and test: real requests, real model, real traffic.

Good intents (applied after confirmation, checked ON THE WIRE with a control):
  G1 block pc1 pinging srv1        arista1 (vendor)   ping fails, web still works
  G2 vm1 -> srv1 web blocked       ovs1 (OVS server)  web fails, ping still works
  G3 web to srv1 from anyone, 10m  hp1 (vendor)       web from pc2 fails
  G4 allow pc1 to ping srv1 again  arista1            ping works again
  G5 quarantine vm2                ovs2 (OVS server)  vm2 reaches nobody, DNS still works
Bad requests (must be questioned or refused, and NOTHING installed):
  ambiguous, unknown device, contradictory, impossible (no meters), DNS,
  management, a duplicate, "all traffic to srv1" (would cut DHCP/DNS replies)
Plus: a human answering "no" installs nothing.

Needs network + Ryu, SSHPASS=<mininet password>, lab9/.env.
Leaves no intent rule behind.
"""

import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(HERE, '..', '..', 'applications', 'tests'))

import b2_intent                      # noqa: E402
import collector                      # noqa: E402
import events                         # noqa: E402
import llm_client                     # noqa: E402
from mininet_host import on_host, resolve      # noqa: E402

BASE = 'http://100.110.3.67:8080'
NSOT = collector.load_nsot()
results = []
transcript = []


def check(name, passed, detail=''):
    results.append((name, bool(passed)))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('\n        %s' % (detail,)) if detail != '' else ''))
    sys.stdout.flush()


def ping_ok(src, dst_ip):
    out = on_host(src, 'ping -c 3 -i 0.3 -W 1 %s' % dst_ip)
    m = re.search(r'(\d+) received', out)
    return bool(m and int(m.group(1)) > 0)


def web_ok(src):
    return on_host(src, 'curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.10.20.21/').strip() == '200'


def dns_ok(src, server='10.10.20.1'):
    """A real DNS lookup through r1 (VLAN 20 gateway) gets an answer."""
    return bool(resolve(src, 'good.lab9.lan', server))


def intents():
    return b2_intent.list_intents(NSOT, BASE)


def run(text, expect, auto=True, ask=input):
    """One request through the whole pipeline; prints the transcript."""
    res = b2_intent.handle(text, NSOT, BASE, auto=auto, ask=ask)
    line = '"%s" -> %s: %s' % (text, res['outcome'], res.get('why') or res.get('question') or
                               (res.get('answer') or {}).get('interpretation', ''))
    transcript.append(line)
    print('   ' + line)
    return res


def main():
    events.configure(BASE)
    llm_client.EVENT_HOOK = events.llm_hook
    b2_intent.clear_intents(NSOT, BASE)
    time.sleep(1)

    # ---- controls before anything -------------------------------------------------
    check('control: pc1 pings srv1, pc1 web ok, vm1 web ok, vm2 pings vm1',
          ping_ok('pc1', '10.10.20.21') and web_ok('pc1') and web_ok('vm1') and ping_ok('vm2', '10.10.20.31'))

    # ---- a human saying no -----------------------------------------------------------
    res = run('Block pc1 from pinging srv1', 'declined', auto=False, ask=lambda q: 'n')
    check('H1 human answers "n": declined, nothing installed', res['outcome'] == 'declined' and not intents())

    # ---- G1: vendor switch ------------------------------------------------------------
    res = run('Block pc1 from pinging srv1', 'applied')
    steps = res.get('plan', {}).get('steps', [])
    check('G1 applied on arista1 (vendor), verified on the switch',
          res['outcome'] == 'applied' and steps[0]['switch'] == 'arista1' and all(ok for _, ok in res['done']),
          res.get('done'))
    check('G1 on the wire: pc1 -> srv1 ping now FAILS, pc1 -> srv1 web still WORKS (only ICMP blocked)',
          not ping_ok('pc1', '10.10.20.21') and web_ok('pc1'))

    # ---- G2: OVS server -----------------------------------------------------------------
    res = run("vm1 must not be able to open srv1's web page", 'applied')
    steps = res.get('plan', {}).get('steps', [])
    check('G2 applied on ovs1 (OVS server)', res['outcome'] == 'applied' and steps[0]['switch'] == 'ovs1',
          res.get('why') or res.get('done'))
    check('G2 on the wire: vm1 web to srv1 FAILS, vm1 ping to srv1 still WORKS',
          not web_ok('vm1') and ping_ok('vm1', '10.10.20.21'))

    # ---- G3: src any, with a duration ------------------------------------------------------
    res = run('Nobody may open web pages on srv1 for the next 10 minutes', 'applied')
    p = res.get('plan', {}).get('steps', [{}])[0].get('proposal', {})
    check('G3 applied on hp1 (srv1\'s switch, vendor) with hard_timeout 600 s',
          res['outcome'] == 'applied' and p.get('switch') == 'hp1' and p.get('hard_timeout') == 600,
          res.get('why') or p)
    check('G3 on the wire: pc2 web to srv1 FAILS', not web_ok('pc2'))

    # ---- G4: allow = remove the earlier block --------------------------------------------------
    res = run('Allow pc1 to ping srv1 again', 'applied')
    check('G4 the G1 block is deleted (verified on arista1)',
          res['outcome'] == 'applied' and res['plan']['steps'][0]['kind'] == 'delete', res.get('why') or res.get('done'))
    check('G4 on the wire: pc1 -> srv1 ping WORKS again', ping_ok('pc1', '10.10.20.21'))

    # ---- G5: quarantine; protected DNS keeps working ----------------------------------------------
    check('G5 control: vm2 DNS works before', dns_ok('vm2'))
    res = run('Quarantine vm2: it must not talk to anyone', 'applied')
    check('G5 applied on ovs2 (OVS server)', res['outcome'] == 'applied'
          and res['plan']['steps'][0]['switch'] == 'ovs2', res.get('why') or res.get('done'))
    check('G5 on the wire: vm2 -> vm1 ping FAILS, but vm2 DNS still WORKS (protected flow)',
          not ping_ok('vm2', '10.10.20.31') and dns_ok('vm2'))

    # ---- bad requests: questioned or refused, nothing new installed --------------------------------
    before = len(intents())
    bad = [('ambiguous', 'Make the network faster'),
           ('unknown device', 'Block the printer from reaching srv1'),
           ('unknown address', 'Block pc1 from reaching 10.10.10.99'),
           ('contradictory', 'Block pc1 from srv1, but pc1 must always be able to reach srv1'),
           ('impossible: no meters', 'Limit vm1 to 100 packets per second towards srv1'),
           ('protected: DNS', 'Stop pc1 from using DNS'),
           ('protected: management', 'Block all traffic to the SDN controller'),
           ('would cut DHCP/DNS replies', 'Block all traffic going to srv1'),
           ('duplicate of G5', 'Quarantine vm2: it must not talk to anyone')]
    for why, text in bad:
        res = run(text, 'refused')
        check('BAD %-26s -> %s' % (why, res['outcome']), res['outcome'] in ('unclear', 'refused', 'invalid'),
              (res.get('why') or res.get('question') or '')[:200])
    check('BAD none of the bad requests installed anything (%d intent rules before and after)' % before,
          len(intents()) == before)

    # ---- clean up --------------------------------------------------------------------------------
    b2_intent.clear_intents(NSOT, BASE)
    time.sleep(1)
    check('cleanup: no intent rules left, vm2 -> vm1 ping works, web works again',
          not intents() and ping_ok('vm2', '10.10.20.31') and web_ok('pc2') and web_ok('vm1'))

    with open(os.path.join(HERE, '..', '..', 'logs', 'stepB2_intent', 'transcript.txt'), 'w') as f:
        f.write('\n'.join(transcript) + '\n')
    passed = sum(1 for _, ok in results if ok)
    print('\n%d/%d checks passed  (model calls: %d)' % (passed, len(results), llm_client.calls_this_run()))
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    os.makedirs(os.path.join(HERE, '..', '..', 'logs', 'stepB2_intent'), exist_ok=True)
    sys.exit(main())
