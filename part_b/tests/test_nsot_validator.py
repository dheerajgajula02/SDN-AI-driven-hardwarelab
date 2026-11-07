#!/usr/bin/env python3
"""Tests part_b/nsot_validator.py (offline: the real NSOT, no network).

Every rule the AI could propose: good ones must pass, and each kind of bad
one must be refused for the RIGHT reason.
  python3 lab9/part_b/tests/test_nsot_validator.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import collector                      # noqa: E402
import nsot_validator as V            # noqa: E402

NSOT = collector.load_nsot()
IP = dict((h, NSOT['hosts'][h]['ip'].split('/')[0]) for h in NSOT['hosts'])
MAC = dict((h, NSOT['hosts'][h]['mac']) for h in NSOT['hosts'])
results = []


def check(name, passed, detail=''):
    results.append((name, bool(passed)))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('\n        %s' % (detail,)) if detail != '' else ''))


def rule(switch='arista1', **kw):
    p = {'switch': switch, 'purpose': 'intent', 'priority': 30, 'action': 'drop', 'hard_timeout': 600,
         'match': {'in_port': 2, 'eth_type': 2048, 'ipv4_src': IP['pc1'], 'ipv4_dst': IP['srv1']}}
    p.update(kw)
    return p


def refused(name, proposal, why, **kw):
    r = V.validate_rule(NSOT, proposal, **kw)
    check('%s -> refused (%s)' % (name, why), not r['ok'] and any(why in e for e in r['errors']), r['errors'])


def main():
    # ---- accepted -----------------------------------------------------------------
    r = V.validate_rule(NSOT, rule())
    check('V1 block pc1 -> srv1 at pc1\'s port on arista1 (vendor switch): accepted', r['ok'], r['errors'] or r['checked'])
    r = V.validate_rule(NSOT, rule(match={'in_port': 2, 'eth_type': 2048, 'ip_proto': 6, 'ipv4_src': IP['pc1'],
                                          'ipv4_dst': IP['srv1'], 'tcp_dst': 80}))
    check('V2 block only web (TCP 80) pc1 -> srv1: accepted', r['ok'], r['errors'])
    r = V.validate_rule(NSOT, rule('ovs1', purpose='response', hard_timeout=120,
                                   match={'in_port': 2, 'eth_src': MAC['vm1']}))
    check('V3 quarantine vm1 on ovs1 (OVS), all its traffic: accepted (DNS/DHCP requests still caught at 50)',
          r['ok'], r['errors'] or r['checked'][-1])

    # ---- protected flows ---------------------------------------------------------
    refused('V4 drop everything TO pc1 (eth_dst=pc1)', rule(match={'eth_dst': MAC['pc1']}),
            'would disrupt protected traffic: DNS reply r1 -> pc1')
    refused('V5 drop everything to srv1 on hp1', rule('hp1', match={'eth_type': 2048, 'ipv4_dst': IP['srv1']}),
            'DHCP reply r1 -> srv1')
    refused('V6 "block DNS for pc1" (udp 53)', rule(match={'in_port': 2, 'eth_type': 2048, 'ip_proto': 17,
                                                          'ipv4_src': IP['pc1'], 'udp_dst': 53}),
            'targets a protected flow')
    refused('V7 the management network', rule(match={'eth_type': 2048, 'ipv4_dst': '10.224.76.126'}),
            'management network')
    refused('V8 a management port (tcp 6633)', rule(match={'in_port': 2, 'eth_type': 2048, 'ip_proto': 6,
                                                         'ipv4_src': IP['pc1'], 'tcp_dst': 6633}),
            'management port')

    # ---- AI limits -----------------------------------------------------------------
    refused('V9 priority 60 (above the protected rules)', rule(priority=60), 'outside the AI band')
    refused('V10 never expires (hard_timeout 0)', rule(hard_timeout=0), 'hard_timeout')
    refused('V11 response longer than 120 s', rule(purpose='response', hard_timeout=600), 'hard_timeout')
    refused('V12 meter on arista1 (no meter support)', rule(action='meter', meter_id=1),
            'does not support meters')
    refused('V13 action "output" (rerouting)', rule(action='output'), 'not allowed')
    refused('V14 match on VLAN (field not allowed)', rule(match={'in_port': 2, 'vlan_vid': 10}), 'not allowed')
    refused('V15 matches everything (only ip_proto)', rule(match={'eth_type': 2048, 'ip_proto': 1}), 'names no host')

    # ---- NSOT inventory -------------------------------------------------------------
    refused('V16 unknown switch', rule('juniper9'), 'not in the NSOT')
    refused('V17 port 9 on arista1', rule(match={'in_port': 9, 'eth_src': MAC['pc1']}), 'no port 9')
    refused('V18 unknown host 10.10.10.99', rule(match={'in_port': 2, 'eth_type': 2048, 'ipv4_src': '10.10.10.99'}),
            'not a host in the NSOT')
    refused('V19 unknown MAC', rule(match={'eth_src': '00:de:ad:be:ef:00'}), 'not a device in the NSOT')
    refused('V20 switch not connected', rule(), 'not connected', connected=['cisco1'])

    # ---- conflicts with live rules -----------------------------------------------------
    live = [{'owner': 'ai_intent', 'cookie': 176, 'priority': 30, 'drop': True, 'actions': [],
             'match': {'in_port': 2, 'dl_type': 2048, 'nw_src': IP['pc1'], 'nw_dst': IP['srv1']}}]
    refused('V21 the same block again', rule(), 'duplicate', live_rules=live)
    meter_live = [dict(live[0], drop=False, actions=['METER:1'],
                       match={'in_port': 2, 'dl_type': 2048, 'nw_src': IP['pc1']})]
    refused('V22 drop overlapping an existing rate limit', rule(), 'conflict', live_rules=meter_live)
    other = [dict(live[0], match={'in_port': 2, 'dl_type': 2048, 'nw_src': IP['pc1'], 'nw_dst': IP['vm1']})]
    r = V.validate_rule(NSOT, rule(), live_rules=other)
    check('V23 a block for a different destination is no conflict', r['ok'], r['errors'])

    # ---- deletes --------------------------------------------------------------------------
    for cookie, owner, ok in ((0, 'table_miss', False), (48, 'dns_intercept', False), (64, 'dhcp_intercept', False),
                              (80, 'tcp_sensor', False), (176, 'ai_intent', True), (177, 'ai_response', True),
                              (16, 'learned', True), (0x99, 'unauthorized', True)):
        r = V.validate_delete(NSOT, {'cookie': cookie, 'owner': owner})
        check('V24 delete cookie %s (%s): %s' % (hex(cookie), owner, 'allowed' if ok else 'refused'),
              r['ok'] == ok, (r['errors'] or r['checked'])[0])

    # ---- the REST body ----------------------------------------------------------------------
    body = V.to_flowentry(NSOT, rule())
    check('V25 REST body: dpid 11, cookie 0xB0, priority 30, hard_timeout 600, no actions (= drop)',
          body['dpid'] == 11 and body['cookie'] == 176 and body['priority'] == 30 and body['hard_timeout'] == 600
          and body['actions'] == [], body)

    passed = sum(1 for _, ok in results if ok)
    print('\n%d/%d checks passed' % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
