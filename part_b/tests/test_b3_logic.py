#!/usr/bin/env python3
"""Offline tests of B3's detectors and decision rules (no network, no model).

Detectors run on REAL snapshots saved by the B1 experiment (planted: flood
from pc2, scan from vm1, rogue rule on hp1, standby link down; clean: normal
traffic). The model and the REST calls are replaced by stubs, so every
decision path is forced on purpose:
  agree -> act | disagree -> nothing | model "none" -> nothing |
  human "no" -> nothing | model error -> nothing | validator refuses -> nothing

  python3 lab9/part_b/tests/test_b3_logic.py
"""

import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import b3_responder as B3            # noqa: E402
import collector                     # noqa: E402
import events                        # noqa: E402
import llm_client                    # noqa: E402

NSOT = collector.load_nsot()
POLICY = B3.load_policy()
SNAP = os.path.join(HERE, '..', '..', 'logs', 'stepB1_analyst', 'run1_6000tokens')
results = []


def check(name, passed, detail=''):
    results.append((name, bool(passed)))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('\n        %s' % (detail,)) if detail != '' else ''))


def load(name):
    with open(os.path.join(SNAP, 'snapshot_%s.json' % name)) as f:
        return json.load(f)


def answer(threat, action, target='x'):
    return {'threat_type': threat, 'confidence': 0.9, 'severity': 'high', 'target': target,
            'explanation': 'stub', 'recommended_action': action, 'evidence_used': []}


class Stub(object):
    """Replaces the model, the REST writes and the re-read."""
    def __init__(self, reply):
        self.reply, self.applied = reply, []

    def install(self):
        B3.classify = lambda c, n, p: self.reply(c) if callable(self.reply) else self.reply
        B3.apply_steps = lambda steps, n, b: [self.applied.append(s['what']) or s['what'] for s in steps]


def responder(mode='auto', ask=None):
    return B3.Responder(NSOT, 'http://stub', mode, ask=ask, log_dir=os.path.join('/tmp/opencode', 'b3_logic_test'),
                        out=lambda s: None)


def main():
    events.configure(None, enabled=False)
    real_classify, real_apply = B3.classify, B3.apply_steps
    planted, clean = load('planted_1'), load('clean_1')

    # ---- detectors on real snapshots ----------------------------------------------
    for name in ('clean_1', 'clean_2'):
        found = B3.detect(load(name), NSOT, POLICY)
        check('D1 %s (normal traffic): no detector fires' % name, not found, [c['key'] for c in found])
    found = dict((c['gate'], c) for c in B3.detect(planted, NSOT, POLICY))
    check('D2 planted: all 4 detectors fire (flood, scan, unauthorized, link)',
          set(found) == set(['traffic_flood', 'port_scan', 'unauthorized_flow', 'link_failure']), sorted(found))
    sym = found.get('traffic_flood', {})
    check('D2 ping -f is symmetric (srv1 replies at the same rate): ONE incident "pc2+srv1", marked symmetric',
          sym.get('target') == 'pc2+srv1' and sym.get('symmetric'), sym.get('target'))
    # The same snapshot as a ONE-WAY flood (the victim does not answer):
    oneway = json.loads(json.dumps(planted))
    for r in oneway['flows']['hp1']:
        if r['owner'] == 'learned' and r['match'].get('dl_src') == NSOT['hosts']['srv1']['mac']:
            r['pps'] = 0.5
    ow = dict((c['gate'], c) for c in B3.detect(oneway, NSOT, POLICY)).get('traffic_flood', {})
    check('D2b one-way flood: the source is pc2 (from its edge switch\'s rules), not symmetric',
          ow.get('target') == 'pc2' and not ow.get('symmetric'), ow.get('evidence', {}).get('forwarded_pps_by_rule'))
    check('D2 scanner = vm1', found.get('port_scan', {}).get('target') == 'vm1')
    check('D2 rogue rule on hp1, cookie 0x99', found.get('unauthorized_flow', {}).get('rule', {}).get('cookie') == 0x99)
    check('D2 link = the standby link', found.get('link_failure', {}).get('target') == 'arista1:4-arista2:4')
    ev = json.dumps([c['evidence'] for c in found.values()])
    check('D3 the evidence never tells the model what the detector suspects',
          'traffic_flood' not in ev and 'port_scan' not in ev and '"gate"' not in ev)

    # ---- responses built by code ---------------------------------------------------------
    steps, note = B3.plan_response(ow, 'rate_limit_source', NSOT, oneway, POLICY, [])
    check('R1 rate limit with no meters -> documented fallback: temporary block of pc2 at arista2 port 2',
          steps and steps[0]['validation']['ok'] and steps[0]['switch'] == 'arista2'
          and steps[0]['proposal']['match']['in_port'] == 2 and 'fall' in note.lower(), (steps and steps[0]['what'], note))
    steps, _ = B3.plan_response(found['port_scan'], 'block_source_tcp', NSOT, planted, POLICY, [])
    check('R2 scan -> block only TCP from vm1 at ovs1 (OVS), validated, 120 s',
          steps and steps[0]['validation']['ok'] and steps[0]['switch'] == 'ovs1'
          and steps[0]['proposal']['match'].get('ip_proto') == 6 and steps[0]['proposal']['hard_timeout'] == 120,
          steps and (steps[0]['what'], steps[0]['validation']['errors']))
    steps, _ = B3.plan_response(found['unauthorized_flow'], 'remove_rule', NSOT, planted, POLICY, [])
    check('R3 unauthorized -> delete exactly that rule (cookie 0x99) on hp1', steps and steps[0]['kind'] == 'delete'
          and steps[0]['validation']['ok'], steps and steps[0]['what'])
    fake = dict(found['unauthorized_flow'], rule=dict(found['unauthorized_flow']['rule'], cookie=48, owner='dns_intercept'))
    steps, _ = B3.plan_response(fake, 'remove_rule', NSOT, planted, POLICY, [])
    check('R4 a "remove" aimed at the DNS rule (cookie 0x30) is refused by the validator',
          steps and not steps[0]['validation']['ok'], steps and steps[0]['validation']['errors'])
    steps, _ = B3.plan_response(found['link_failure'], 'verify_failover', NSOT, planted, POLICY, [])
    check('R5 link failure -> verify failover (read-only check first)', steps and steps[0]['kind'] == 'check')
    status, ok = B3.failover_status(planted, 'arista1:4-arista2:4')
    check('R5 failover check on the planted snapshot says redundancy is lost', 'no redundancy left' in status, status)
    steps, note = B3.plan_response(dict(found['traffic_flood'], target='10.10.10.250'), 'block_source', NSOT,
                                   planted, POLICY, [])
    check('R6 a source that is no NSOT host is never blocked', not steps and 'not an NSOT host' in note, note)

    # ---- decision rules (stub model, stub REST) -------------------------------------------------
    s = Stub(answer('traffic_flood', 'block_source', 'pc2')); s.install()
    r = responder(); r.handle(sym, planted)
    check('P0 symmetric flood + model says "block pc2" -> ALERT only, nothing blocked (never on a guess)',
          r.incidents[sym['key']]['status'] == 'alerted' and not s.applied)
    c = ow
    s = Stub(answer('traffic_flood', 'block_source', 'pc2')); s.install()
    r = responder(); r.handle(c, planted)
    check('P1 AUTO, detector + model agree -> applied', r.incidents[c['key']]['status'] == 'handled' and s.applied,
          s.applied)
    s = Stub(answer('none', 'none')); s.install()
    r = responder(); r.handle(c, planted)
    check('P2 model says "none" -> NO action, counted as a disagreement',
          r.incidents[c['key']]['status'] == 'disagreed' and not s.applied and r.stats['disagreements'] == 1)
    s = Stub(answer('port_scan', 'block_source_tcp', 'pc2')); s.install()
    r = responder(); r.handle(c, planted)
    check('P3 model names a different threat -> NO action', r.incidents[c['key']]['status'] == 'disagreed' and not s.applied)
    s = Stub(answer('traffic_flood', 'alert_only', 'pc2')); s.install()
    r = responder(); r.handle(c, planted)
    check('P4 model recommends alert only -> alert, no change', r.incidents[c['key']]['status'] == 'alerted' and not s.applied)
    s = Stub(answer('traffic_flood', 'block_source', 'pc2')); s.install()
    r = responder('hitl', ask=lambda q: False); r.handle(c, planted)
    check('P5 HITL, operator says no -> declined, no change', r.incidents[c['key']]['status'] == 'declined' and not s.applied)
    r = responder('hitl', ask=lambda q: True); r.handle(c, planted)
    check('P6 HITL, operator says yes -> applied', r.incidents[c['key']]['status'] == 'handled' and s.applied)

    def boom(cand):
        raise llm_client.LLMError('stub: answer still invalid')
    s = Stub(boom); s.install()
    r = responder(); r.handle(c, planted)
    check('P7 model gives no valid answer -> NO action', r.incidents[c['key']]['status'] == 'model_error' and not s.applied)
    s = Stub(answer('unauthorized_flow', 'remove_rule', 'hp1')); s.install()
    r = responder(); r.handle(dict(fake, key='x'), planted)
    check('P8 validator refuses (protected cookie) -> NO action even in AUTO',
          r.incidents['x']['status'] == 'refused' and not s.applied)

    B3.classify, B3.apply_steps = real_classify, real_apply
    passed = sum(1 for _, ok in results if ok)
    print('\n%d/%d checks passed' % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
