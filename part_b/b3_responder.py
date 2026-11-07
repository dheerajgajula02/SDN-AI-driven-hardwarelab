#!/usr/bin/env python3
"""Lab 9 Part B, Objective B3: closed-loop responder (builds on Lab 8).

Every cycle (about 6 s):
  1. collect   all switches through the controller REST API (collector.py)
  2. detect    CODE detectors with thresholds from b3_policy.json:
                 traffic_flood     a host's forwarded traffic >= flood_pps
                 port_scan         TCP sensor: >= 25 ports or >= 6 hosts, active
                 unauthorized_flow a rule whose cookie none of our apps uses
                 link_failure      an NSOT link reported down
  3. classify  the model gets the evidence (NOT the detector's guess) and
               names the threat and an action from the allowed list. Action
               only if detector and model AGREE; otherwise logged, nothing done.
  4. plan      CODE builds the response from the NSOT (source host's edge port,
               cookie 0xB1, priority 35, removes itself after 120 s) and the
               NSOT validator checks it (protected flows, AI band, conflicts).
               rate_limit -> meters are checked; none exist -> documented
               fallback: temporary block of the source.
  5. approve   HITL: operator answers Approve/Reject in the console's AI tab
               or y/N in the terminal (first answer wins; 60 s timeout = no).
               AUTO: applied when detector + model + validator all agree.
  6. apply     REST add / delete_strict through the controller; verified on
               the next cycles (the source's forwarded traffic drops to 0,
               the rogue rule is gone, the standby link carries traffic).
  link_failure response (bonus): verify failover (standby link up and
  carrying traffic, no rule still pointing out of a dead port; stale learned
  rules out of a dead port are deleted so traffic re-learns).

Stops after --duration seconds or --cycles, at the call cap
(LAB9_LLM_MAX_CALLS) or when part_b/STOP exists. Never runs unbounded.

Usage:
  python3 part_b/b3_responder.py --controller 100.110.3.67:8080 --mode hitl --duration 300
  python3 part_b/b3_responder.py --controller 100.110.3.67:8080 --mode auto --duration 300
"""

import argparse
import json
import os
import sys
import time
import urllib.request
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import approvals                     # noqa: E402
import collector                     # noqa: E402
import events                        # noqa: E402
import llm_client                    # noqa: E402
import nsot_validator                # noqa: E402
import nsot_view                     # noqa: E402

THREATS = ['traffic_flood', 'port_scan', 'unauthorized_flow', 'link_failure', 'none']
ACTIONS = ['rate_limit_source', 'block_source', 'block_source_tcp', 'remove_rule', 'verify_failover',
           'alert_only', 'none']
SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'required': ['threat_type', 'confidence', 'severity', 'target', 'explanation', 'recommended_action',
                 'evidence_used'],
    'properties': {
        'threat_type': {'type': 'string', 'enum': THREATS},
        'confidence': {'type': 'number', 'minimum': 0, 'maximum': 1},
        'severity': {'type': 'string', 'enum': ['low', 'medium', 'high', 'critical']},
        'target': {'type': 'string', 'maxLength': 60},
        'explanation': {'type': 'string', 'maxLength': 600},
        'recommended_action': {'type': 'string', 'enum': ACTIONS},
        'evidence_used': {'type': 'array', 'maxItems': 6, 'items': {'type': 'string', 'maxLength': 200}}}}


def load_policy():
    with open(os.path.join(HERE, 'b3_policy.json')) as f:
        return json.load(f)


# ===========================================================================
# Function 1: detectors (code only; thresholds from b3_policy.json)
# ===========================================================================

def detect(state, nsot, policy):
    """Return the candidate incidents in this snapshot:
    [{'key', 'gate', 'target', 'switch', 'evidence'}]."""
    d = policy['detect']
    att = nsot_view.attachments(nsot)
    macs = nsot_view.mac_names(nsot)
    found = []

    # Step 1: floods: traffic a host sends that its edge switch FORWARDS
    #         (learned + per-connection rules from its port). Traffic already
    #         dropped by an AI rule is not counted, so a working block clears it.
    floods = []
    for h, a in sorted(att.items()):
        if h not in nsot['hosts'] or a['switch'] not in state['flows']:
            continue
        mac = nsot['hosts'][h]['mac'].lower()
        rules = [r for r in state['flows'][a['switch']]
                 if r['owner'] in ('learned', 'tcp_sensor_connection')
                 and int(r['match'].get('in_port', -1)) == a['port']
                 and str(r['match'].get('dl_src', mac)).lower() == mac]
        pps = sum(r.get('pps') or 0 for r in rules)
        if pps >= d['flood_pps']:
            port = state['port_rates'][a['switch']].get(str(a['port']), {})
            floods.append({'key': 'traffic_flood|%s' % h, 'gate': 'traffic_flood', 'target': h, 'pps': pps,
                          'switch': a['switch'], 'evidence': {
                              'source_host': h, 'plugs_into': '%s port %d' % (a['switch'], a['port']),
                              'edge_port_rx_pps': port.get('rx_pps'), 'edge_port_tx_pps': port.get('tx_pps'),
                              'forwarded_pps_by_rule': ['%s -> %s: %s pps' % (
                                  h, macs.get(str(r['match'].get('dl_dst', '')).lower(), r['match'].get('dl_dst')),
                                  r.get('pps')) for r in sorted(rules, key=lambda r: -(r.get('pps') or 0))[:5]],
                              'tcp_connections_last_60s': sensor_for(state, nsot, h),
                              'normal_lab_traffic': 'a few packets per second per host'}})
    # Step 1b: a SYMMETRIC pair (two hosts at about the same high rate) is a
    #          conversation, e.g. a ping flood and the victim's replies. Flow
    #          counters cannot tell the sender from the responder, so it
    #          becomes ONE incident naming both, and code allows alert only:
    #          blocking on a guess could cut off the victim (found by
    #          tests/test_b3_logic.py on a real ping -f snapshot).
    used = set()
    for i, f in enumerate(floods):
        partner = [g for g in floods[i + 1:] if g['key'] not in used and
                   0.75 <= f['pps'] / max(g['pps'], 1e-9) <= 1.33]
        if f['key'] in used:
            continue
        if partner:
            g = partner[0]
            used.update([f['key'], g['key']])
            pair = '%s+%s' % (f['target'], g['target'])
            found.append({'key': 'traffic_flood|%s' % pair, 'gate': 'traffic_flood', 'target': pair,
                          'switch': f['switch'], 'symmetric': True, 'evidence': {
                              'two_hosts_at_the_same_rate': [f['evidence'], g['evidence']],
                              'note': 'both hosts send at about the same rate: one may be replying to the other'}})
        else:
            found.append(dict((k, v) for k, v in f.items() if k != 'pps'))

    # Step 2: scans: the controller's TCP sensor, still active.
    for ip, s in sorted(((state.get('tcp_sensor') or {}).get('sources') or {}).items()):
        if (s['distinct_dst_ports'] >= d['scan_distinct_ports'] or s['distinct_dst_hosts'] >= d['scan_distinct_hosts']) \
                and s['seconds_since_last'] <= d['scan_active_seconds']:
            h = s['host']
            found.append({'key': 'port_scan|%s' % h, 'gate': 'port_scan', 'target': h,
                          'switch': att.get(h, {}).get('switch'), 'evidence': {
                              'source_host': h, 'source_ip': ip,
                              'new_tcp_connections_last_60s': s['new_connections'],
                              'distinct_destination_ports': s['distinct_dst_ports'],
                              'distinct_destination_hosts': s['distinct_dst_hosts'],
                              'destination_hosts': s['dst_hosts'], 'example_ports': s['example_ports'],
                              'seconds_since_last_connection': s['seconds_since_last']}})

    # Step 3: unauthorized rules (cookie not owned by any of our apps).
    for sw, rules in sorted(state['unauthorized_rules'].items()):
        for r in rules:
            found.append({'key': 'unauthorized_flow|%s|%s|%s|%s' % (sw, r['cookie'], r['priority'],
                                                                   json.dumps(r['match'], sort_keys=True)),
                          'gate': 'unauthorized_flow', 'target': sw, 'switch': sw, 'rule': r, 'evidence': {
                              'switch': sw, 'owner': r['owner'], 'cookie': r['cookie'], 'priority': r['priority'],
                              'match': r['match'], 'actions': r['actions'] or 'DROP', 'packets': r['packets'],
                              'age_seconds': r['age_s'],
                              'our_applications_cookies': dict((k, v) for k, v in nsot['flow_cookies'].items()
                                                               if k != '_about')}})

    # Step 4: links down.
    for l in state['links']:
        if l['state'] != 'up':
            found.append({'key': 'link_failure|%s' % l['link'], 'gate': 'link_failure', 'target': l['link'],
                          'switch': l['a'], 'link': l, 'evidence': {
                              'link': l['link'], 'state': l['state'], 'why': l['why'], 'standby': l['standby'],
                              'all_links': ['%s %s%s%s' % (x['link'], x['state'], ' standby' if x['standby'] else '',
                                                           ' carrying %d rules' % x['learned_rules_using_it']
                                                           if x['standby'] else '') for x in state['links']]}})
    return found


def sensor_for(state, nsot, host):
    for ip, s in (((state.get('tcp_sensor') or {}).get('sources')) or {}).items():
        if s['host'] == host:
            return {'new_connections': s['new_connections'], 'distinct_dst_ports': s['distinct_dst_ports']}
    return {'new_connections': 0}


# ===========================================================================
# Function 2: the model's independent opinion
# ===========================================================================

def classify(candidate, nsot, policy):
    """Ask the model; returns the checked answer (raises LLMError)."""
    allowed = policy['allowed_actions']
    with open(os.path.join(HERE, 'prompts', 'b3_classify.md')) as f:
        system = f.read().replace('{network}', nsot_view.describe_network(nsot)) \
                        .replace('{allowed}', '\n'.join('- %s: %s' % (t, ', '.join(a))
                                                        for t, a in sorted(allowed.items())))

    def check(a):
        errors = []
        if a['recommended_action'] not in allowed[a['threat_type']]:
            errors.append('recommended_action "%s" is not allowed for %s (allowed: %s)'
                          % (a['recommended_action'], a['threat_type'], ', '.join(allowed[a['threat_type']])))
        return errors
    out = llm_client.call_llm('b3_classify', system, {'evidence': candidate['evidence']}, SCHEMA,
                              extra_check=check, max_tokens=3000)
    return out['answer']


# ===========================================================================
# Function 3: plan the response (code, from the NSOT; validated)
# ===========================================================================

def plan_response(candidate, action, nsot, state, policy, meter_switches=()):
    """Steps to carry out `action` for this incident:
    [{'kind': 'install'|'delete'|'check', 'switch', ..., 'validation'}] and a note."""
    att = nsot_view.attachments(nsot)
    resp = policy['response']
    note = ''
    if action == 'rate_limit_source':
        # Step 1: meters only where a switch has them; else the fallback.
        sw = att.get(candidate['target'], {}).get('switch')
        if sw not in meter_switches:
            action, note = resp['rate_limit_fallback'], resp['rate_limit_fallback_note']
    if action in ('block_source', 'block_source_tcp'):
        # Step 2: drop the source where it enters the network.
        h = candidate['target']
        if h not in att or h not in nsot['hosts']:
            return [], 'source %s is not an NSOT host: nothing safe to block' % h
        match = {'in_port': att[h]['port'], 'eth_src': nsot['hosts'][h]['mac']}
        if action == 'block_source_tcp':
            match.update(eth_type=0x0800, ip_proto=6)
        proposal = {'switch': att[h]['switch'], 'purpose': 'response', 'priority': resp['priority'],
                    'match': match, 'action': 'drop', 'hard_timeout': resp['hard_timeout']}
        v = nsot_validator.validate_rule(nsot, proposal, live_rules=state['flows'].get(att[h]['switch'], []),
                                         connected=state['switches']['connected'], meter_switches=meter_switches)
        return [{'kind': 'install', 'switch': att[h]['switch'], 'proposal': proposal, 'validation': v,
                 'what': '%s %s at %s port %d for %d s' % ('BLOCK TCP from' if action == 'block_source_tcp'
                                                           else 'BLOCK all from', h, att[h]['switch'],
                                                           att[h]['port'], resp['hard_timeout'])}], note
    if action == 'remove_rule':
        # Step 3: delete exactly the rogue rule (never a protected one).
        r = candidate['rule']
        v = nsot_validator.validate_delete(nsot, r)
        return [{'kind': 'delete', 'switch': candidate['switch'], 'rule': r, 'validation': v,
                 'what': 'DELETE rule cookie %s priority %s %s on %s' % (hex(r['cookie']), r['priority'],
                                                                         r['match'], candidate['switch'])}], note
    if action == 'verify_failover':
        # Step 4: link failure: the controller already moved traffic; check
        #         it, and remove learned rules still pointing out a dead port.
        steps = [{'kind': 'check', 'switch': candidate['switch'], 'validation': {'ok': True, 'errors': [],
                                                                               'checked': []},
                  'what': 'verify failover around %s' % candidate['target']}]
        for sw, ports in sorted(state['port_state'].items()):
            for r in state['flows'].get(sw, []):
                outs = [a.split(':', 1)[1] for a in r['actions'] if a.startswith('OUTPUT:')]
                if r['owner'] == 'learned' and any(ports.get(o) == 'down' for o in outs):
                    steps.append({'kind': 'delete', 'switch': sw, 'rule': r,
                                  'validation': nsot_validator.validate_delete(nsot, r),
                                  'what': 'DELETE stale learned rule on %s out of dead port %s' % (sw, outs)})
        return steps, note
    return [], note


def failover_status(state, link_key):
    """Plain-language failover check from a fresh snapshot."""
    down = [l for l in state['links'] if l['state'] != 'up']
    standby = [l for l in state['links'] if l['standby']]
    parts = []
    for s in standby:
        if s['state'] != 'up':
            parts.append('standby link %s is DOWN: no redundancy left' % s['link'])
        elif any(not l['standby'] for l in down):
            parts.append('standby link %s is up and carries %d learned rules (failover %s)'
                         % (s['link'], s['learned_rules_using_it'],
                            'active' if s['learned_rules_using_it'] else 'ready, no traffic yet'))
        else:
            parts.append('standby link %s is up and idle' % s['link'])
    stale = sum(1 for sw, ports in state['port_state'].items() for r in state['flows'].get(sw, [])
                if r['owner'] == 'learned' and any(ports.get(a.split(':', 1)[1]) == 'down'
                                                   for a in r['actions'] if a.startswith('OUTPUT:')))
    parts.append('%d learned rules still point out of a dead port' % stale)
    return '; '.join(parts), stale == 0


# ===========================================================================
# Function 4: approval and applying
# ===========================================================================

def rest_post(base, path, body):
    req = urllib.request.Request(base + path, json.dumps(body).encode(), {'Content-Type': 'application/json'})
    return urllib.request.urlopen(req, timeout=10).status


def apply_steps(steps, nsot, base):
    """REST add / delete_strict for every validated step."""
    done = []
    for s in steps:
        if s['kind'] == 'install':
            rest_post(base, '/stats/flowentry/add', nsot_validator.to_flowentry(nsot, s['proposal']))
        elif s['kind'] == 'delete':
            r = s['rule']
            rest_post(base, '/stats/flowentry/delete_strict', {
                'dpid': nsot['switches'][s['switch']]['dpid'], 'table_id': 0, 'cookie': r['cookie'],
                'cookie_mask': 0xffffffffffffffff, 'priority': r['priority'],
                'match': nsot_validator.normalize_match(r['match'])})
        events.emit('apply', app='b3', switch=s['switch'], what=s['what'],
                    rest={'install': '/stats/flowentry/add', 'delete': '/stats/flowentry/delete_strict',
                          'check': '(read only)'}[s['kind']])
        done.append(s['what'])
    return done


# ===========================================================================
# Class 1: the loop
# ===========================================================================

class Responder(object):
    def __init__(self, nsot, base, mode, policy=None, ask=None, log_dir=None, out=print):
        self.nsot, self.base, self.mode = nsot, base, mode
        self.policy = policy or load_policy()
        self.ask = ask                      # None = console + terminal (approvals.py); a function in tests
        self.out = out
        self.incidents = {}                 # key -> incident record
        self.log_dir = log_dir or os.path.join(HERE, '..', 'logs', 'b3_runs',
                                               datetime.now().strftime('%Y%m%d_%H%M%S_') + mode)
        if not os.path.isdir(self.log_dir):
            os.makedirs(self.log_dir)
        self.meter_switches = []
        self.stats = {'cycles': 0, 'incidents': 0, 'actions': 0, 'disagreements': 0, 'refused': 0,
                      'declined': 0, 'model_errors': 0}

    def log(self, record):
        record = dict(record, time=datetime.now().isoformat())
        with open(os.path.join(self.log_dir, 'responses.jsonl'), 'a') as f:
            f.write(json.dumps(record, sort_keys=True, default=str) + '\n')

    def say(self, text):
        self.out('[%s] %s' % (datetime.now().strftime('%H:%M:%S'), text))

    # ---- one cycle ----------------------------------------------------------
    def cycle(self):
        # Step 1: collect.
        state = collector.collect_network_state(self.nsot, self.base, self.policy['loop']['sample_seconds'])
        self.stats['cycles'] += 1
        events.emit('collect', app='b3', switches=len(state['switches']['connected']),
                    rest_calls=state['rest_calls'], cycle=self.stats['cycles'])
        # Step 2: detect; age out incidents that went quiet.
        cands = detect(state, self.nsot, self.policy)
        seen = set(c['key'] for c in cands)
        for key, inc in list(self.incidents.items()):
            if key in seen:
                inc['quiet'] = 0
                continue
            inc['quiet'] += 1
            if inc['quiet'] >= self.policy['detect']['clear_after_quiet_cycles'] and inc['status'] != 'cleared':
                inc['status_before_clear'], inc['status'] = inc['status'], 'cleared'
                inc['cleared_at'] = time.time()
                self.say('CLEARED %s (after %s)' % (key.split('|')[0] + ' ' + inc['target'], inc['status_before_clear']))
                self.log({'event': 'cleared', 'key': key, 'after': inc['status_before_clear'],
                          'seconds_open': round(inc['cleared_at'] - inc['first_seen'], 1)})
                events.emit('verify', app='b3', ok=True, what='%s %s cleared' % (inc['gate'], inc['target']))
        # Step 3: handle each new (or returning) incident.
        for c in cands:
            inc = self.incidents.get(c['key'])
            if inc and inc['status'] != 'cleared':
                retry = (inc['status'] == 'handled' and c['gate'] in ('traffic_flood', 'port_scan', 'unauthorized_flow')
                         and inc['handled_cycle'] < self.stats['cycles'] - 1 and inc['attempts'] < 3)
                if not retry:
                    continue
                self.say('STILL ACTIVE after the response: %s %s (attempt %d)' % (c['gate'], c['target'],
                                                                               inc['attempts'] + 1))
            self.handle(c, state, inc)
        return state

    # ---- one incident -----------------------------------------------------------
    def handle(self, c, state, previous=None):
        inc = previous if previous and previous['status'] != 'cleared' else {
            'key': c['key'], 'gate': c['gate'], 'target': c['target'], 'first_seen': time.time(), 'attempts': 0}
        inc.update(quiet=0, attempts=inc['attempts'] + 1)
        self.incidents[c['key']] = inc
        self.stats['incidents'] += 1 if inc['attempts'] == 1 else 0
        self.say('DETECTED %s: %s' % (c['gate'], c['target']))
        events.emit('detect', app='b3', gate=c['gate'], target=c['target'], switch=c['switch'])

        # Step 1: the model's independent opinion.
        try:
            a = classify(c, self.nsot, self.policy)
        except llm_client.LLMError as e:
            inc['status'] = 'model_error'
            self.stats['model_errors'] += 1
            self.say('  model: no valid answer (%s): NO ACTION' % e)
            self.log({'event': 'model_error', 'key': c['key'], 'error': str(e)})
            events.emit('refuse', app='b3', why='model: %s' % e)
            return
        self.say('  model: %s (confidence %.2f, %s) -> %s: %s' % (a['threat_type'], a['confidence'], a['severity'],
                                                                 a['recommended_action'], a['explanation'][:160]))
        inc['model'] = a
        # Step 2: detector and model must agree.
        if a['threat_type'] != c['gate']:
            inc['status'] = 'disagreed'
            self.stats['disagreements'] += 1
            self.say('  detector says %s, model says %s: NO ACTION (logged)' % (c['gate'], a['threat_type']))
            self.log({'event': 'disagreement', 'key': c['key'], 'detector': c['gate'], 'model': a,
                      'evidence': c['evidence']})
            events.emit('refuse', app='b3', why='detector %s vs model %s' % (c['gate'], a['threat_type']))
            return
        if c.get('symmetric') and a['recommended_action'] not in ('alert_only', 'none'):
            inc['status'] = 'alerted'
            self.say('  ALERT only: %s send at the same rate, so the flow counters cannot tell the sender '
                     'from the responder; code never blocks on a guess (model suggested %s)'
                     % (c['target'].replace('+', ' and '), a['recommended_action']))
            self.log({'event': 'alert', 'key': c['key'], 'model': a, 'evidence': c['evidence'],
                      'why': 'symmetric flood: attribution impossible from flow counters'})
            events.emit('refuse', app='b3', why='symmetric flood %s: alert only, no block on a guess' % c['target'])
            return
        if a['recommended_action'] in ('alert_only', 'none'):
            inc['status'] = 'alerted'
            self.say('  ALERT only (model recommends no network change)')
            self.log({'event': 'alert', 'key': c['key'], 'model': a, 'evidence': c['evidence']})
            return
        # Step 3: the response, built and validated by code.
        steps, note = plan_response(c, a['recommended_action'], self.nsot, state, self.policy, self.meter_switches)
        if note:
            self.say('  note: %s' % note)
        bad = [e for s in steps for e in s['validation']['errors']]
        for s in steps:
            events.emit('validate', app='b3', switch=s['switch'], ok=s['validation']['ok'],
                        reasons=s['validation']['errors'] or s['validation']['checked'][-1:], what=s['what'])
        if not steps or bad:
            inc['status'] = 'refused'
            self.stats['refused'] += 1
            self.say('  validator REFUSED: %s' % ('; '.join(bad) or note or 'no safe action'))
            self.log({'event': 'refused', 'key': c['key'], 'errors': bad, 'note': note, 'model': a})
            return
        for s in steps:
            self.say('  plan: %s' % s['what'])
        # Step 4: approval. AUTO: detector + model + validator agreed.
        #         HITL: the operator, in the console (Approve / Reject) or
        #         the terminal, first answer wins; no answer in time = no.
        if self.mode == 'auto':
            yes = True
            events.emit('approval', app='b3', mode='auto', decision=True)
        elif self.ask is not None:
            yes = self.ask('Apply %d step(s) for %s %s?' % (len(steps), c['gate'], c['target']))
            events.emit('approval', app='b3', mode='human', decision=yes, by='scripted operator')
        else:
            yes, _ = approvals.ask_operator(
                self.base, 'b3', 'B3 response: %s from %s' % (c['gate'].replace('_', ' '), c['target']),
                [s['what'] for s in steps],
                ['detector: %s (b3_policy.json thresholds)' % c['gate'],
                 'model agrees: %s, confidence %.2f, recommends %s' % (a['threat_type'], a['confidence'],
                                                                        a['recommended_action'])]
                + [x for s in steps for x in s['validation']['checked']] + ([note] if note else []),
                a['explanation'], self.policy['loop']['hitl_timeout_seconds'], out=self.say)
        if not yes:
            inc['status'] = 'declined'
            self.stats['declined'] += 1
            self.say('  declined: no change')
            self.log({'event': 'declined', 'key': c['key'], 'steps': [s['what'] for s in steps]})
            return
        # Step 5: apply through the controller.
        done = apply_steps(steps, self.nsot, self.base)
        self.stats['actions'] += len([s for s in steps if s['kind'] != 'check'])
        inc.update(status='handled', handled_cycle=self.stats['cycles'], applied_at=time.time())
        result = ''
        if a['recommended_action'] == 'verify_failover':
            time.sleep(1)
            fresh = collector.collect_network_state(self.nsot, self.base, 1.0)
            result, ok = failover_status(fresh, c['target'])
            events.emit('verify', app='b3', ok=ok, what=result)
            self.say('  failover check: %s' % result)
        self.say('  APPLIED (%s): %s' % (self.mode, '; '.join(done)))
        self.log({'event': 'applied', 'key': c['key'], 'mode': self.mode, 'steps': done, 'model': a,
                  'evidence': c['evidence'], 'note': note, 'verify': result,
                  'detect_to_apply_s': round(time.time() - inc['first_seen'], 1)})

    # ---- the bounded loop ----------------------------------------------------------
    def run(self, duration, max_cycles=0, stop_event=None):
        """Run until `duration` s, `max_cycles`, the call cap, STOP, or stop_event."""
        self.meter_switches = switches_with_meters(self.nsot, self.base)
        events.emit('run_start', app='b3', mode=self.mode, duration=duration)
        self.say('B3 responder: mode %s, %d s, policy %s, meters on: %s' % (
            self.mode.upper(), duration, json.dumps(self.policy['detect']), self.meter_switches or 'no switch'))
        end = time.time() + duration
        while time.time() < end and not (max_cycles and self.stats['cycles'] >= max_cycles):
            if stop_event is not None and stop_event.is_set():
                break
            if os.path.exists(llm_client.STOP_FILE):
                self.say('STOP file found: stopping')
                break
            started = time.time()
            try:
                self.cycle()
            except llm_client.LLMError as e:
                self.say('model budget/kill switch: %s: stopping' % e)
                break
            except Exception as e:                 # a REST hiccup must not kill the loop
                self.say('cycle error (continuing): %s' % e)
                self.log({'event': 'cycle_error', 'error': str(e)})
            time.sleep(max(0, self.policy['loop']['interval_seconds'] - (time.time() - started)))
        self.stats['model_calls'] = llm_client.calls_this_run()
        events.emit('run_end', app='b3', **self.stats)
        self.say('done: %s' % json.dumps(self.stats))
        with open(os.path.join(self.log_dir, 'summary.json'), 'w') as f:
            json.dump({'stats': self.stats, 'incidents': self.incidents, 'mode': self.mode,
                       'policy': self.policy}, f, indent=1, default=str)
        return self.stats


def switches_with_meters(nsot, base):
    out = []
    for n, s in sorted(nsot['switches'].items()):
        try:
            f = collector.rest_get(base, '/stats/meterfeatures/%d' % s['dpid']).get(str(s['dpid']), [{}])[0]
            if f.get('max_meter', 0) > 0:
                out.append(n)
        except Exception:
            pass
    return out


def main():
    ap = argparse.ArgumentParser(description='B3: bounded closed-loop detection and response.')
    ap.add_argument('--controller', help='IP:port of the controller REST API (default: NSOT)')
    ap.add_argument('--mode', choices=['hitl', 'auto'], default='hitl')
    ap.add_argument('--duration', type=int, default=300, help='seconds to run (default 300)')
    ap.add_argument('--cycles', type=int, default=0, help='stop after this many cycles (0 = no limit)')
    args = ap.parse_args()
    if args.duration <= 0 or args.duration > 3600:
        ap.error('--duration must be 1-3600 s (no unbounded loops)')
    nsot = collector.load_nsot()
    base = collector.controller_url(nsot, args.controller)
    events.configure(base)
    llm_client.EVENT_HOOK = events.llm_hook
    Responder(nsot, base, args.mode).run(args.duration, args.cycles)
    return 0


if __name__ == '__main__':
    sys.exit(main())
