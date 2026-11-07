#!/usr/bin/env python3
"""Lab 9 Part B, Objective B2: intent controller (builds on Lab 7).

  English -> model (translate only) -> code builds the rule from the NSOT
          -> NSOT validator -> human confirms -> controller REST -> verify

1. translate(): the model turns the request into a small structured policy
   (block / allow / rate_limit, src, dst, protocol, port), or says it is
   unclear (asks a question) or refuses. Checked by schema + NSOT names.
2. plan(): CODE decides where and how: the rule goes on the source host's
   edge switch at its port (vendor switch for pc1/pc2/srv1, OVS server for
   vm1/vm2); "allow" means deleting an earlier block. Contradictions inside
   one request are caught here.
3. Every rule goes through nsot_validator (protected flows, AI band, NSOT
   inventory, meters, conflicts with existing rules). Refused = not applied.
4. confirm(): the human sees the interpretation, the exact rules and what the
   validator checked, and answers yes/no (default no), in the console's AI
   tab (Approve / Reject) or in this terminal: first answer wins, no answer
   in 120 s = no (approvals.py).
5. apply(): POST/DELETE through the controller REST API (one controller
   path), then read the switch back to verify.

Usage:
  python3 part_b/b2_intent.py --controller 100.110.3.67:8080 "block pc1 from pinging srv1"
  python3 part_b/b2_intent.py --controller 100.110.3.67:8080 --list
  python3 part_b/b2_intent.py --controller 100.110.3.67:8080 --clear
Options: --dry-run (stop before asking), --yes (auto-confirm: scripted tests only)
"""

import argparse
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import approvals                     # noqa: E402
import collector                     # noqa: E402
import events                        # noqa: E402
import llm_client                    # noqa: E402
import nsot_validator                # noqa: E402
import nsot_view                     # noqa: E402

PROTO = {'icmp': 1, 'tcp': 6, 'udp': 17}
INTENT_PRIORITY = 30
DEFAULT_DURATION = 1800             # s; every intent removes itself (max in ai_policy)
APPROVAL_TIMEOUT = 120              # s; no answer from the operator = no

SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'required': ['status', 'policies', 'question', 'reason', 'interpretation'],
    'properties': {
        'status': {'type': 'string', 'enum': ['ok', 'unclear', 'refuse']},
        'policies': {'type': 'array', 'maxItems': 4, 'items': {
            'type': 'object', 'additionalProperties': False,
            'required': ['action', 'src', 'dst', 'protocol', 'dst_port', 'rate_pps', 'duration_s'],
            'properties': {
                'action': {'type': 'string', 'enum': ['block', 'allow', 'rate_limit']},
                'src': {'type': 'string'}, 'dst': {'type': 'string'},
                'protocol': {'type': 'string', 'enum': ['any', 'icmp', 'tcp', 'udp']},
                'dst_port': {'type': ['integer', 'null'], 'minimum': 1, 'maximum': 65535},
                'rate_pps': {'type': ['integer', 'null'], 'minimum': 1},
                'duration_s': {'type': ['integer', 'null'], 'minimum': 1}}}},
        'question': {'type': ['string', 'null'], 'maxLength': 300},
        'reason': {'type': ['string', 'null'], 'maxLength': 500},
        'interpretation': {'type': 'string', 'maxLength': 400}}}


# ===========================================================================
# Function 1: translate (the only step that uses the model)
# ===========================================================================

def intent_check(nsot):
    """Code checks on the model's translation (beyond the schema)."""
    names = set(nsot['hosts']) | set(['any'])

    def check(a):
        errors = []
        if a['status'] == 'ok' and not a['policies']:
            errors.append('status "ok" needs at least one policy')
        if a['status'] != 'ok' and a['policies']:
            errors.append('status "%s" must have an empty policies list' % a['status'])
        if a['status'] == 'unclear' and not a['question']:
            errors.append('status "unclear" needs a question')
        if a['status'] == 'refuse' and not a['reason']:
            errors.append('status "refuse" needs a reason')
        for i, p in enumerate(a['policies']):
            for k in ('src', 'dst'):
                if p[k] not in names:
                    errors.append('policies[%d].%s "%s" is not a host in the NSOT (hosts: %s)'
                                  % (i, k, p[k], ', '.join(sorted(nsot['hosts']))))
            if p['src'] == 'any' and p['dst'] == 'any':
                errors.append('policies[%d]: src and dst cannot both be "any"' % i)
            if p['src'] == p['dst']:
                errors.append('policies[%d]: src and dst are the same' % i)
            if p['dst_port'] is not None and p['protocol'] not in ('tcp', 'udp'):
                errors.append('policies[%d]: dst_port needs protocol tcp or udp' % i)
            if p['action'] == 'rate_limit' and not p['rate_pps']:
                errors.append('policies[%d]: rate_limit needs rate_pps' % i)
        return errors
    return check


def translate(text, nsot):
    """English -> checked structured answer (raises llm_client.LLMError)."""
    with open(os.path.join(HERE, 'prompts', 'b2_intent.md')) as f:
        system = f.read().replace('{network}', nsot_view.describe_network(nsot))
    return llm_client.call_llm('b2_intent', system, 'Operator request: %s' % text, SCHEMA,
                               extra_check=intent_check(nsot), max_tokens=3000)


# ===========================================================================
# Function 2: plan (CODE decides switch, port, match: never the model)
# ===========================================================================

def policy_match(nsot, p):
    """(switch, OF 1.3 match) for a policy. The rule sits on the SOURCE's
    edge switch at its port (traffic stopped where it enters the network);
    with src "any", on the destination's edge switch."""
    att = nsot_view.attachments(nsot)
    match = {'eth_type': 0x0800}
    if p['src'] != 'any':
        # Step 1: source side: the host's port and MAC (MAC, not IP: a host
        #         may have a DHCP address that differs from the NSOT).
        sw, port = att[p['src']]['switch'], att[p['src']]['port']
        match.update(in_port=port, eth_src=nsot['hosts'][p['src']]['mac'])
    else:
        sw = att[p['dst']]['switch']
    # Step 2: destination and protocol/port.
    if p['dst'] != 'any':
        match['ipv4_dst'] = nsot_view.host_ip(nsot, p['dst'])
    if p['protocol'] != 'any':
        match['ip_proto'] = PROTO[p['protocol']]
    if p['dst_port'] is not None:
        match['%s_dst' % p['protocol']] = p['dst_port']
    return sw, match


def same_traffic(a, b):
    return all(a[k] == b[k] for k in ('src', 'dst', 'protocol', 'dst_port'))


def plan(answer, nsot, base, live=None, meter_switches=None):
    """Turn a checked translation into concrete steps. Returns
    {'steps': [{'kind': 'install'|'delete', 'switch', 'proposal'|'rule',
                'validation'}], 'refused': [reasons]}"""
    steps, refused = [], []
    pols = answer['policies']
    # Step 1: contradictions inside one request (block AND allow the same).
    for i, a in enumerate(pols):
        for b in pols[i + 1:]:
            if same_traffic(a, b) and a['action'] != b['action']:
                refused.append('contradictory: "%s" and "%s" for the same traffic (%s -> %s)'
                               % (a['action'], b['action'], a['src'], a['dst']))
    if refused:
        return {'steps': [], 'refused': refused}

    connected = collector.collect_switches(nsot, base)['connected']
    if meter_switches is None:
        meter_switches = switches_with_meters(nsot, base, connected)
    for p in pols:
        sw, match = policy_match(nsot, p)
        rules = live.get(sw, []) if live is not None else collector.collect_flows(nsot, base, [sw])[sw]
        if p['action'] == 'allow':
            # Step 2: allow = delete the matching earlier block(s).
            hits = [r for r in rules if r['owner'] == 'ai_intent' and r['drop']
                    and nsot_validator.normalize_match(r['match']) == normalize(match)]
            if not hits:
                refused.append('nothing to allow: no block for %s -> %s (%s) exists on %s'
                               % (p['src'], p['dst'], p['protocol'], sw))
            for r in hits:
                steps.append({'kind': 'delete', 'switch': sw, 'rule': r,
                              'validation': nsot_validator.validate_delete(nsot, r)})
            continue
        # Step 3: block / rate_limit = one rule, validated.
        proposal = {'switch': sw, 'purpose': 'intent', 'priority': INTENT_PRIORITY, 'match': match,
                    'action': 'drop' if p['action'] == 'block' else 'meter', 'meter_id': 1,
                    'hard_timeout': min(p['duration_s'] or DEFAULT_DURATION,
                                        nsot['ai_policy']['intent_hard_timeout_max'])}
        v = nsot_validator.validate_rule(nsot, proposal, live_rules=rules, connected=connected,
                                         meter_switches=meter_switches)
        steps.append({'kind': 'install', 'switch': sw, 'proposal': proposal, 'validation': v})
    for s in steps:
        if not s['validation']['ok']:
            refused.extend(s['validation']['errors'])
    return {'steps': steps, 'refused': refused}


def normalize(match):
    """OF 1.3 match with values as strings/ints the way ofctl_rest returns them."""
    return dict((k, v) for k, v in match.items())


def switches_with_meters(nsot, base, names):
    """Switches whose /stats/meterfeatures reports max_meter > 0."""
    out = []
    for n in names:
        dpid = nsot['switches'][n]['dpid']
        try:
            f = collector.rest_get(base, '/stats/meterfeatures/%d' % dpid).get(str(dpid), [{}])[0]
            if f.get('max_meter', 0) > 0:
                out.append(n)
        except Exception:
            pass
    return out


# ===========================================================================
# Function 3: human confirmation
# ===========================================================================

def describe_step(s, nsot):
    if s['kind'] == 'install':
        p = s['proposal']
        return 'INSTALL on %s (%s): priority %d, %s %s, removes itself after %d s' % (
            s['switch'], nsot['switches'][s['switch']]['vendor'], p['priority'], p['action'].upper(),
            json.dumps(p['match'], sort_keys=True), p['hard_timeout'])
    r = s['rule']
    return 'DELETE on %s: priority %s cookie %s %s' % (s['switch'], r['priority'], r['cookie'], r['match'])


def confirm(answer, the_plan, nsot, auto=False, ask=None, base=None, request='', timeout=APPROVAL_TIMEOUT):
    """Show everything; return (approved, by). True only on an explicit yes.
    Default: ask in the console AND the terminal (approvals.py), first
    answer wins, no answer in `timeout` s = no. `ask` (a function) replaces
    the human in scripted tests; auto=True is --yes (tests only)."""
    # Step 1: what will happen, and what the validator checked.
    print('\nI understood: %s' % answer['interpretation'])
    for s in the_plan['steps']:
        print('  ' + describe_step(s, nsot))
        for c in s['validation']['checked']:
            print('      ok: %s' % c)
    # Step 2: who answers.
    if auto:
        print('Apply? [y/N] y   (auto-confirmed: --yes, for scripted tests)')
        return True, 'auto-confirm (test)'
    if ask is not None:
        try:
            return ask('Apply? [y/N] ').strip().lower() in ('y', 'yes'), 'scripted'
        except EOFError:
            return False, 'scripted'
    checks = []
    for s in the_plan['steps']:
        checks.extend(c for c in s['validation']['checked'] if c not in checks)
    return approvals.ask_operator(base, 'b2', 'B2 intent: "%s"' % request,
                                  [describe_step(s, nsot) for s in the_plan['steps']], checks,
                                  answer['interpretation'], timeout)


# ===========================================================================
# Function 4: apply through the controller, then verify on the switch
# ===========================================================================

def rest_post(base, path, body):
    req = urllib.request.Request(base + path, json.dumps(body).encode(), {'Content-Type': 'application/json'})
    return urllib.request.urlopen(req, timeout=10).status


def apply(the_plan, nsot, base):
    """Install/delete each step via REST; read the switch back. Returns
    [(step text, verified True/False)]."""
    done = []
    for s in the_plan['steps']:
        # Step 1: the REST call (same controller path as Part A).
        if s['kind'] == 'install':
            body = nsot_validator.to_flowentry(nsot, s['proposal'])
            rest_post(base, '/stats/flowentry/add', body)
        else:
            r = s['rule']
            body = {'dpid': nsot['switches'][s['switch']]['dpid'], 'table_id': 0, 'cookie': r['cookie'],
                    'cookie_mask': 0xffffffffffffffff, 'priority': r['priority'],
                    'match': nsot_validator.normalize_match(r['match'])}
            rest_post(base, '/stats/flowentry/delete_strict', body)
        events.emit('apply', app='b2', switch=s['switch'], what=describe_step(s, nsot),
                    rest='/stats/flowentry/%s' % ('add' if s['kind'] == 'install' else 'delete_strict'))
        # Step 2: verify: is the rule there (install) / gone (delete)?
        rules = collector.collect_flows(nsot, base, [s['switch']])[s['switch']]
        if s['kind'] == 'install':
            want = nsot_validator.normalize_match(s['proposal']['match'])
            ok = any(r['owner'] == 'ai_intent' and nsot_validator.normalize_match(r['match']) == want for r in rules)
        else:
            ok = not any(r['cookie'] == s['rule']['cookie'] and r['match'] == s['rule']['match'] for r in rules)
        events.emit('verify', app='b2', switch=s['switch'], ok=ok)
        done.append((describe_step(s, nsot), ok))
    return done


# ===========================================================================
# Function 5: one request, start to finish
# ===========================================================================

def handle(text, nsot, base, auto=False, dry_run=False, ask=None, timeout=APPROVAL_TIMEOUT):
    """Returns {'outcome': 'applied'|'declined'|'unclear'|'refused'|'invalid'|'dry_run', ...}."""
    events.emit('run_start', app='b2', request=text)
    try:
        answer = translate(text, nsot)['answer']
    except llm_client.LLMError as e:
        events.emit('refuse', app='b2', why=str(e))
        return {'outcome': 'invalid', 'why': str(e)}
    if answer['status'] == 'unclear':
        events.emit('refuse', app='b2', why='question: ' + answer['question'])
        return {'outcome': 'unclear', 'question': answer['question'], 'answer': answer}
    if answer['status'] == 'refuse':
        events.emit('refuse', app='b2', why=answer['reason'])
        return {'outcome': 'refused', 'why': answer['reason'], 'by': 'model', 'answer': answer}
    the_plan = plan(answer, nsot, base)
    for s in the_plan['steps']:
        events.emit('validate', app='b2', switch=s['switch'], ok=s['validation']['ok'],
                    reasons=s['validation']['errors'] or s['validation']['checked'][-1:])
    if the_plan['refused']:
        events.emit('refuse', app='b2', why='; '.join(the_plan['refused']))
        return {'outcome': 'refused', 'why': '; '.join(the_plan['refused']), 'by': 'code', 'answer': answer,
                'plan': the_plan}
    if dry_run:
        return {'outcome': 'dry_run', 'answer': answer, 'plan': the_plan}
    yes, by = confirm(answer, the_plan, nsot, auto, ask, base, text, timeout)
    if auto or ask is not None:              # approvals.py reports console/terminal answers itself
        events.emit('approval', app='b2', mode='human' if not auto else 'auto-confirm (test)', decision=yes, by=by)
    if not yes:
        return {'outcome': 'declined', 'answer': answer, 'plan': the_plan, 'by': by}
    done = apply(the_plan, nsot, base)
    events.emit('run_end', app='b2', applied=len(done), verified=all(ok for _, ok in done))
    return {'outcome': 'applied', 'answer': answer, 'plan': the_plan, 'done': done, 'by': by}


def list_intents(nsot, base):
    tables = collector.collect_flows(nsot, base, collector.collect_switches(nsot, base)['connected'])
    return [(sw, r) for sw, rules in sorted(tables.items()) for r in rules if r['owner'] == 'ai_intent']


def clear_intents(nsot, base):
    """Delete every intent rule (cookie 0xB0) on every switch."""
    for sw in collector.collect_switches(nsot, base)['connected']:
        rest_post(base, '/stats/flowentry/delete', {'dpid': nsot['switches'][sw]['dpid'], 'table_id': 0,
                                                    'cookie': nsot['ai_policy']['cookies']['intent'],
                                                    'cookie_mask': 0xffffffffffffffff, 'match': {}})


def main():
    ap = argparse.ArgumentParser(description='B2: apply a plain-English policy, after validation and confirmation.')
    ap.add_argument('request', nargs='?', help='e.g. "block pc1 from pinging srv1"')
    ap.add_argument('--controller', help='IP:port of the controller REST API (default: NSOT)')
    ap.add_argument('--yes', action='store_true', help='auto-confirm (scripted tests only)')
    ap.add_argument('--dry-run', action='store_true', help='translate, plan and validate, but do not apply')
    ap.add_argument('--timeout', type=int, default=APPROVAL_TIMEOUT,
                    help='seconds to wait for Approve/Reject (default %d; no answer = no)' % APPROVAL_TIMEOUT)
    ap.add_argument('--list', action='store_true', help='show installed intent rules')
    ap.add_argument('--clear', action='store_true', help='delete every intent rule')
    args = ap.parse_args()
    nsot = collector.load_nsot()
    base = collector.controller_url(nsot, args.controller)
    events.configure(base)
    llm_client.EVENT_HOOK = events.llm_hook
    if args.list:
        for sw, r in list_intents(nsot, base):
            print('%s: priority %s %s -> %s, %d packets, hard_timeout %s s' % (
                sw, r['priority'], r['match'], r['actions'] or 'DROP', r['packets'], r['hard_timeout']))
        return 0
    if args.clear:
        clear_intents(nsot, base)
        print('all intent rules deleted')
        return 0
    if not args.request:
        ap.error('give a request, --list or --clear')
    res = handle(args.request, nsot, base, auto=args.yes, dry_run=args.dry_run, timeout=args.timeout)
    out = res['outcome']
    if out == 'unclear':
        print('Question: %s' % res['question'])
    elif out in ('refused', 'invalid'):
        print('Refused%s: %s' % (' by the validator' if res.get('by') == 'code' else '', res['why']))
    elif out == 'declined':
        print('Not applied (not approved: %s).' % res['by'])
    elif out == 'dry_run':
        print('Dry run: %s' % res['answer']['interpretation'])
        for s in res['plan']['steps']:
            print('  ' + describe_step(s, nsot))
    else:
        for text, ok in res['done']:
            print('%s  %s' % ('VERIFIED' if ok else 'NOT VERIFIED', text))
    return 0 if out in ('applied', 'dry_run') else 1


if __name__ == '__main__':
    sys.exit(main())
