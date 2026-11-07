#!/usr/bin/env python3
"""Lab 9 Part B, Objective B1: AI network analyst (builds on Lab 6).

  collect (REST, all switches) -> prepare evidence -> model -> checked report

1. collector.collect_network_state(): flows, port rates, drop rules, links,
   TCP sensor, through the controller (no model).
2. prepare_evidence(): turn that into a compact, readable picture: MACs and
   IPs replaced by NSOT names, rules summarised, nothing secret.
3. analyze(): one call_llm() with the chosen prompt (prompts/b1_*.md) and the
   report schema. The answer is checked in code: schema, plus every device
   and port it names must exist in the NSOT.
4. Print the report for the engineer; every step is also sent to the console
   (events.py) and the call to the cost log (llm_client).

The prompt was chosen by experiment: b1_experiment.py ran three prompts on the
same snapshots (clean network + planted issues) and scored them.

Usage:
  python3 part_b/b1_analyst.py --controller 100.110.3.67:8080
  python3 part_b/b1_analyst.py --controller 100.110.3.67:8080 --prompt v1_plain --json
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import collector                     # noqa: E402
import events                        # noqa: E402
import llm_client                    # noqa: E402
import nsot_view                     # noqa: E402

PROMPT_DIR = os.path.join(HERE, 'prompts')
BEST_PROMPT = 'v3_checklist'         # chosen by b1_experiment.py run 2 (see docs/BUILD_LOG.md, Step 13)

CATEGORIES = ['link_failure', 'unauthorized_flow', 'drop_rule', 'traffic_flood', 'port_scan',
              'switch_disconnected', 'port_errors', 'other']

# The report the model must return (checked by llm_client before anyone sees it).
SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'required': ['network_health', 'findings', 'summary'],
    'properties': {
        'network_health': {'type': 'string', 'enum': ['healthy', 'degraded', 'critical']},
        'findings': {'type': 'array', 'maxItems': 10, 'items': {
            'type': 'object', 'additionalProperties': False,
            'required': ['category', 'severity', 'device', 'port', 'evidence', 'explanation',
                         'recommended_action'],
            'properties': {
                'category': {'type': 'string', 'enum': CATEGORIES},
                'severity': {'type': 'string', 'enum': ['info', 'warning', 'critical']},
                'device': {'type': 'string', 'maxLength': 40},
                'port': {'type': ['integer', 'null']},
                'evidence': {'type': 'string', 'maxLength': 600},
                'explanation': {'type': 'string', 'maxLength': 900},
                'recommended_action': {'type': 'string', 'maxLength': 600}}}},
        'summary': {'type': 'string', 'maxLength': 1200}}}


# ===========================================================================
# Function 1: the prompt (a file in prompts/, filled from the NSOT)
# ===========================================================================

def load_prompt(variant, nsot):
    """Read prompts/b1_<variant>.md and fill {network} with the NSOT
    description (so no prompt hard-codes a device name)."""
    # Step 1: read the file; Step 2: insert the NSOT-built description.
    with open(os.path.join(PROMPT_DIR, 'b1_%s.md' % variant)) as f:
        return f.read().replace('{network}', nsot_view.describe_network(nsot))


def prompt_variants():
    """Every b1_*.md file name, e.g. ['v1_plain', 'v2_context', 'v3_checklist']."""
    return sorted(f[3:-3] for f in os.listdir(PROMPT_DIR) if f.startswith('b1_') and f.endswith('.md'))


# ===========================================================================
# Function 2: prepare the evidence for the model
# ===========================================================================

def describe_rule(rule, macs, ips):
    """A learned/other rule in words: 'in 2: pc1 -> r1 => push VLAN 10, out 1'."""
    m = rule['match']
    # Step 1: name the addresses (fall back to the raw value).
    name = lambda v, table: table.get(str(v).lower(), v)
    who = []
    if 'dl_src' in m or 'dl_dst' in m:
        who.append('%s -> %s' % (name(m.get('dl_src', 'any'), macs), name(m.get('dl_dst', 'any'), macs)))
    if 'nw_src' in m or 'nw_dst' in m:
        who.append('IP %s -> %s' % (name(m.get('nw_src', 'any'), ips), name(m.get('nw_dst', 'any'), ips)))
    rest = dict((k, v) for k, v in m.items() if k not in ('dl_src', 'dl_dst', 'nw_src', 'nw_dst', 'in_port'))
    # Step 2: in port, who, other match fields, and what it does.
    return '%s%s%s => %s' % ('in %s: ' % m['in_port'] if 'in_port' in m else '', ', '.join(who) or 'any',
                             (' ' + json.dumps(rest, sort_keys=True)) if rest else '',
                             ', '.join(rule['actions']) or 'DROP')


def prepare_evidence(state, nsot):
    """The snapshot as the model sees it: compact, names instead of MACs."""
    macs, ips = nsot_view.mac_names(nsot), nsot_view.ip_names(nsot)
    att = nsot_view.attachments(nsot)
    ev = {'switches': state['switches'],
          'hosts': dict((h, {'ip': nsot_view.host_ip(nsot, h), 'plugs_into': '%s port %d' % (att[h]['switch'], att[h]['port'])
                                                                        if h in att else '?'}) for h in nsot['hosts']),
          'links': [dict((k, l[k]) for k in ('link', 'standby', 'state', 'why', 'learned_rules_using_it'))
                    for l in state['links']],
          'switch_tables': {}, 'ports': {}, 'tcp_sensor_last_60s': {}}
    # Step 1: per switch: rule counts by owner; learned rules in words with
    #         their rate; every other non-standard rule in full.
    for sw, rules in sorted(state['flows'].items()):
        owners = {}
        for r in rules:
            owners[r['owner']] = owners.get(r['owner'], 0) + 1
        table = {'rule_count_by_owner': owners, 'learned_rules': [], 'other_rules': []}
        for r in sorted(rules, key=lambda r: -(r.get('pps') or 0)):
            if r['owner'] == 'learned':
                table['learned_rules'].append('%s  (%s pps)' % (describe_rule(r, macs, ips), r.get('pps')))
            elif r['owner'] not in ('table_miss', 'dns_intercept', 'dhcp_intercept', 'tcp_sensor',
                                    'tcp_sensor_connection') or r['drop']:
                table['other_rules'].append({'owner': r['owner'], 'cookie': r['cookie'], 'priority': r['priority'],
                                             'rule': describe_rule(r, macs, ips), 'drop': r['drop'],
                                             'packets': r['packets'], 'pps': r.get('pps'),
                                             'hard_timeout': r['hard_timeout']})
        table['learned_rules'] = table['learned_rules'][:12]      # busiest first
        ev['switch_tables'][sw] = table
    # Step 2: ports: what they connect to, rates, drops, errors.
    for sw, ports in sorted(state['port_rates'].items()):
        ev['ports'][sw] = dict((p, dict((k, v) for k, v in r.items() if k not in ('rx_total', 'tx_total')))
                               for p, r in sorted(ports.items()) if p != '_seconds')
    # Step 3: TCP sensor, by host name.
    for ip, s in sorted(((state.get('tcp_sensor') or {}).get('sources') or {}).items()):
        ev['tcp_sensor_last_60s'][s['host']] = dict((k, s[k]) for k in ('new_connections', 'distinct_dst_ports',
                                                                         'distinct_dst_hosts', 'dst_hosts',
                                                                         'example_ports'))
    ev['rates_measured_over_seconds'] = state['sample_seconds']
    return ev


# ===========================================================================
# Function 3: the code check on the model's answer
# ===========================================================================

def nsot_check(nsot):
    """Returns extra_check(answer) -> errors: every device must be a switch
    or host in the NSOT, every port must exist on that switch."""
    def check(answer):
        errors = []
        for i, f in enumerate(answer['findings']):
            dev, port = f['device'], f['port']
            if dev in nsot['switches']:
                if port is not None and str(port) not in nsot['switches'][dev]['ports']:
                    errors.append('findings[%d]: %s has no port %s in the NSOT' % (i, dev, port))
            elif dev == 'unknown' and f['category'] == 'other':
                pass             # a device the NSOT does not know (e.g. a stray IP) is worth reporting
            elif dev not in nsot['hosts'] and dev not in nsot.get('routers', {}):
                errors.append('findings[%d]: device "%s" is not in the NSOT (switches: %s); for a device '
                              'the NSOT does not know, use device "unknown" with category "other"'
                              % (i, dev, ', '.join(sorted(nsot['switches']))))
        if answer['network_health'] == 'healthy' and any(f['severity'] != 'info' for f in answer['findings']):
            errors.append('network_health is "healthy" but there are warning/critical findings')
        return errors
    return check


# ===========================================================================
# Function 4: ask the model
# ===========================================================================

def analyze(state, nsot, variant=BEST_PROMPT, reasoning=None):
    """One analysis. Returns {'report', 'calls', 'repaired', 'variant',
    'evidence_chars'}; raises llm_client.LLMError if no valid answer.
    reasoning: None = LAB9_LLM_REASONING from .env, or off/low/medium/high."""
    # Step 1: prompt + evidence.
    evidence = prepare_evidence(state, nsot)
    system = load_prompt(variant, nsot)
    user = 'Live network state, collected %s:\n%s' % (state['collected_at'][:19],
                                                       json.dumps(evidence, indent=1, sort_keys=True))
    # Step 2: the checked call.
    out = llm_client.call_llm('b1_analyst_' + variant, system, user, SCHEMA,
                              extra_check=nsot_check(nsot), max_tokens=12000, reasoning=reasoning)
    return {'report': out['answer'], 'calls': out['calls'], 'repaired': out['repaired'],
            'variant': variant, 'evidence_chars': len(user)}


# ===========================================================================
# Function 5: print the report
# ===========================================================================

def report_lines(report):
    """The report as an engineer reads it."""
    out = ['network health: %s' % report['network_health'].upper(), report['summary'], '']
    order = {'critical': 0, 'warning': 1, 'info': 2}
    for f in sorted(report['findings'], key=lambda f: order[f['severity']]):
        out.append('[%s] %s on %s%s' % (f['severity'].upper(), f['category'], f['device'],
                                        ' port %s' % f['port'] if f['port'] is not None else ''))
        out.append('   evidence: %s' % f['evidence'])
        out.append('   why:      %s' % f['explanation'])
        out.append('   action:   %s' % f['recommended_action'])
    if not report['findings']:
        out.append('no findings')
    return out


def main():
    ap = argparse.ArgumentParser(description='B1: AI analysis of the live network.')
    ap.add_argument('--controller', help='IP:port of the controller REST API (default: NSOT)')
    ap.add_argument('--prompt', default=BEST_PROMPT, help='prompt variant (default %s)' % BEST_PROMPT)
    ap.add_argument('--json', action='store_true', help='print the raw checked report')
    args = ap.parse_args()

    # Step 1: NSOT, controller, event feed.
    nsot = collector.load_nsot()
    base = collector.controller_url(nsot, args.controller)
    events.configure(base)
    llm_client.EVENT_HOOK = events.llm_hook
    events.emit('run_start', app='b1', prompt=args.prompt)

    # Step 2: collect through the controller.
    state = collector.collect_network_state(nsot, base)
    events.emit('collect', app='b1', switches=len(state['switches']['connected']), rest_calls=state['rest_calls'])

    # Step 3: the model, checked.
    try:
        res = analyze(state, nsot, args.prompt)
    except llm_client.LLMError as e:
        events.emit('refuse', app='b1', why=str(e))
        print('no valid analysis: %s' % e)
        return 2
    events.emit('report', app='b1', health=res['report']['network_health'],
                findings=['%s %s on %s' % (f['severity'], f['category'], f['device']) for f in res['report']['findings']])
    events.emit('run_end', app='b1', calls=res['calls'])

    # Step 4: show it.
    print(json.dumps(res['report'], indent=2) if args.json else '\n'.join(report_lines(res['report'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
