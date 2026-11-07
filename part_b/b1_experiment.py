#!/usr/bin/env python3
"""Lab 9 B1: plant issues, run every prompt on the SAME snapshots, score them.

Scenarios (each captured once, then given to every prompt variant):
  clean_1, clean_2     normal traffic only (pings, a web page, DNS): any
                       warning/critical finding is a FALSE ALARM
  planted_1, planted_2 four planted issues the model is NOT told about:
     I1 redundant link failure   the standby link arista1:4-arista2:4 cut
     I2 rogue drop rule          cookie 0x99 on hp1 silently drops pc1 -> srv1
     I3 traffic flood            ping -f from pc2 to srv1
     I4 port scan                vm1 opens connections to 300 ports on srv1

Scoring per analysis:
  found       a warning/critical finding with the right category on a
              plausible device
  downplayed  only an "info" finding for it
  missed      nothing about it
  false alarm a warning/critical finding that matches no planted issue

Everything planted is removed afterwards (also on error).
Needs: network + Ryu running, SSHPASS=<mininet password>, lab9/.env.
  python3 part_b/b1_experiment.py --controller 100.110.3.67:8080
"""

import argparse
import json
import os
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', 'applications', 'tests'))

import b1_analyst                                   # noqa: E402
import collector                                    # noqa: E402
import events                                       # noqa: E402
import llm_client                                   # noqa: E402
import nsot_view                                    # noqa: E402
from mininet_host import on_host, on_root           # noqa: E402

OUT = os.path.join(HERE, '..', 'logs', 'stepB1_analyst')

# What was planted, and what counts as finding it.
TRUTH = [
    {'id': 'I1', 'name': 'redundant (standby) link arista1:4-arista2:4 down',
     'categories': ['link_failure'], 'devices': ['arista1', 'arista2']},
    {'id': 'I2', 'name': 'rogue drop rule (cookie 0x99) on hp1: pc1 -> srv1',
     'categories': ['unauthorized_flow', 'drop_rule'], 'devices': ['hp1']},
    {'id': 'I3', 'name': 'ping flood from pc2 to srv1',
     'categories': ['traffic_flood'], 'devices': ['pc2', 'arista2', 'cisco1', 'hp1', 'srv1', 'r1']},
    {'id': 'I4', 'name': 'port scan from vm1 to srv1 (300 ports)',
     'categories': ['port_scan'], 'devices': ['vm1', 'ovs1', 'arista1', 'cisco1', 'hp1', 'srv1']},
]


# ===========================================================================
# Function 1: plant and remove the issues
# ===========================================================================

def rogue_rule(nsot):
    """The planted unauthorized drop rule (REST body for /stats/flowentry)."""
    return {'dpid': nsot['switches']['hp1']['dpid'], 'cookie': 0x99, 'priority': 30, 'table_id': 0,
            'match': {'eth_type': 2048, 'ipv4_src': nsot_view.host_ip(nsot, 'pc1'),
                      'ipv4_dst': nsot_view.host_ip(nsot, 'srv1')}, 'actions': []}


def rest_post(base, path, body):
    req = urllib.request.Request(base + path, json.dumps(body).encode(), {'Content-Type': 'application/json'})
    return urllib.request.urlopen(req, timeout=10).status


def background(host, cmd, seconds):
    """Run a command in a host in a thread (returns the thread)."""
    t = threading.Thread(target=lambda: on_host(host, cmd, timeout=seconds + 30))
    t.daemon = True
    t.start()
    return t


def normal_traffic(seconds):
    """What a healthy lab looks like: light pings, a web page, a DNS lookup."""
    return [background('pc1', 'ping -q -i 0.3 -w %d 10.10.20.21' % seconds, seconds),
            background('vm2', 'ping -q -i 0.5 -w %d 10.10.20.31' % seconds, seconds),
            background('pc2', 'curl -s -m 5 -o /dev/null http://10.10.20.21/; nslookup example.com 10.10.10.1', seconds)]


def plant(nsot, base, seconds):
    """Plant I1-I4; returns the background threads."""
    on_root('ip link set arista2-eth4 down')                                   # I1
    rest_post(base, '/stats/flowentry/add', rogue_rule(nsot))                  # I2
    scan = ("python3 -c \"import socket\nfor p in range(1,301):\n s=socket.socket(); s.settimeout(0.3); "
            "s.connect_ex(('10.10.20.21',p)); s.close()\"")
    on_host('vm1', scan, timeout=120)                                          # I4 (finishes first)
    time.sleep(3)
    return [background('pc2', 'ping -f -q -w %d 10.10.20.21' % seconds, seconds)]   # I3


def unplant(nsot, base):
    on_root('ip link set arista2-eth4 up; pkill -f "ping -f" ; true')
    try:
        rest_post(base, '/stats/flowentry/delete_strict', rogue_rule(nsot))
    except Exception as e:
        print('could not remove the rogue rule: %s' % e)


# ===========================================================================
# Function 2: score one report against the truth
# ===========================================================================

def score(report, truth):
    """Match findings to planted issues. Returns {found, downplayed, missed,
    false_alarms: [finding], per_issue: {id: 'found'|'downplayed'|'missed'}}."""
    per_issue = dict((t['id'], 'missed') for t in truth)
    false_alarms = []
    for f in report['findings']:
        match = [t for t in truth if f['category'] in t['categories'] and f['device'] in t['devices']]
        if match:
            t = match[0]
            if f['severity'] == 'info':
                if per_issue[t['id']] == 'missed':
                    per_issue[t['id']] = 'downplayed'
            else:
                per_issue[t['id']] = 'found'
        elif f['severity'] != 'info':
            false_alarms.append('%s %s on %s: %s' % (f['severity'], f['category'], f['device'], f['evidence'][:120]))
    count = lambda v: sum(1 for x in per_issue.values() if x == v)
    return {'found': count('found'), 'downplayed': count('downplayed'), 'missed': count('missed'),
            'false_alarms': false_alarms, 'per_issue': per_issue}


# ===========================================================================
# Function 3: the experiment
# ===========================================================================

def log_lines():
    """Lines in the cost log now (to sum the cost of what follows)."""
    f = llm_client.LOG_FILE
    return sum(1 for _ in open(f)) if os.path.exists(f) else 0


def cost_since(n):
    with open(llm_client.LOG_FILE) as f:
        rows = [json.loads(l) for l in f.read().splitlines()[n:]]
    return round(sum(r.get('cost_usd') or 0 for r in rows), 6)


def capture(nsot, base, name, planted):
    """One snapshot under the scenario's traffic. Saved to logs."""
    print('capturing %s ...' % name)
    threads = normal_traffic(25)
    if planted:
        threads += plant(nsot, base, 25)
    time.sleep(4)                                     # let rates settle
    state = collector.collect_network_state(nsot, base, 3.0)
    for t in threads:
        t.join()
    with open(os.path.join(OUT, 'snapshot_%s.json' % name), 'w') as f:
        json.dump(state, f, indent=1)
    return state


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--controller', default='100.110.3.67:8080')
    ap.add_argument('--variants', default=','.join(b1_analyst.prompt_variants()))
    ap.add_argument('--reasoning', default='off,low', help='reasoning levels to compare')
    ap.add_argument('--reuse', help='folder with snapshot_*.json to analyse instead of capturing')
    args = ap.parse_args()
    if not os.path.isdir(OUT):
        os.makedirs(OUT)
    nsot = collector.load_nsot()
    base = collector.controller_url(nsot, args.controller)
    events.configure(base)
    llm_client.EVENT_HOOK = events.llm_hook
    variants = args.variants.split(',')

    # Step 1: the four snapshots (clean first: the scan must not be in the
    #         sensor's 60 s window yet). Planted issues removed even on error.
    #         --reuse DIR analyses snapshots captured earlier instead.
    snaps = {}
    if args.reuse:
        for name in ('clean_1', 'clean_2', 'planted_1', 'planted_2'):
            with open(os.path.join(args.reuse, 'snapshot_%s.json' % name)) as f:
                snaps[name] = json.load(f)
    else:
        try:
            for name in ('clean_1', 'clean_2'):
                snaps[name] = capture(nsot, base, name, planted=False)
                time.sleep(5)
            for name in ('planted_1', 'planted_2'):
                snaps[name] = capture(nsot, base, name, planted=True)
                unplant(nsot, base)
                time.sleep(70)                        # let the scan leave the 60 s window
        finally:
            unplant(nsot, base)

    # Step 2: every (prompt, reasoning level) on every snapshot.
    combos = ['%s/%s' % (v, r) for v in variants for r in args.reasoning.split(',')]
    results = []
    for name, state in sorted(snaps.items()):
        for combo in combos:
            v, level = combo.split('/')
            events.emit('run_start', app='b1', prompt=combo, scenario=name)
            before = log_lines()
            started = time.time()
            try:
                res = b1_analyst.analyze(state, nsot, v, reasoning=level)
            except llm_client.LLMError as e:
                results.append({'scenario': name, 'combo': combo, 'error': str(e), 'cost': cost_since(before),
                                'seconds': round(time.time() - started, 1)})
                print('%-10s %-22s INVALID: %s' % (name, combo, str(e)[:110]))
                continue
            truth = TRUTH if name.startswith('planted') else []
            sc = score(res['report'], truth)
            row = {'scenario': name, 'combo': combo, 'calls': res['calls'], 'repaired': res['repaired'],
                   'evidence_chars': res['evidence_chars'], 'report': res['report'], 'score': sc,
                   'cost': cost_since(before), 'seconds': round(time.time() - started, 1)}
            results.append(row)
            events.emit('report', app='b1', prompt=combo, scenario=name, health=res['report']['network_health'],
                        found=sc['found'], missed=sc['missed'], false_alarms=len(sc['false_alarms']))
            print('%-10s %-22s health=%-9s found %d/%d  downplayed %d  missed %d  false alarms %d  calls %d  %5.1fs'
                  % (name, combo, res['report']['network_health'], sc['found'], len(truth), sc['downplayed'],
                     sc['missed'], len(sc['false_alarms']), res['calls'], row['seconds']))
    with open(os.path.join(OUT, 'experiment_results.json'), 'w') as f:
        json.dump(results, f, indent=1)

    # Step 3: totals per combination -> the best one.
    print('\n%-22s found  missed  downplayed  false_alarms  invalid  calls    cost   avg s' % 'prompt/reasoning')
    totals = {}
    for c in combos:
        rows = [r for r in results if r['combo'] == c]
        ok = [r for r in rows if 'score' in r]
        t = {'found': sum(r['score']['found'] for r in ok), 'missed': sum(r['score']['missed'] for r in ok),
             'downplayed': sum(r['score']['downplayed'] for r in ok),
             'false_alarms': sum(len(r['score']['false_alarms']) for r in ok),
             'invalid': len(rows) - len(ok), 'calls': sum(r.get('calls', 0) for r in ok),
             'cost': round(sum(r['cost'] for r in rows), 6),
             'avg_seconds': round(sum(r['seconds'] for r in rows) / max(1, len(rows)), 1)}
        totals[c] = t
        print('%-22s %5d  %6d  %10d  %12d  %7d  %5d  $%.4f  %5.1f' % (
            c, t['found'], t['missed'], t['downplayed'], t['false_alarms'], t['invalid'], t['calls'], t['cost'],
            t['avg_seconds']))
    best = sorted(combos, key=lambda c: (totals[c]['invalid'] + totals[c]['missed'] + totals[c]['downplayed'],
                                         totals[c]['false_alarms'], -totals[c]['found'], totals[c]['cost']))[0]
    print('\nbest prompt/reasoning: %s' % best)
    with open(os.path.join(OUT, 'experiment_totals.json'), 'w') as f:
        json.dump({'totals': totals, 'best': best, 'truth': TRUTH}, f, indent=1)
    return 0


if __name__ == '__main__':
    sys.exit(main())
