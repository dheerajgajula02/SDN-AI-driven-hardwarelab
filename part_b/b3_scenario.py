#!/usr/bin/env python3
"""Lab 9 B3: run the responder while threats are injected on a schedule.

Plans:
  full   AUTO mode, 330 s (>= 5 min), normal background traffic all along,
         and 8 injected threats covering every type, acting on BOTH OVS
         servers and on vendor switches:
           t=15   flood   pc1 -> srv1  (one-way UDP)      arista1 (vendor)
           t=60   scan    vm2 -> srv1  (300 ports)        ovs2 (OVS)
           t=100  rogue   drop rule on hp1, cookie 0x99   hp1 (vendor)
           t=140  link    cut cisco1-arista2 (main link)  restored t=190
           t=210  flood   vm1 -> vm2   (one-way UDP)      ovs1 (OVS)
           t=250  rogue   drop rule on ovs2, cookie 0x98  ovs2 (OVS)
           t=280  scan    pc2 -> srv1  (300 ports)        arista2 (vendor)
           t=300  link    cut the STANDBY link            restored t=320
  hitl   HITL mode, 150 s; a scripted operator answers: yes to the flood,
         NO to the rogue rule, yes to the link check (shows both paths)
  fp     false-positive runs: 5 x 60 s AUTO with only legitimate traffic,
         including a large legitimate TCP transfer (iperf)

After the run every injected threat is scored: detected? how fast? what was
done? cleared? Everything planted is removed at the end (also on error).
Needs network + Ryu, SSHPASS=<mininet password>, lab9/.env.
  python3 part_b/b3_scenario.py --plan full
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

import b3_responder                                 # noqa: E402
import collector                                    # noqa: E402
import events                                       # noqa: E402
import llm_client                                   # noqa: E402
import nsot_view                                    # noqa: E402
from mininet_host import on_host, on_root           # noqa: E402

LOG = []


def note(text):
    line = '[%s] SCENARIO %s' % (time.strftime('%H:%M:%S'), text)
    LOG.append(line)
    print(line)
    sys.stdout.flush()


# ===========================================================================
# Function 1: traffic and threats
# ===========================================================================

def bg(host, cmd, seconds):
    t = threading.Thread(target=lambda: on_host(host, cmd, timeout=seconds + 60))
    t.daemon = True
    t.start()
    return t


def normal_traffic(seconds):
    """Legitimate background traffic for the whole run."""
    loop = 'end=$(($(date +%%s)+%d)); while [ $(date +%%s) -lt $end ]; do %s; sleep %s; done'
    return [bg('srv1', loop % (seconds, 'ping -c 1 -W 1 10.10.10.11 > /dev/null', 2), seconds),
            bg('pc2', loop % (seconds, 'curl -s -m 3 -o /dev/null http://10.10.20.21/', 5), seconds),
            bg('vm2', loop % (seconds, 'nslookup good.lab9.lan 10.10.20.1 > /dev/null', 7), seconds),
            bg('vm1', loop % (seconds, 'ping -c 1 -W 1 10.10.20.32 > /dev/null', 3), seconds)]


def udp_flood(host, dst_ip, seconds):
    """One-way UDP flood (the classic DoS): the victim has nothing on port 9
    and Linux rate-limits its 'port unreachable' replies, so the sender is
    clearly the source. (A ping -f flood is symmetric; see b3_responder.)"""
    return bg(host, "python3 -c \"import socket,time\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
                    "end=time.time()+%d\nwhile time.time()<end:\n s.sendto(b'x'*64,('%s',9))\"" % (seconds, dst_ip),
              seconds)


def scan(host, target='10.10.20.21', ports=300):
    on_host(host, "python3 -c \"import socket\nfor p in range(1,%d):\n s=socket.socket(); s.settimeout(0.2); "
                  "s.connect_ex(('%s',p)); s.close()\"" % (ports + 1, target), timeout=180)


def rogue(nsot, sw, cookie, src, dst):
    return {'dpid': nsot['switches'][sw]['dpid'], 'cookie': cookie, 'priority': 30, 'table_id': 0,
            'match': {'eth_type': 2048, 'ipv4_src': nsot_view.host_ip(nsot, src),
                      'ipv4_dst': nsot_view.host_ip(nsot, dst)}, 'actions': []}


def rest(base, path, body):
    req = urllib.request.Request(base + path, json.dumps(body).encode(), {'Content-Type': 'application/json'})
    return urllib.request.urlopen(req, timeout=10).status


def cleanup(nsot, base):
    on_root('ip link set cisco1-eth3 up; ip link set arista2-eth1 up; ip link set arista2-eth4 up; '
            'pkill -f "ping -f"; pkill -f "iperf"; pkill -f SOCK_DGRAM; true')
    for sw, cookie in (('hp1', 0x99), ('ovs2', 0x98)):
        try:
            rest(base, '/stats/flowentry/delete', {'dpid': nsot['switches'][sw]['dpid'], 'table_id': 0,
                                                   'cookie': cookie, 'cookie_mask': 0xffffffffffffffff, 'match': {}})
        except Exception:
            pass
    resp = nsot['ai_policy']['cookies']['response']
    for sw, s in nsot['switches'].items():
        try:
            rest(base, '/stats/flowentry/delete', {'dpid': s['dpid'], 'table_id': 0, 'cookie': resp,
                                                   'cookie_mask': 0xffffffffffffffff, 'match': {}})
        except Exception:
            pass


# ===========================================================================
# Function 2: the schedules
# ===========================================================================

def full_schedule(nsot, base):
    return [
        (15, 'UDP flood pc1 -> srv1 (25 s)', 'traffic_flood', 'pc1',
         lambda: udp_flood('pc1', '10.10.20.21', 25)),
        (60, 'port scan vm2 -> srv1 (300 ports)', 'port_scan', 'vm2', lambda: scan('vm2')),
        (100, 'rogue drop rule on hp1 (cookie 0x99, pc2 -> srv1)', 'unauthorized_flow', 'hp1',
         lambda: rest(base, '/stats/flowentry/add', rogue(nsot, 'hp1', 0x99, 'pc2', 'srv1'))),
        (140, 'cut main link cisco1-arista2', 'link_failure', 'cisco1:3-arista2:1',
         lambda: on_root('ip link set cisco1-eth3 down; ip link set arista2-eth1 down')),
        (190, 'restore cisco1-arista2', None, None,
         lambda: on_root('ip link set cisco1-eth3 up; ip link set arista2-eth1 up')),
        (210, 'UDP flood vm1 -> vm2 (25 s)', 'traffic_flood', 'vm1',
         lambda: udp_flood('vm1', '10.10.20.32', 25)),
        (250, 'rogue drop rule on ovs2 (cookie 0x98, vm2 -> srv1)', 'unauthorized_flow', 'ovs2',
         lambda: rest(base, '/stats/flowentry/add', rogue(nsot, 'ovs2', 0x98, 'vm2', 'srv1'))),
        (280, 'port scan pc2 -> srv1 (300 ports)', 'port_scan', 'pc2', lambda: scan('pc2')),
        (300, 'cut the STANDBY link arista1-arista2', 'link_failure', 'arista1:4-arista2:4',
         lambda: on_root('ip link set arista2-eth4 down')),
        (320, 'restore the standby link', None, None, lambda: on_root('ip link set arista2-eth4 up')),
    ]


def hitl_schedule(nsot, base):
    return [
        (10, 'UDP flood pc1 -> srv1 (25 s)', 'traffic_flood', 'pc1',
         lambda: udp_flood('pc1', '10.10.20.21', 25)),
        (55, 'rogue drop rule on hp1 (cookie 0x99)', 'unauthorized_flow', 'hp1',
         lambda: rest(base, '/stats/flowentry/add', rogue(nsot, 'hp1', 0x99, 'pc2', 'srv1'))),
        (95, 'cut main link cisco1-arista2', 'link_failure', 'cisco1:3-arista2:1',
         lambda: on_root('ip link set cisco1-eth3 down; ip link set arista2-eth1 down')),
        (130, 'restore cisco1-arista2', None, None,
         lambda: on_root('ip link set cisco1-eth3 up; ip link set arista2-eth1 up')),
    ]


def scripted_operator(question):
    """HITL demo operator: yes to floods and link checks, NO to the rogue rule."""
    answer = 'unauthorized_flow' not in question
    note('operator asked "%s" -> %s' % (question, 'YES' if answer else 'NO'))
    return answer


# ===========================================================================
# Function 3: run a plan, then score it
# ===========================================================================

def run_plan(nsot, base, mode, duration, schedule, ask=None, tag=''):
    stop = threading.Event()
    log_dir = os.path.join(HERE, '..', 'logs', 'b3_runs', time.strftime('%Y%m%d_%H%M%S_') + tag)
    r = b3_responder.Responder(nsot, base, mode, ask=ask, log_dir=log_dir)
    th = threading.Thread(target=lambda: r.run(duration, stop_event=stop))
    th.start()
    t0 = time.time()
    normal_traffic(duration)
    injected = []
    try:
        for at, what, gate, target, action in schedule:
            time.sleep(max(0, t0 + at - time.time()))
            note('t=%3ds INJECT %s' % (time.time() - t0, what))
            action()
            if gate:
                injected.append({'at': time.time(), 'what': what, 'gate': gate, 'target': target})
        th.join()
    finally:
        stop.set()
        th.join(30)
        cleanup(nsot, base)
    return r, injected, log_dir


def score(r, injected, log_dir):
    rows = [json.loads(l) for l in open(os.path.join(log_dir, 'responses.jsonl'))] \
        if os.path.exists(os.path.join(log_dir, 'responses.jsonl')) else []
    out = []
    for inj in injected:
        inc = [i for k, i in r.incidents.items() if i['gate'] == inj['gate'] and
               (i['target'] == inj['target'] or inj['target'] in k)]
        inc = inc[0] if inc else None
        applied = [x for x in rows if x.get('event') == 'applied' and inc and x['key'] == inc['key']]
        out.append({'threat': inj['what'], 'detected': bool(inc),
                    'seconds_to_detect': round(inc['first_seen'] - inj['at'], 1) if inc else None,
                    'status': inc and inc.get('status_before_clear', inc['status']),
                    'model': inc and inc.get('model', {}).get('threat_type'),
                    'action': applied[0]['steps'] if applied else None,
                    'cleared': bool(inc and inc['status'] == 'cleared')})
    unexpected = [k for k, i in r.incidents.items()
                  if not any(i['gate'] == x['gate'] and (i['target'] == x['target'] or x['target'] in k)
                             for x in injected)]
    return out, unexpected


def print_score(out, unexpected, r):
    print('\n%-52s %-8s %-7s %-10s %-18s %s' % ('injected threat', 'detected', 'secs', 'model', 'outcome', 'action'))
    for o in out:
        print('%-52s %-8s %-7s %-10s %-18s %s' % (o['threat'][:52], o['detected'], o['seconds_to_detect'],
                                                  o['model'], o['status'], '; '.join(o['action'] or [])[:90]))
    print('incidents not caused by an injected threat (false positives): %s' % (unexpected or 'none'))
    print('responder stats: %s' % json.dumps(r.stats))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plan', choices=['full', 'hitl', 'fp'], default='full')
    ap.add_argument('--controller', default='100.110.3.67:8080')
    args = ap.parse_args()
    nsot = collector.load_nsot()
    base = collector.controller_url(nsot, args.controller)
    events.configure(base)
    llm_client.EVENT_HOOK = events.llm_hook
    cleanup(nsot, base)

    if args.plan == 'full':
        r, inj, d = run_plan(nsot, base, 'auto', 330, full_schedule(nsot, base), tag='full_auto')
        out, unexpected = score(r, inj, d)
        print_score(out, unexpected, r)
        json.dump({'score': out, 'unexpected': unexpected, 'stats': r.stats, 'scenario_log': LOG},
                  open(os.path.join(d, 'scenario_score.json'), 'w'), indent=1)
    elif args.plan == 'hitl':
        r, inj, d = run_plan(nsot, base, 'hitl', 150, hitl_schedule(nsot, base), ask=scripted_operator, tag='hitl')
        out, unexpected = score(r, inj, d)
        print_score(out, unexpected, r)
        json.dump({'score': out, 'unexpected': unexpected, 'stats': r.stats, 'scenario_log': LOG},
                  open(os.path.join(d, 'scenario_score.json'), 'w'), indent=1)
    else:
        mixes = [
            ('light: pings, web, DNS', []),
            ('busy web: 4 hosts fetching pages every second', [
                (2, 'web from 4 hosts', None, None, lambda: [bg(h, 'for i in $(seq 50); do curl -s -m 2 -o /dev/null '
                                                                  'http://10.10.20.21/; sleep 1; done', 55)
                                                             for h in ('pc1', 'pc2', 'vm1', 'vm2')])]),
            ('large legitimate TCP transfer (iperf pc1 -> srv1, 30 s)', [
                (2, 'iperf server on srv1', None, None, lambda: bg('srv1', 'timeout 50 iperf -s', 50)),
                (5, 'iperf pc1 -> srv1', None, None, lambda: bg('pc1', 'iperf -c 10.10.20.21 -t 30', 35))]),
            ('DNS burst: 60 lookups from 3 hosts', [
                (2, 'DNS burst', None, None, lambda: [bg(h, 'for i in $(seq 60); do nslookup host$i.lab9.lan %s '
                                                            '> /dev/null; done' % gw, 55)
                                                      for h, gw in (('pc1', '10.10.10.1'), ('vm1', '10.10.20.1'),
                                                                    ('srv1', '10.10.20.1'))])]),
            ('monitoring host pinging every host each second', [
                (2, 'ping sweep (legit monitoring)', None, None, lambda: bg('srv1', 'for i in $(seq 50); do for ip in '
                                                                             '10.10.10.11 10.10.20.31 10.10.20.32 '
                                                                             '203.0.113.2; do ping -c 1 -W 1 $ip '
                                                                             '> /dev/null; done; sleep 1; done', 55))]),
        ]
        summary = []
        for i, (name, sched) in enumerate(mixes, 1):
            note('FP run %d/5: %s' % (i, name))
            r, inj, d = run_plan(nsot, base, 'auto', 60, sched, tag='fp%d' % i)
            rows = [json.loads(l) for l in open(os.path.join(d, 'responses.jsonl'))] \
                if os.path.exists(os.path.join(d, 'responses.jsonl')) else []
            summary.append({'run': i, 'traffic': name, 'detector_triggers': r.stats['incidents'],
                            'actions': r.stats['actions'], 'disagreements': r.stats['disagreements'],
                            'model_calls': r.stats.get('model_calls'),
                            'events': [{'event': x['event'], 'key': x.get('key'),
                                        'model': (x.get('model') or {}).get('threat_type'),
                                        'why': (x.get('model') or {}).get('explanation', '')[:200]} for x in rows]})
            time.sleep(10)
        print('\nrun  traffic                                              triggers  actions  model said "not a threat"')
        for s in summary:
            print('%3d  %-52s %8d  %7d  %d' % (s['run'], s['traffic'][:52], s['detector_triggers'], s['actions'],
                                              s['disagreements']))
        out = os.path.join(HERE, '..', 'logs', 'b3_runs', 'fp_summary.json')
        json.dump({'runs': summary, 'scenario_log': LOG}, open(out, 'w'), indent=1)
    return 0


if __name__ == '__main__':
    sys.exit(main())
