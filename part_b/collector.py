#!/usr/bin/env python3
"""Lab 9 Part B, step 1: collect live network state through the controller.

B1 asks for "flow tables, port statistics/rates, drop rules, and link status"
from the hardware devices. Labs 6 and 8 read those with ssh + ovs-ofctl,
which only works on Open vSwitch. This collector reads everything through the
controller's REST API (Ryu ofctl_rest on port 8080), so the same code works
for the Arista, HP and Cisco switches: they all speak OpenFlow to Ryu.

  GET /stats/switches          which switches are connected
  GET /stats/flow/<dpid>       flow table (each rule tagged with its owner)
  GET /stats/port/<dpid>       port counters (read twice -> packets/second)
  GET /stats/portdesc/<dpid>   port up/down

Everything else (names, wiring, which links are standby, who owns which
cookie) comes from the NSOT. No model is called here.

Usage (laptop, any Python 3.5+; standard library only):
  python3 part_b/collector.py --controller 100.110.3.67:8080
  python3 part_b/collector.py --controller 100.110.3.67:8080 --json > state.json
"""

import argparse
import json
import os
import sys
import time
import urllib.request
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
NSOT_PATH = os.environ.get('LAB9_NSOT', os.path.join(HERE, '..', 'part_a', 'nsot.json'))

# OpenFlow 1.3 bits in /stats/portdesc
OFPPS_LINK_DOWN = 1      # port state: no carrier (cable cut, far end down)
OFPPC_PORT_DOWN = 1      # port config: administratively shut


# ===========================================================================
# Function 1: read the NSOT and find the controller
# ===========================================================================

def load_nsot(path=NSOT_PATH):
    """The NSOT is the only place names, DPIDs and wiring come from.
    Path: LAB9_NSOT if set, else ../part_a/nsot.json."""
    # Step 1: open the file and parse the JSON (a broken file fails loudly here).
    with open(path) as f:
        return json.load(f)


def controller_url(nsot, override=None):
    """'http://ip:port' of the controller REST API.
    Order: --controller, then LAB9_CONTROLLER, then the NSOT."""
    # Step 1: an address given on the command line or in the environment wins
    #         (the laptop reaches the controller over Tailscale, not the LAN IP).
    addr = override or os.environ.get('LAB9_CONTROLLER')
    # Step 2: otherwise use the controller IP and REST port from the NSOT.
    if not addr:
        c = nsot['controller']
        addr = '%s:%s' % (c['ip'], c['rest_port'])
    # Step 3: make sure it is a full URL.
    return addr if addr.startswith('http') else 'http://' + addr


# ===========================================================================
# Function 2: one REST call
# ===========================================================================

def rest_get(base, path, timeout=5):
    """GET base+path and return the parsed JSON.
    A switch that does not answer within `timeout` seconds raises an error
    instead of hanging the collector."""
    # Step 1: send the request; Step 2: decode the bytes to text first
    #         (Python 3.5's json.loads needs a str), then parse the JSON.
    with urllib.request.urlopen(base + path, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8'))


# ===========================================================================
# Function 3: who is connected?
# ===========================================================================

def collect_switches(nsot, base):
    """Compare the controller's connected DPIDs with the NSOT.

    Returns {'connected': [names], 'missing': [names in the NSOT but not
    connected], 'unknown_dpids': [connected but not in the NSOT]}."""
    # Step 1: what the controller sees right now.
    connected = set(int(d) for d in rest_get(base, '/stats/switches'))
    # Step 2: what the NSOT says should be there.
    by_dpid = dict((sw['dpid'], name) for name, sw in nsot['switches'].items())
    # Step 3: the differences are the findings.
    return {
        'connected': sorted(by_dpid[d] for d in connected if d in by_dpid),
        'missing': sorted(name for d, name in by_dpid.items() if d not in connected),
        'unknown_dpids': sorted(d for d in connected if d not in by_dpid),
    }


# ===========================================================================
# Function 4: flow tables, each rule tagged with its owner
# ===========================================================================

def flow_owner(nsot, cookie):
    """The app that owns a cookie (NSOT flow_cookies), or 'unauthorized'.
    Every Lab 9 app stamps its rules with its own cookie, e.g. DNS = 48."""
    # Step 1: look the cookie up in the NSOT (keys are text, e.g. "48").
    # Step 2: a cookie no app uses means no app installed the rule.
    return nsot.get('flow_cookies', {}).get(str(cookie), 'unauthorized')


def is_drop(rule):
    """A drop rule has no actions at all (Ryu shows [] or ['DROP'])."""
    # Step 1: OpenFlow has no "drop" action; an empty action list means drop.
    return rule.get('actions') in ([], ['DROP'], 'DROP')


def rule_key(rule):
    """A stable id for a rule across two readings: priority + cookie + match.
    Used to pair the same rule in reading 1 and reading 2."""
    # Step 1: OpenFlow identifies a rule by priority + match; the cookie is
    #         added so two apps' rules can never be confused. sort_keys makes
    #         the text the same however the fields are ordered.
    return '%s|%s|%s' % (rule.get('priority'), rule.get('cookie'),
                         json.dumps(rule.get('match', {}), sort_keys=True))


def collect_flows(nsot, base, names):
    """Read every connected switch's flow table.

    Returns {switch: [ {priority, cookie, owner, match, actions, drop,
                        packets, bytes, age_s, idle_timeout, hard_timeout} ]}"""
    tables = {}
    for name in names:
        # Step 0: the switch's name -> its DPID (from the NSOT).
        dpid = nsot['switches'][name]['dpid']
        # Step 1: the switch's real table, as the controller reports it.
        raw = rest_get(base, '/stats/flow/%d' % dpid).get(str(dpid), [])
        # Step 2: keep what an engineer (or a model) needs, plus the owner.
        tables[name] = [{
            'priority': r.get('priority'),
            'cookie': r.get('cookie'),
            'owner': flow_owner(nsot, r.get('cookie')),
            'match': r.get('match', {}),
            'actions': r.get('actions', []),
            'drop': is_drop(r),
            'packets': r.get('packet_count', 0),
            'bytes': r.get('byte_count', 0),
            'age_s': r.get('duration_sec', 0),
            'idle_timeout': r.get('idle_timeout', 0),
            'hard_timeout': r.get('hard_timeout', 0),
        } for r in raw]
    return tables


# ===========================================================================
# Function 5: port counters, read twice -> rates
# ===========================================================================

def read_ports(nsot, base, names):
    """One reading of every switch's port counters.
    Returns ({switch: {port: counters}}, {switch: time of the reading})."""
    counters, when = {}, {}
    for name in names:
        dpid = nsot['switches'][name]['dpid']
        start = time.monotonic()
        raw = rest_get(base, '/stats/port/%d' % dpid).get(str(dpid), [])
        # Step 1: the moment of the reading = middle of the REST call.
        when[name] = (start + time.monotonic()) / 2
        # Step 2: numbered ports only (skip the internal LOCAL port).
        counters[name] = dict((str(p['port_no']), p) for p in raw if str(p['port_no']).isdigit())
    return counters, when


def port_rates(first, second, t1, t2, nsot):
    """Packets per second on every port, from two readings.

    Each switch uses its own measured time gap. A port missing from one
    reading, or a counter that went backwards (reset), is reported as
    'invalid' with a reason, never as zero traffic (same rule as Lab 8)."""
    rates = {}
    for name in second:
        # Step 1: the real time between this switch's two readings (not just
        #         the 2 s sleep: the REST calls themselves take time).
        gap = t2[name] - t1[name]
        rates[name] = {}
        for port, b in second[name].items():
            a = first.get(name, {}).get(port)
            # Step 2: what the port is wired to, from the NSOT (e.g. "pc1").
            row = {'to': nsot['switches'][name]['ports'].get(port, {}).get('to', '?')}
            # Step 3: refuse bad samples instead of reporting a false 0.
            if a is None or gap <= 0:
                row.update(valid=False, reason='port missing from the first reading')
            elif b['rx_packets'] < a['rx_packets'] or b['tx_packets'] < a['tx_packets']:
                row.update(valid=False, reason='counter reset')
            else:
                # Step 4: rate = (counter now - counter before) / seconds.
                #         Dropped and error counts are the increase too.
                row.update(valid=True,
                           rx_pps=round((b['rx_packets'] - a['rx_packets']) / gap, 1),
                           tx_pps=round((b['tx_packets'] - a['tx_packets']) / gap, 1),
                           rx_dropped=b['rx_dropped'] - a['rx_dropped'],
                           tx_dropped=b['tx_dropped'] - a['tx_dropped'],
                           errors=(b['rx_errors'] - a['rx_errors']) + (b['tx_errors'] - a['tx_errors']))
            # Step 5: keep the raw totals too, so the arithmetic can be checked.
            row['rx_total'], row['tx_total'] = b['rx_packets'], b['tx_packets']
            rates[name][port] = row
        rates[name]['_seconds'] = round(gap, 2)
    return rates


def flow_rates(first, second, seconds):
    """Packets per second on every rule that was there in both readings.
    This names WHO is sending (e.g. one source MAC), not just which port."""
    for name, rules in second.items():
        # Step 1: each rule's packet count in the first reading, by rule_key.
        before = dict((rule_key(r), r['packets']) for r in first.get(name, []))
        for r in rules:
            # Step 2: same rule in both readings -> (now - before) / seconds.
            #         A rule that is new (not in reading 1) gets None, not 0.
            old = before.get(rule_key(r))
            r['pps'] = None if old is None or seconds[name] <= 0 \
                else round(max(0, r['packets'] - old) / seconds[name], 1)
    return second


# ===========================================================================
# Function 6: link status for every NSOT link
# ===========================================================================

def nsot_links(nsot):
    """Every switch-to-switch cable in the NSOT, once:
    [(sw_a, port_a, sw_b, port_b, standby)]."""
    links, seen = [], set()
    for name, sw in nsot['switches'].items():
        for port, p in sw['ports'].items():
            # Step 1: a port whose "to" is "<switch>:<port>" is a cable to
            #         another switch; "pc1" or "r1" is a host or the router.
            peer = p.get('to', '')
            if ':' not in peer or peer.split(':')[0] not in nsot['switches']:
                continue                     # a host or the router, not a link
            # Step 2: each cable appears at both of its ends in the NSOT;
            #         keep it once (the sorted pair of ends is its id).
            peer_sw, peer_port = peer.split(':')
            key = tuple(sorted([(name, port), (peer_sw, peer_port)]))
            if key not in seen:
                seen.add(key)
                links.append((name, port, peer_sw, peer_port, bool(p.get('standby'))))
    return links


def collect_links(nsot, base, names, tables):
    """Up/down state of every NSOT link, read from both ends.

    Returns [{link, a, b, standby, state: up|down|unknown, why, carrying}]
    and every port's own state ({switch: {port: up|down}})."""
    # Step 1: each connected switch's port states.
    ports = {}
    for name in names:
        dpid = nsot['switches'][name]['dpid']
        ports[name] = {}
        for p in rest_get(base, '/stats/portdesc/%d' % dpid).get(str(dpid), []):
            if str(p['port_no']).isdigit():
                down = (p['state'] & OFPPS_LINK_DOWN) or (p['config'] & OFPPC_PORT_DOWN)
                ports[name][str(p['port_no'])] = 'down' if down else 'up'

    # Step 2: a link is down if either end is down or missing.
    result = []
    for a, pa, b, pb, standby in nsot_links(nsot):
        ends = [ports.get(a, {}).get(pa), ports.get(b, {}).get(pb)]
        if a not in ports or b not in ports:
            state, why = 'unknown', 'a switch on this link is not connected'
        elif 'down' in ends or None in ends:
            state = 'down'
            why = ', '.join('%s port %s %s' % (s, p, e or 'missing')
                            for (s, p), e in zip([(a, pa), (b, pb)], ends) if e != 'up')
        else:
            state, why = 'up', ''
        # Step 3: is traffic actually forwarded onto this link? (any learned
        # rule outputting on either end). A standby link should carry
        # nothing while the main path is up.
        carrying = sum(1 for s, p in ((a, pa), (b, pb)) for r in tables.get(s, [])
                       if r['owner'] == 'learned' and ('OUTPUT:%s' % p) in r['actions'])
        result.append({'link': '%s:%s-%s:%s' % (a, pa, b, pb), 'a': a, 'b': b,
                       'standby': standby, 'state': state, 'why': why,
                       'learned_rules_using_it': carrying})
    return result, ports


# ===========================================================================
# Function 7: everything in one snapshot
# ===========================================================================

def collect_network_state(nsot, base, sample_seconds=2.0):
    """One snapshot of the whole network (what B1's model will read).

    Flows and port counters are read twice, sample_seconds apart, so rates
    are real measurements. ~4 REST calls per switch per reading."""
    if sample_seconds <= 0:
        raise ValueError('sample_seconds must be positive')
    started = datetime.now()

    # Step 1: who is there.
    switches = collect_switches(nsot, base)
    names = switches['connected']

    # Step 2: first reading, wait, second reading.
    flows1 = collect_flows(nsot, base, names)
    ports1, t1 = read_ports(nsot, base, names)
    time.sleep(sample_seconds)
    flows2 = collect_flows(nsot, base, names)
    ports2, t2 = read_ports(nsot, base, names)

    # Step 3: rates, drop rules, link state.
    rates = port_rates(ports1, ports2, t1, t2, nsot)
    seconds = dict((n, rates[n]['_seconds']) for n in names)
    tables = flow_rates(flows1, flows2, seconds)
    links, port_state = collect_links(nsot, base, names, tables)

    # Step 4: the controller's TCP sensor (new connections per source host,
    #         last 60 s). None if this controller has no sensor.
    try:
        sensor = rest_get(base, '/lab9/sensor')
    except Exception:
        sensor = None

    return {
        'collected_at': started.isoformat(),
        'controller': base,
        'sample_seconds': sample_seconds,
        'hardware_switches': sorted(n for n, s in nsot['switches'].items() if s['vendor'] != 'ovs'),
        'ovs_switches': sorted(n for n, s in nsot['switches'].items() if s['vendor'] == 'ovs'),
        'switches': switches,
        'flows': tables,
        'drop_rules': dict((n, [r for r in rules if r['drop']]) for n, rules in tables.items()),
        'unauthorized_rules': dict((n, [r for r in rules if r['owner'] == 'unauthorized'])
                                   for n, rules in tables.items()),
        'port_rates': rates,
        'port_state': port_state,
        'links': links,
        'tcp_sensor': sensor,
        # switches + (2 flow + 2 port + 1 portdesc) per switch + sensor
        'rest_calls': 1 + 5 * len(names) + 1,
    }


# ===========================================================================
# Function 8: a readable summary (CLI)
# ===========================================================================

def summary_lines(state):
    """Step 1: the short human view of a snapshot."""
    s = state['switches']
    out = ['collected %s from %s (rates over %.1f s)' % (state['collected_at'][:19], state['controller'],
                                                        state['sample_seconds']),
           'switches: %d connected%s%s' % (len(s['connected']),
                                           ', MISSING: ' + ', '.join(s['missing']) if s['missing'] else '',
                                           ', UNKNOWN dpids: %s' % s['unknown_dpids'] if s['unknown_dpids'] else '')]
    # Step 2: flow tables by owner.
    for name, rules in sorted(state['flows'].items()):
        owners = {}
        for r in rules:
            owners[r['owner']] = owners.get(r['owner'], 0) + 1
        out.append('  %-8s %2d rules  %s' % (name, len(rules),
                                            ', '.join('%s %d' % kv for kv in sorted(owners.items()))))
    # Step 3: the things worth looking at.
    for name, rules in sorted(state['drop_rules'].items()):
        for r in rules:
            out.append('DROP rule on %s: priority %s cookie %s %s' % (name, r['priority'], r['cookie'], r['match']))
    for name, rules in sorted(state['unauthorized_rules'].items()):
        for r in rules:
            out.append('UNAUTHORIZED rule on %s (cookie %s): %s -> %s' % (name, r['cookie'], r['match'], r['actions']))
    for l in state['links']:
        out.append('link %-22s %-4s%s%s%s' % (l['link'], l['state'], '  standby' if l['standby'] else '',
                                              '  (%s)' % l['why'] if l['why'] else '',
                                              '  carrying: %d rules' % l['learned_rules_using_it']
                                              if l['standby'] and l['learned_rules_using_it'] else ''))
    busiest = sorted(((r.get('rx_pps', 0) + r.get('tx_pps', 0), n, p, r)
                      for n, ports in state['port_rates'].items() for p, r in ports.items()
                      if p != '_seconds' and r.get('valid') and r['rx_pps'] + r['tx_pps'] >= 1),
                     key=lambda x: -x[0])[:3]
    # Step 4: TCP sensor: sources that opened connections in the last 60 s.
    for ip, src in sorted(((state.get('tcp_sensor') or {}).get('sources') or {}).items()):
        out.append('tcp sensor: %s (%s) opened %d connections to %d ports on %s' % (
            src['host'], ip, src['new_connections'], src['distinct_dst_ports'], ', '.join(src['dst_hosts'])))
    # Step 5: the three busiest ports (only ports with real traffic).
    for total, n, p, r in busiest:
        out.append('busy port %s:%s (to %s): rx %.1f pps, tx %.1f pps' % (n, p, r['to'], r['rx_pps'], r['tx_pps']))
    return out


def main():
    """Command line: summary (default) or the full snapshot (--json).
    Exit code 0 = collected, 2 = the controller could not be read."""
    # Step 1: options.
    ap = argparse.ArgumentParser(description='Collect live network state through the controller REST API.')
    ap.add_argument('--controller', help='IP:port of the controller REST API (default: LAB9_CONTROLLER or the NSOT)')
    ap.add_argument('--seconds', type=float, default=2.0, help='gap between the two readings (default 2)')
    ap.add_argument('--json', action='store_true', help='print the full snapshot as JSON')
    args = ap.parse_args()

    # Step 2: NSOT + controller address, then one snapshot.
    nsot = load_nsot()
    base = controller_url(nsot, args.controller)
    # Step 3: print it; an unreachable controller is a clear message, not a traceback.
    try:
        state = collect_network_state(nsot, base, args.seconds)
    except Exception as e:
        print('cannot collect from %s: %s' % (base, e))
        return 2
    print(json.dumps(state, indent=2) if args.json else '\n'.join(summary_lines(state)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
