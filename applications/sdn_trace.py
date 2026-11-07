"""Lab 9 Objective 5 (A5) & Objective 6 (A6): SDN trace application.

What Objective 5 requires:
  "Accept a source and destination from the user (CLI or Flask GUI) and trace
   the path through the OpenFlow network, printing the DPIDs of the switches
   along the path."  + ingress and egress ports at every switch.

Why not ICMP traceroute: switches don't lower the TTL or answer traceroute,
so traceroute pc1 -> srv1 shows only the router and srv1 (measured: 2 hops),
never the 4 switches in between.

How this trace works (no packet is sent, nothing is installed):
  1. Start where the source plugs in (from the NSOT), e.g. pc1 = arista1 port 2.
  2. Read that switch's REAL flow table through the controller's REST API
     (GET /stats/flow/<dpid>) and find the rule an ordinary packet from the
     source would match. The rule names the out port.
  3. Look up in the NSOT what that out port is wired to -> the next switch
     and the port the packet arrives on. Repeat from step 2.
  4. At the router (not OpenFlow: no flow table) work out its Layer 3
     decision from the NSOT: the destination IP's subnet -> VLAN, frame
     readdressed to the destination's MAC. Then continue from step 2.
  5. Stop when the destination is reached, or say exactly why not
     (a switch has no rule yet, a rule points somewhere else, a loop, ...).

REST (on Ryu's port 8080):
  GET /lab9/trace?src=pc1&dst=srv1     -> JSON result (hops + printed lines)
CLI: applications/trace_cli.py pc1 srv1
"""

import ipaddress
import json
import urllib.request

from ryu.app.wsgi import ControllerBase, route

from .console import json_response, nsot_topology

# A trace longer than this is certainly a loop or a broken rule.
MAX_HOPS = 16


# ===========================================================================
# Function 1: read one switch's flow table through the controller REST API
# ===========================================================================

def rest_flow_reader(base_url):
    """Return a function fetch(dpid) -> list of flow rules, read from Ryu's
    ofctl_rest (GET <base_url>/stats/flow/<dpid>).

    Each rule looks like:
      {"priority": 1, "cookie": 16, "packet_count": 23,
       "match": {"in_port": 2, "dl_vlan": "0x0000", "dl_dst": "00:00:00:00:01:01"},
       "actions": ["PUSH_VLAN:33024", "SET_FIELD: {vlan_vid:10}", "OUTPUT:1"]}
    """
    def fetch(dpid):
        url = '%s/stats/flow/%d' % (base_url, dpid)
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read().decode('utf-8')).get(str(dpid), [])
    return fetch


# ===========================================================================
# Function 2: does a rule match the packet the trace is following?
# ===========================================================================

def tag_of(value):
    """A rule's VLAN field as a number, or None for "no tag".
    ofctl_rest shows "0x0000" for "untagged" and e.g. "10" for VLAN 10."""
    n = int(str(value), 0)
    if n == 0:
        return None
    return n & 0x0fff          # drop OpenFlow's "tag present" bit if shown


def rule_matches(match, in_port, tag, src_mac, dst_mac):
    """True if an ordinary IPv4 packet (like a ping) arriving on `in_port`
    with VLAN tag `tag` (None = untagged), sent from `src_mac` to `dst_mac`,
    would match this rule.

    Every field in the rule must agree. A field the packet doesn't have
    (e.g. a UDP port: the DNS/DHCP rules) means the rule doesn't match.
    """
    for key, want in match.items():
        if key == 'in_port':
            ok = int(want) == in_port
        elif key in ('dl_src', 'eth_src'):
            ok = str(want).lower() == src_mac
        elif key in ('dl_dst', 'eth_dst'):
            ok = str(want).lower() == dst_mac
        elif key in ('dl_vlan', 'vlan_vid'):
            ok = tag_of(want) == tag
        elif key in ('dl_type', 'eth_type'):
            ok = int(want) == 0x0800          # IPv4
        elif key in ('nw_proto', 'ip_proto'):
            ok = int(want) == 1               # ICMP, like ping
        else:
            ok = False
        if not ok:
            return False
    return True


# ===========================================================================
# Function 3: what a switch does with that packet
# ===========================================================================

def switch_decision(flows, in_port, tag, src_mac, dst_mac):
    """The rule the switch would use: the highest-priority match.
    None if nothing matches."""
    for rule in sorted(flows, key=lambda f: -f.get('priority', 0)):
        if rule_matches(rule.get('match', {}), in_port, tag, src_mac, dst_mac):
            return rule
    return None


def rule_effect(rule, tag):
    """From a rule's actions: (out port, VLAN tag after the actions).
    Out port is a number, or a word like "CONTROLLER", or None (= drop)."""
    out_port = None
    for action in rule.get('actions', []):
        if action.startswith('OUTPUT:'):
            value = action.split(':', 1)[1].strip()
            out_port = int(value) if value.isdigit() else value
        elif action.startswith('POP_VLAN'):
            tag = None
        elif action.startswith('SET_FIELD') and 'vlan_vid' in action:
            tag = int(action.split('vlan_vid:')[1].strip(' }')) & 0x0fff
    return out_port, tag


def rule_text(rule):
    """One readable line for a rule, e.g.
    'in_port=2 dl_vlan=0x0000 dl_dst=00:..:01:01 -> PUSH_VLAN:33024, ..., OUTPUT:1'"""
    match = ' '.join('%s=%s' % (k, v) for k, v in sorted(rule.get('match', {}).items()))
    return '%s -> %s' % (match or '(everything)', ', '.join(rule.get('actions', [])) or 'drop')


# ===========================================================================
# Class 1: the trace engine
# ===========================================================================

class TraceEngine(object):
    """Traces a path using the NSOT (wiring) + the switches' flow tables."""

    def __init__(self, nsot, fetch_flows):
        # Step 1: everything the trace needs from the NSOT.
        self.topo = nsot_topology(nsot)
        self.fetch = fetch_flows
        self.router = self.topo['router']
        self.subnets = {}
        for vid, subnet in self.router['subnets'].items():
            self.subnets[int(vid)] = ipaddress.ip_network(subnet)

        # Step 2: wiring[(switch, port)] = what is plugged into that port:
        #   ('switch', peer, peer_port, standby) | ('host', name) | ('router', name)
        self.wiring = {}
        for l in self.topo['links']:
            self.wiring[(l['a'], l['a_port'])] = ('switch', l['b'], l['b_port'], l['standby'])
            self.wiring[(l['b'], l['b_port'])] = ('switch', l['a'], l['a_port'], l['standby'])
        for name, a in self.topo['attach'].items():
            kind = 'router' if name == self.router['name'] else 'host'
            self.wiring[(a['switch'], a['port'])] = (kind, name)

    # ---- input --------------------------------------------------------------

    def resolve(self, text):
        """Turn user input into ('host', name) or ('external', ip).
        Accepts a host name (pc1), a host IP (10.10.10.11), the Internet node
        name (inet), or any IP outside the VLANs (8.8.8.8)."""
        text = (text or '').strip()
        hosts = self.topo['hosts']
        if text in hosts:
            return ('host', text)
        for name, h in hosts.items():
            if h['ip'] == text:
                return ('host', name)
        ext = self.topo.get('external') or {}
        if text and text == ext.get('name'):
            return ('external', ext['ip'])
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            raise ValueError('"%s" is not a host in the NSOT or an IP address' % text)
        if any(ip in net for net in self.subnets.values()):
            raise ValueError('%s is inside a VLAN but is not a host in the NSOT' % text)
        return ('external', str(ip))

    # ---- the trace ----------------------------------------------------------

    def trace(self, src, dst):
        """Trace src -> dst. Returns a dict:
          complete: True if the destination was reached
          hops:     [{kind, name, dpid, in_port, out_port, ...}, ...]
          lines:    what the CLI prints
          stopped:  why the trace stopped early (None if complete)
        Raises ValueError for bad input."""
        # Step 1: check the input against the NSOT.
        s_kind, s_name = self.resolve(src)
        if s_kind != 'host':
            raise ValueError('the source must be a host in the NSOT (got %s)' % src)
        d_kind, d_name = self.resolve(dst)
        if d_kind == 'host' and d_name == s_name:
            raise ValueError('source and destination are the same host')

        sa = self.topo['attach'][s_name]
        s_vlan = sa['vlan']
        if d_kind == 'host':
            da = self.topo['attach'][d_name]
            d_vlan, d_ip = da['vlan'], self.topo['hosts'][d_name]['ip']
            d_mac = self.topo['hosts'][d_name]['mac']
        else:
            d_vlan, d_ip, d_mac = None, d_name, None
        routed = d_vlan != s_vlan
        r = self.router

        res = {'src': s_name, 'dst': d_name if d_kind == 'host' else d_ip,
               'complete': False, 'stopped': None, 'hops': [], 'flow_reads': 0,
               'lines': ['trace %s -> %s' % (s_name, d_name if d_kind == 'host' else d_ip)]}
        flows = {}    # each switch's table is read at most once per trace

        # Step 2: first leg, sent by the source host. Same VLAN: straight to
        #         the destination's MAC. Different VLAN or Internet: to the
        #         gateway (router's MAC).
        s_mac = self.topo['hosts'][s_name]['mac']
        first_mac = r['mac'] if routed else d_mac
        first_target = r['name'] if routed else d_name
        if not self._walk(res, flows, sa['switch'], sa['port'], None, s_mac, first_mac, first_target):
            return res

        if routed:
            # Step 3: the router. Not OpenFlow, so its Layer 3 decision is
            #         worked out from the NSOT subnets.
            r_sw = self.topo['attach'][r['name']]
            if d_kind == 'host':
                res['hops'].append({'kind': 'router', 'name': r['name'],
                                    'vlan_in': s_vlan, 'vlan_out': d_vlan,
                                    'decision': '%s is in %s (VLAN %s): out the VLAN %s side, to %s'
                                                % (d_ip, self.subnets[d_vlan], d_vlan, d_vlan, d_mac)})
                res['lines'].append('%-19sVLAN %s -> %s, to %s' % (r['name'] + ' (router)', s_vlan, d_vlan, d_name))
                # Step 4: second leg, from the router back into its switch,
                #         tagged with the destination VLAN. The router
                #         readdressed the frame: from its own MAC to the
                #         destination's MAC.
                if not self._walk(res, flows, r_sw['switch'], r_sw['port'], d_vlan, r['mac'], d_mac, d_name):
                    return res
            else:
                res['hops'].append({'kind': 'router', 'name': r['name'], 'vlan_in': s_vlan,
                                    'vlan_out': None,
                                    'decision': '%s is outside every VLAN: default route out the Internet side, NAT to %s'
                                                % (d_ip, r['wan_ip'])})
                res['lines'].append('%-19sto the Internet (NAT %s)' % (r['name'] + ' (router)', r['wan_ip']))
                res['lines'].append('-> leaves the OpenFlow network toward %s' % d_ip)
                res['complete'] = True
                return res

        res['lines'].append('-> %s reached' % d_name)
        res['complete'] = True
        return res

    def _walk(self, res, flows, sw, in_port, tag, src_mac, dst_mac, target):
        """Follow the switches' rules from `sw` (packet from `src_mac` to
        `dst_mac`, arriving on `in_port` with VLAN `tag`) until `target`
        (a host or the router) is reached.
        Appends hops to `res`; returns False if the trace had to stop."""
        seen = set()
        for _ in range(MAX_HOPS):
            # Step 1: a switch+port visited twice in one leg is a loop.
            if (sw, in_port) in seen:
                return self._stop(res, 'loop: %s port %s was reached twice' % (sw, in_port))
            seen.add((sw, in_port))
            dpid = self.topo['switches'][sw]['dpid']

            # Step 2: read the switch's real flow table (once per trace).
            if sw not in flows:
                try:
                    flows[sw] = self.fetch(dpid)
                    res['flow_reads'] += 1
                except Exception as e:
                    return self._stop(res, 'could not read %s\'s flow table: %s' % (sw, e))

            # Step 3: the rule this packet would match.
            rule = switch_decision(flows[sw], in_port, tag, src_mac, dst_mac)
            out_port, new_tag = rule_effect(rule, tag) if rule else (None, tag)
            hop = {'kind': 'switch', 'name': sw, 'dpid': dpid, 'in_port': in_port,
                   'vlan_in': tag, 'vlan_out': new_tag, 'out_port': out_port,
                   'rule': rule_text(rule) if rule else None,
                   'rule_packets': rule.get('packet_count') if rule else None,
                   'standby': False}
            res['hops'].append(hop)
            name = '%-19s' % ('%s (dpid %d)' % (sw, dpid))
            if rule is None or not isinstance(out_port, int):
                why = ('no rule yet: the packet would be dropped' if rule is None else
                       'no rule yet: only "send to the controller" matches')
                hop['out_port'] = None
                res['lines'].append('%sin %s -> no rule yet, stop' % (name, in_port))
                return self._stop(res, '%s has %s. Run a ping from %s to %s so the '
                                       'switches learn the path, then trace again.'
                                  % (sw, why, res['src'], res['dst']))

            # Step 4: what is wired to the out port (NSOT)?
            wired = self.wiring.get((sw, out_port))
            hop['standby'] = bool(wired and wired[0] == 'switch' and wired[3])
            res['lines'].append('%sin %s -> out %s%s' % (name, in_port, out_port,
                                                        '  (standby link)' if hop['standby'] else ''))
            if wired is None:
                return self._stop(res, '%s port %s is not in the NSOT' % (sw, out_port))
            if wired[0] == 'switch':
                sw, in_port, tag = wired[1], wired[2], new_tag
                continue
            if wired[1] == target:
                return True
            return self._stop(res, '%s sends it out port %s to %s, not toward %s'
                              % (sw, out_port, wired[1], target))
        return self._stop(res, 'more than %d switch hops: probably a loop' % MAX_HOPS)

    @staticmethod
    def _stop(res, why):
        res['stopped'] = why
        res['lines'].append('trace stopped: %s' % why)
        return False


# ===========================================================================
# Class 2: REST API (Objective 6)
# ===========================================================================

class TraceRestController(ControllerBase):
    """GET /lab9/trace?src=pc1&dst=srv1  ->  the trace as JSON.
    Registered by VlanSwitch13 with data {'trace_engine': TraceEngine}."""

    def __init__(self, req, link, data, **config):
        super(TraceRestController, self).__init__(req, link, data, **config)
        self.engine = data['trace_engine']

    def _json(self, payload, status=200):
        return json_response(payload, status)

    @route('lab9_trace', '/lab9/trace', methods=['GET'])
    def get_trace(self, req, **kwargs):
        src = req.params.get('src', '')
        dst = req.params.get('dst', '')
        if not src or not dst:
            return self._json({'error': 'give both src and dst, e.g. /lab9/trace?src=pc1&dst=srv1'}, 400)
        try:
            return self._json(self.engine.trace(src, dst))
        except ValueError as e:
            return self._json({'error': str(e)}, 400)
