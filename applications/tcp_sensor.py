"""Lab 9 Part B (B3 support): TCP connection sensor, inside the controller.

Why it exists:
  B3 must detect a port scan. Our switching rules match MAC addresses only,
  so 1000 TCP connections from pc1 to srv1 all ride ONE learned rule and look
  like ordinary traffic. A scan is only visible at Layer 4 (many destination
  ports). OVS 2.0 cannot match TCP flags (SYN), so the sensor works on the
  FIRST PACKET OF EVERY TCP CONNECTION instead:

  1. Catch rule (`install_tcp_sensor_flows`), on every ACCESS port (where
     hosts plug in): priority 10, cookie 0x50,
       in_port=<host port>, IPv4, TCP  ->  CONTROLLER
     Priority 10 is ABOVE learned rules (1), so new connections are seen,
     and BELOW the AI rule band (20-40), so a host the AI blocked is dropped
     before the sensor (it can never be forwarded around a block).
  2. The controller notes the connection (`observe`) and forwards the packet
     as usual. The switching app then installs a per-connection rule
     (`connection_match`, priority 11, cookie 0x51, idle 10 s), so the rest
     of the connection stays in the switch. One packet per connection reaches
     the controller.
  3. Replies are told apart from new connections: a packet whose reverse
     (dst -> src) was seen recently is a reply. So srv1 answering a scan with
     hundreds of RSTs is NOT mistaken for srv1 scanning.
  4. REST: GET /lab9/sensor -> per source over the last 60 s: new
     connections, distinct destination ports, distinct destination hosts.
     The Part B collector reads this; the sensor itself decides nothing.

Cookies 0x50/0x51 are in the NSOT flow_cookies list (owner tcp_sensor).
"""

import collections
import time

from ryu.app.wsgi import ControllerBase, route
from ryu.lib.packet import ether_types, ipv4, tcp

from .console import json_response

SENSOR_PRIORITY = 10          # catch rule: above learned (1), below AI rules (20-40)
CONNECTION_PRIORITY = 11      # per-connection rule
SENSOR_COOKIE = 0x50
CONNECTION_COOKIE = 0x51
CONNECTION_IDLE = 10          # seconds; a quiet connection's rule expires
WINDOW = 60                   # seconds of history kept per source
MAX_EVENTS = 20000            # memory cap


# ===========================================================================
# Function 1: install the catch rule on every access port of a switch
# ===========================================================================

def install_tcp_sensor_flows(dp, access_ports):
    """Priority-10 rule per access port: new TCP from a host -> controller."""
    ofp = dp.ofproto
    parser = dp.ofproto_parser
    for port in access_ports:
        # Step 1: match TCP arriving from the host on this port.
        match = parser.OFPMatch(in_port=port, eth_type=ether_types.ETH_TYPE_IP, ip_proto=6)
        # Step 2: send the whole packet to the controller.
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=SENSOR_PRIORITY, cookie=SENSOR_COOKIE,
                                      match=match, instructions=inst))


# ===========================================================================
# Function 2: the per-connection rule the switching app installs
# ===========================================================================

def connection_match(parser, in_port, eth, ip, seg, match_vid):
    """Match exactly one TCP connection (one direction) on one port."""
    # Step 1: same fields as a learned rule (port, MACs, VLAN tag state) ...
    # Step 2: ... plus the TCP 5-tuple, so other connections still reach
    #         the controller through the catch rule.
    return parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst, vlan_vid=match_vid,
                           eth_type=ether_types.ETH_TYPE_IP, ip_proto=6,
                           ipv4_src=ip.src, ipv4_dst=ip.dst,
                           tcp_src=seg.src_port, tcp_dst=seg.dst_port)


# ===========================================================================
# Class 1: the sensor's memory
# ===========================================================================

class TcpSensor(object):
    """Remembers the new TCP connections of the last WINDOW seconds."""

    def __init__(self, nsot, logger, clock=time.time):
        # Step 1: IP -> host name from the NSOT, for readable reports.
        self.names = dict((h['ip'].split('/')[0], n) for n, h in nsot['hosts'].items())
        self.logger = logger
        self.clock = clock
        # Step 2: (time, src, sport, dst, dport) of new connections, oldest first,
        #         and when each direction was last seen (to recognise replies).
        self.events = collections.deque()
        self.last_seen = {}
        self.stats = {'packets_seen': 0, 'new_connections': 0, 'replies': 0}

    def observe(self, dpid, in_port, role, pkt):
        """Called by the switching app for every packet-in. Records it if it
        is TCP from a host port. Returns (ip, tcp) headers if it is sensor
        traffic (so the caller installs a per-connection rule), else None."""
        # Step 1: only TCP arriving from a host (access port).
        if role != 'access':
            return None
        ip = pkt.get_protocol(ipv4.ipv4)
        seg = pkt.get_protocol(tcp.tcp)
        if ip is None or seg is None:
            return None
        now = self.clock()
        self.stats['packets_seen'] += 1
        key = (ip.src, seg.src_port, ip.dst, seg.dst_port)
        reverse = (ip.dst, seg.dst_port, ip.src, seg.src_port)
        # Step 2: a reply to a connection seen recently is not a new one.
        if now - self.last_seen.get(reverse, -1e9) <= WINDOW:
            self.stats['replies'] += 1
        else:
            self.stats['new_connections'] += 1
            self.events.append((now, ip.src, seg.src_port, ip.dst, seg.dst_port))
        self.last_seen[key] = now
        # Step 3: forget anything older than the window (and cap memory).
        self._trim(now)
        return ip, seg

    def _trim(self, now):
        while self.events and (now - self.events[0][0] > WINDOW or len(self.events) > MAX_EVENTS):
            self.events.popleft()
        if len(self.last_seen) > 2 * MAX_EVENTS:
            self.last_seen = dict((k, t) for k, t in self.last_seen.items() if now - t <= WINDOW)

    def report(self):
        """Per source host over the last WINDOW seconds:
        new connections, distinct destination ports and hosts."""
        # Step 1: drop old events first.
        now = self.clock()
        self._trim(now)
        # Step 2: group by source.
        by_src = {}
        for t, src, sport, dst, dport in self.events:
            s = by_src.setdefault(src, {'host': self.names.get(src, src), 'new_connections': 0,
                                        'dst_ports': set(), 'dst_hosts': set(), 'last': 0})
            s['new_connections'] += 1
            s['dst_ports'].add((dst, dport))
            s['dst_hosts'].add(dst)
            s['last'] = max(s['last'], t)
        # Step 3: plain numbers (JSON), plus a few example ports.
        out = {}
        for src, s in by_src.items():
            ports = sorted(p for _, p in s['dst_ports'])
            out[src] = {'host': s['host'], 'new_connections': s['new_connections'],
                        'distinct_dst_ports': len(s['dst_ports']),
                        'distinct_dst_hosts': len(s['dst_hosts']),
                        'dst_hosts': sorted(self.names.get(d, d) for d in s['dst_hosts']),
                        'example_ports': ports[:10],
                        'seconds_since_last': round(now - s['last'], 1)}
        return {'window_seconds': WINDOW, 'sources': out, 'stats': dict(self.stats)}


# ===========================================================================
# Class 2: REST API
# ===========================================================================

class TcpSensorRestController(ControllerBase):
    """GET /lab9/sensor -> TcpSensor.report() as JSON."""

    def __init__(self, req, link, data, **config):
        super(TcpSensorRestController, self).__init__(req, link, data, **config)
        self.sensor = data['tcp_sensor']

    @route('lab9_sensor', '/lab9/sensor', methods=['GET'])
    def get_report(self, req, **kwargs):
        return json_response(self.sensor.report())
