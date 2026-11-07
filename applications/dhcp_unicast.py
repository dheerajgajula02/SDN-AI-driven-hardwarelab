"""Lab 9 Objective 4 (A4) & Objective 6 (A6): DHCP Unicast Forcing Application.

What Objective 4 requires:
  "Force DHCP requests from hosts to the Internet router (DHCP server).
   Requests entering the network at the edge switches must be unicast."

Why this is needed:
  Normally a host asking for DHCP has no IP (0.0.0.0) and does not know where
  the DHCP server is, so it broadcasts:
    Ethernet dst = ff:ff:ff:ff:ff:ff
    IPv4 dst     = 255.255.255.255
    UDP ports    = 68 (client) -> 67 (server)
  In a normal network that broadcast floods to every host in the VLAN.

  With SDN, the controller already knows from `nsot.json` where the router `r1`
  is (`cisco1` port 1), its MAC (`00:00:00:00:01:01`), and its gateway IP on
  each VLAN (`10.10.10.1` for VLAN 10, `10.10.20.1` for VLAN 20). So when a
  DHCP request enters an edge switch, the controller rewrites it into a UNICAST
  frame addressed to `r1` and sends it straight up the path to `cisco1:1`
  without flooding to any other host.

What exactly is rewritten (found by testing):
  - Ethernet destination: ALWAYS rewritten ff:ff:ff:ff:ff:ff -> router MAC.
    This is what makes the frame unicast on every link: switches forward it
    to one port only, and no other host ever receives it.
  - IP destination: rewritten 255.255.255.255 -> gateway IP ONLY when the
    client already has an IP (e.g. a renewal). A brand-new client has source
    IP 0.0.0.0, and routers drop a unicast IP packet from 0.0.0.0 as a
    "martian" (impossible source), so for those the IP destination stays
    255.255.255.255 inside the unicast frame. The router accepts that.
"""

from collections import deque
import json
import os
import socket
import struct
import time

from ryu.app.wsgi import ControllerBase, Response, route
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, udp, vlan

from .console import console_response, json_response

# Priority 50 beats priority-1 learned L2 flows; cookie 0x40 (64) marks this
# rule as a protected flow in nsot.json so topology flushes and AI policies
# never delete it.
DHCP_PRIORITY = 50
DHCP_COOKIE = 0x40

DHCP_MSG_TYPES = {
    1: 'DISCOVER',
    2: 'OFFER',
    3: 'REQUEST',
    4: 'DECLINE',
    5: 'ACK',
    6: 'NAK',
    7: 'RELEASE',
    8: 'INFORM',
}


# ===========================================================================
# Function 1: Install the OpenFlow rule intercepting DHCP requests (UDP 68->67)
# ===========================================================================

def install_dhcp_intercept_flow(dp):
    """Install one rule on switch `dp` that forces all DHCP client requests
    (IPv4 UDP src_port=68, dst_port=67) to the controller.

    Why only 68 -> 67?
      - 68 -> 67 is host-to-server (DISCOVER, REQUEST, RELEASE). That is the
        traffic that arrives as a broadcast at the edge switch and must be
        converted to unicast and steered to the router.
      - 67 -> 68 is server-to-host (OFFER, ACK) coming back from the router,
        which the switch's normal VLAN MAC learning forwards back to the host.
    """
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    # Step 1: match IPv4 (0x0800) + UDP (17) + client port 68 -> server port 67.
    match = parser.OFPMatch(
        eth_type=ether_types.ETH_TYPE_IP,
        ip_proto=17,
        udp_src=68,
        udp_dst=67,
    )

    # Step 2: send the full packet (OFPCML_NO_BUFFER) to the controller.
    actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

    # Step 3: install at priority 50 (above priority-1 L2 flows) with protected
    #         cookie 0x40 so update_tree() never deletes it.
    mod = parser.OFPFlowMod(
        datapath=dp,
        priority=DHCP_PRIORITY,
        cookie=DHCP_COOKIE,
        match=match,
        instructions=inst,
    )
    dp.send_msg(mod)


# ===========================================================================
# Function 2: Find the single egress port on `dpid` leading to the router
# ===========================================================================

def find_next_hop_to_router(dpid, router_dpid, router_port, links, blocked, down):
    """Decide which single port on switch `dpid` leads toward the router.

    Example in our topology (`router_dpid = 1` cisco1, `router_port = 1`):
      - On `ovs2` (dpid 32):    returns port 1 (trunk up to arista2)
      - On `arista2` (dpid 12): returns port 1 (trunk up to cisco1)
      - If `cisco1 <-> arista2` is cut (so standby `arista2:4 <-> arista1:4`
        is unblocked):          returns port 4 on `arista2` (via arista1)!
      - On `cisco1` (dpid 1):   returns port 1 (the port where `r1` lives)

    Returns the outgoing port number (int), or None if the router is unreachable.
    """
    # Step 1: if this switch IS the router's switch (cisco1), the next hop is
    #         simply the port the router is plugged into (port 1).
    if dpid == router_dpid:
        if (dpid, router_port) in blocked or (dpid, router_port) in down:
            return None
        return router_port

    # Step 2: build an adjacency map of all currently usable switch links
    #         (skip any link where either end is blocked or down).
    #         adj[switch_dpid] = [(my_port, neighbor_dpid), ...]
    adj = {}
    for (da, pa), (db, pb), _ in links:
        if (da, pa) in blocked or (da, pa) in down:
            continue
        if (db, pb) in blocked or (db, pb) in down:
            continue
        adj.setdefault(da, []).append((pa, db))
        adj.setdefault(db, []).append((pb, da))

    # Step 3: Breadth-First Search (BFS) starting from `dpid`.
    #         We remember `first_port` (the port on `dpid` that started the
    #         path) so when we reach `router_dpid` we know which port on `dpid`
    #         to send the packet out of.
    visited = {dpid}
    queue = deque()
    for out_port, neighbor in sorted(adj.get(dpid, [])):
        if neighbor == router_dpid:
            return out_port
        visited.add(neighbor)
        queue.append((neighbor, out_port))

    while queue:
        curr, first_port = queue.popleft()
        for _, neighbor in sorted(adj.get(curr, [])):
            if neighbor == router_dpid:
                return first_port
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, first_port))

    return None


# ===========================================================================
# Function 3: Parse the DHCP payload (transaction ID, client MAC, message type)
# ===========================================================================

def parse_dhcp_packet(raw_data):
    """Read the BOOTP/DHCP payload inside a raw Ethernet frame.

    Why we need this:
      1. To verify the packet really is a valid DHCP packet (has the 4-byte
         DHCP magic cookie `63:82:53:63` at BOOTP offset 236).
      2. To extract the human-readable DHCP message type (Option 53:
         DISCOVER, REQUEST, RELEASE, etc.) and client MAC for logging and the UI.
      3. To slice out the exact `udp_payload` bytes so we can re-wrap them
         unchanged inside the new unicast Ethernet + IPv4 + UDP headers.
    """
    # Step 1: find where the IPv4, UDP, and BOOTP headers start.
    #         Ethernet header is 14 bytes (or 18 bytes if 802.1Q tagged).
    if len(raw_data) < 14 + 20 + 8 + 240:
        return None
    eth_type = struct.unpack('!H', raw_data[12:14])[0]
    ip_offset = 18 if eth_type == ether_types.ETH_TYPE_8021Q else 14
    if len(raw_data) < ip_offset + 20:
        return None
    ip_hlen = (raw_data[ip_offset] & 0x0F) * 4
    udp_offset = ip_offset + ip_hlen
    dhcp_offset = udp_offset + 8
    if len(raw_data) < dhcp_offset + 240:
        return None

    # Step 2: unpack the fixed 236-byte BOOTP header fields:
    #         [4:8]   xid (Transaction ID)
    #         [12:16] ciaddr (client IP if renewing)
    #         [28:34] chaddr (client 6-byte MAC address)
    bootp = raw_data[dhcp_offset:]
    xid = struct.unpack('!I', bootp[4:8])[0]
    ciaddr = socket.inet_ntoa(bootp[12:16])
    chaddr = ':'.join('%02x' % b for b in bootp[28:34])

    msg_type = 'BOOTP'
    req_ip = ciaddr if ciaddr != '0.0.0.0' else ''

    # Step 3: walk the TLV options after the DHCP magic cookie (bytes 236..240)
    #         Option 53 = DHCP Message Type (1=DISCOVER, 3=REQUEST, ...)
    #         Option 50 = Requested IP Address
    if bootp[236:240] == b'\x63\x82\x53\x63':
        idx = 240
        while idx < len(bootp):
            opt = bootp[idx]
            idx += 1
            if opt == 255:       # 255 = End of options
                break
            if opt == 0:         # 0 = Padding byte
                continue
            if idx >= len(bootp):
                break
            length = bootp[idx]
            idx += 1
            val = bootp[idx:idx + length]
            idx += length
            if opt == 53 and length >= 1:
                msg_type = DHCP_MSG_TYPES.get(val[0], 'TYPE_%d' % val[0])
            elif opt == 50 and length == 4:
                req_ip = socket.inet_ntoa(val)

    return {
        'xid': '0x%08x' % xid,
        'client_mac': chaddr,
        'msg_type': msg_type,
        'requested_ip': req_ip,
        'udp_payload': bootp,
    }


# ===========================================================================
# Function 4: Rewrite broadcast DHCP request into a Unicast frame to the Router
# ===========================================================================

def rewrite_dhcp_to_unicast(eth_req, ip_req, udp_req, dhcp_payload,
                            vid, egress_tagged, router_mac, ip_dst):
    """Turn a broadcast DHCP frame into a unicast frame addressed to `r1`.

    ip_dst: the IP destination to put in the packet. The caller decides:
            the gateway IP (10.10.10.1) if the client already has an IP,
            otherwise 255.255.255.255 (see "What exactly is rewritten" above).

    Before (arriving from pc2 on arista2 port 2, VLAN 10, new client):
      eth.src = 00:00:00:00:10:12   eth.dst = ff:ff:ff:ff:ff:ff (broadcast)
      ip.src  = 0.0.0.0             ip.dst  = 255.255.255.255
      vlan    = untagged (access port)

    After (leaving arista2 port 1 trunk toward cisco1):
      eth.src = 00:00:00:00:10:12   eth.dst = 00:00:00:00:01:01 (router r1 MAC)
      ip.src  = 0.0.0.0             ip.dst  = 255.255.255.255   (kept: no IP yet)
      vlan    = 802.1Q tag 10 (because outgoing port 1 is a trunk)
    """
    pkt = packet.Packet()

    # Step 1: Ethernet header (with 802.1Q tag if leaving on a trunk port),
    #         replacing broadcast ff:ff:ff:ff:ff:ff with `router_mac`.
    if egress_tagged:
        pkt.add_protocol(ethernet.ethernet(
            src=eth_req.src,
            dst=router_mac,
            ethertype=ether_types.ETH_TYPE_8021Q,
        ))
        pkt.add_protocol(vlan.vlan(vid=vid, ethertype=ether_types.ETH_TYPE_IP))
    else:
        pkt.add_protocol(ethernet.ethernet(
            src=eth_req.src,
            dst=router_mac,
            ethertype=ether_types.ETH_TYPE_IP,
        ))

    # Step 2: IPv4 header with the destination the caller chose (`ip_dst`).
    pkt.add_protocol(ipv4.ipv4(
        src=ip_req.src,
        dst=ip_dst,
        proto=17,
        ttl=ip_req.ttl,
        flags=ip_req.flags,
        identification=ip_req.identification,
    ))

    # Step 3: UDP header (68 -> 67) + original BOOTP/DHCP payload.
    #         pkt.serialize() recomputes the IPv4 and UDP checksums for the
    #         new destination IP address.
    pkt.add_protocol(udp.udp(
        src_port=udp_req.src_port,
        dst_port=udp_req.dst_port,
    ))
    pkt.add_protocol(dhcp_payload)
    pkt.serialize()
    return pkt.data


# ===========================================================================
# Class 1: DhcpUnicastEngine (called by VlanSwitch13 on UDP 68->67 packets)
# ===========================================================================

class DhcpUnicastEngine(object):
    """Stateful DHCP unicast engine attached to VlanSwitch13."""

    def __init__(self, nsot, links, logger):
        self.logger = logger
        self.links = links
        self.enabled = True

        # Step 1: read router location, MAC, and per-VLAN gateway IPs from NSOT.
        r1 = nsot.get('routers', {}).get('r1')
        if r1:
            sw_name, port_str = r1['lan']['to'].split(':')
            self.router_dpid = nsot['switches'][sw_name]['dpid']
            self.router_port = int(port_str)
            self.router_mac = r1['lan']['mac']
        else:
            self.router_dpid = None
            self.router_port = None
            self.router_mac = '00:00:00:00:01:01'
            self.enabled = False
        self.vlan_gateways = {
            int(vid): v['gateway'] for vid, v in nsot['vlans'].items()
        }
        self.dpid_names = {
            sw['dpid']: name for name, sw in nsot['switches'].items()
        }

        self.stats = {
            'total_requests': 0,
            'unicast_rewrites_at_edge': 0,
            'forwarded_hops': 0,
        }
        self.history = []

    def handle_packet(self, dp, in_port, role, vid, pkt, raw_data, ports_map, blocked, down):
        """Inspect a packet arriving at the controller.

        Returns True if the packet is a DHCP client request (handled and sent
        as unicast toward `r1`), or False if it is not a DHCP request.
        """
        if not self.enabled:
            return False

        # Step 1: check if this is an IPv4 UDP 68 -> 67 packet.
        ip_hdr = pkt.get_protocol(ipv4.ipv4)
        udp_hdr = pkt.get_protocol(udp.udp)
        if not ip_hdr or not udp_hdr:
            return False
        if not (udp_hdr.src_port == 68 and udp_hdr.dst_port == 67):
            return False

        # Step 2: parse the BOOTP/DHCP payload inside UDP.
        dhcp_info = parse_dhcp_packet(raw_data)
        if not dhcp_info:
            return False

        eth_hdr = pkt.get_protocol(ethernet.ethernet)
        router_ip = self.vlan_gateways.get(vid, ip_hdr.dst)

        # Step 3: find the single outgoing port on this switch toward `r1`.
        out_port = find_next_hop_to_router(
            dpid=dp.id,
            router_dpid=self.router_dpid,
            router_port=self.router_port,
            links=self.links,
            blocked=blocked,
            down=down,
        )
        if out_port is None or out_port == in_port:
            self.logger.warning('DHCP: no path to router from dpid=%s in_port=%s', dp.id, in_port)
            return True

        out_role = ports_map[dp.id][out_port][0]
        egress_tagged = (out_role == 'trunk')

        # "Broadcast" here means the Ethernet frame: that is what floods.
        was_broadcast = eth_hdr.dst.lower() == 'ff:ff:ff:ff:ff:ff'

        # Step 4: choose the IP destination.
        #   client has an IP (e.g. renewal) -> gateway IP (fully unicast)
        #   client has no IP yet (0.0.0.0)  -> keep the original destination,
        #     because routers drop unicast IP from 0.0.0.0 as a "martian"
        client_has_ip = ip_hdr.src != '0.0.0.0'
        ip_dst = router_ip if client_has_ip else ip_hdr.dst

        # Step 5: rewrite the frame to unicast (and set the outgoing VLAN tag).
        unicast_frame = rewrite_dhcp_to_unicast(
            eth_req=eth_hdr,
            ip_req=ip_hdr,
            udp_req=udp_hdr,
            dhcp_payload=dhcp_info['udp_payload'],
            vid=vid,
            egress_tagged=egress_tagged,
            router_mac=self.router_mac,
            ip_dst=ip_dst,
        )

        # Step 6: record stats and history for the REST API / UI.
        self.stats['total_requests'] += 1
        if role == 'access' and was_broadcast:
            self.stats['unicast_rewrites_at_edge'] += 1
        else:
            self.stats['forwarded_hops'] += 1

        sw_name = self.dpid_names.get(dp.id, 'dpid-%s' % dp.id)
        entry = {
            'time': time.strftime('%H:%M:%S'),
            'switch': sw_name,
            'dpid': dp.id,
            'in_port': in_port,
            'in_role': role,
            'out_port': out_port,
            'out_role': out_role,
            'vlan': vid,
            'msg_type': dhcp_info['msg_type'],
            'xid': dhcp_info['xid'],
            'client_mac': dhcp_info['client_mac'],
            'orig_dst': '%s / %s' % (eth_hdr.dst, ip_hdr.dst),
            'new_dst': '%s / %s' % (self.router_mac, ip_dst),
            'rewritten_at_edge': bool(role == 'access' and was_broadcast),
        }
        self.history.append(entry)
        if len(self.history) > 100:
            self.history.pop(0)

        self.logger.info(
            'DHCP [%s] %s (dpid=%s) port %s->%s vlan=%s client=%s: eth %s -> %s, ip dst %s',
            dhcp_info['msg_type'], sw_name, dp.id, in_port, out_port, vid,
            dhcp_info['client_mac'], eth_hdr.dst, self.router_mac, ip_dst,
        )

        # Step 7: send the unicast frame out ONLY `out_port` (never flooded).
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=[parser.OFPActionOutput(out_port)],
            data=unicast_frame,
        )
        dp.send_msg(out)
        return True


# ===========================================================================
# Class 2: Ryu WSGI REST Controller for DHCP (Objective 6 + Web UI)
# ===========================================================================

class DhcpRestController(ControllerBase):
    """REST endpoints for Objective 4 (DHCP Unicast Application):
      GET  /lab9/dhcp/ui      -> Browser UI Control Panel
      GET  /lab9/dhcp/status  -> JSON stats, router target, and packet history
      POST /lab9/dhcp/config  -> Enable/disable or clear packet log
    """

    def __init__(self, req, link, data, **config):
        super(DhcpRestController, self).__init__(req, link, data, **config)
        self.engine = data['dhcp_engine']

    def _json(self, payload, status=200):
        return json_response(payload, status)

    # Old URL, kept working: serves the shared console, opened on the DHCP tab.
    @route('lab9_dhcp', '/lab9/dhcp/ui', methods=['GET'])
    def serve_ui(self, req, **kwargs):
        return console_response()

    @route('lab9_dhcp', '/lab9/dhcp/status', methods=['GET'])
    def get_status(self, req, **kwargs):
        return self._json({
            'enabled': self.engine.enabled,
            'router_dpid': self.engine.router_dpid,
            'router_port': self.engine.router_port,
            'router_mac': self.engine.router_mac,
            'vlan_gateways': self.engine.vlan_gateways,
            'stats': self.engine.stats,
            'recent_packets': list(reversed(self.engine.history[-40:])),
        })

    @route('lab9_dhcp', '/lab9/dhcp/config', methods=['POST'])
    def update_config(self, req, **kwargs):
        data = json.loads(req.body.decode('utf-8') or '{}')
        if 'enabled' in data:
            self.engine.enabled = bool(data['enabled'])
        if data.get('action') == 'clear_history':
            self.engine.history.clear()
            self.engine.stats = {
                'total_requests': 0,
                'unicast_rewrites_at_edge': 0,
                'forwarded_hops': 0,
            }
        return self._json({'ok': True, 'enabled': self.engine.enabled, 'stats': self.engine.stats})
