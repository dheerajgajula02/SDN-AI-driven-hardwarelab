"""Lab 9: VLAN-aware learning switch (OpenFlow 1.3).

The controller, not the switch, decides VLAN membership and applies tags:
  packet enters an access port -> it belongs to that port's VLAN (arrives untagged)
  packet enters a trunk port   -> it belongs to the VLAN in its 802.1Q tag
  leaving on a trunk           -> the packet must carry the tag
  leaving on an access port    -> the packet must not carry the tag

Port roles come from the NSOT (nsot.json next to this file, or the file named
by the LAB9_NSOT environment variable).

Run on the controller VM:
  ryu-manager3 vlan_switch_13.py ryu.app.ofctl_rest
"""

import ipaddress
import json
import os
import sys

# Allow importing `applications.*` from the parent `lab9/` directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib.packet import ether_types, ethernet, packet, udp, vlan
from ryu.ofproto import ofproto_v1_3

from applications import console, dhcp_unicast, dns_blacklist, sdn_trace


# nsot.json sits next to this file. Setting LAB9_NSOT points the app at another
# file (e.g. the physical-lab NSOT) without editing code.
NSOT_PATH = os.environ.get(
    'LAB9_NSOT',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nsot.json'))


def load_ports(path):
    """Read the NSOT and build the port-role map the app uses.

    Returns {dpid: {port: role}}:
      key   = switch DPID (the switch's OpenFlow ID number)
      value = {port number: role}
        ('access', 10)       one host plugged in, untagged, belongs to VLAN 10
        ('trunk', [10, 20])  link between switches, tagged, carries VLANs 10 and 20

    Stops with a clear error if the file disagrees with itself, so a typo
    fails at start-up instead of showing up later as silent packet loss.
    """
    with open(path) as f:
        nsot = json.load(f)
    switches = nsot['switches']
    known_vlans = set(int(v) for v in nsot['vlans'])

    # Out-of-band management check: the management subnet must never overlap
    # any data VLAN subnet, and the controller + switch management IPs must
    # live inside the management subnet.
    mgmt_net = None
    if 'management' in nsot:
        mgmt_net = ipaddress.ip_network(nsot['management']['subnet'])
        for vid, vinfo in nsot['vlans'].items():
            vlan_net = ipaddress.ip_network(vinfo['subnet'])
            if mgmt_net.overlaps(vlan_net):
                raise ValueError('management subnet %s overlaps VLAN %s (%s)'
                                 % (mgmt_net, vid, vlan_net))
        ctl_ip = ipaddress.ip_address(nsot['controller']['ip'])
        if ctl_ip not in mgmt_net:
            raise ValueError('controller ip %s is not in management subnet %s'
                             % (ctl_ip, mgmt_net))

    ports = {}
    for name, sw in switches.items():
        dpid = sw['dpid']
        if dpid in ports:
            raise ValueError('duplicate dpid %s (%s)' % (dpid, name))
        if sw['vlan_mode'] != 'controller':
            # 'switch' mode (vendor switch keeps its own VLANs) is not built yet.
            raise ValueError('%s: vlan_mode %r not supported yet' % (name, sw['vlan_mode']))
        if mgmt_net and 'mgmt' in sw:
            sw_ip = ipaddress.ip_address(sw['mgmt']['ip'])
            if sw_ip not in mgmt_net:
                raise ValueError('%s: mgmt ip %s is not in management subnet %s'
                                 % (name, sw_ip, mgmt_net))

        ports[dpid] = {}
        for port_str, p in sw['ports'].items():
            where = '%s port %s' % (name, port_str)

            if p['mode'] == 'access':
                role = ('access', p['vlan'])
                used = [p['vlan']]
            elif p['mode'] == 'trunk':
                role = ('trunk', list(p['vlans']))
                used = p['vlans']
            else:
                raise ValueError('%s: unknown mode %r' % (where, p['mode']))

            if not set(used) <= known_vlans:
                raise ValueError('%s: VLAN %s is not in the vlans section' % (where, used))

            # A link between switches must be listed the same way at both ends.
            if ':' in p['to']:
                peer, peer_port = p['to'].split(':')
                back = switches.get(peer, {}).get('ports', {}).get(peer_port)
                if back is None or back['to'] != '%s:%s' % (name, port_str):
                    raise ValueError('%s: link to %s has no matching entry there'
                                     % (where, p['to']))
                if (back['mode'] != p['mode'] or back.get('vlans') != p.get('vlans')
                        or bool(back.get('standby')) != bool(p.get('standby'))):
                    raise ValueError('%s: both ends of the link to %s must match'
                                     ' (mode, vlans, standby)' % (where, p['to']))

            ports[dpid][int(port_str)] = role   # JSON keys are text; OpenFlow ports are numbers

    return ports


def load_links(path):
    """Every switch-to-switch cable in the NSOT, each listed once.

    Returns a list of ((dpid_a, port_a), (dpid_b, port_b), standby), e.g.
      ((1, 2), (11, 1), False)    cisco1 port 2  <->  arista1 port 1
      ((11, 4), (12, 4), True)    arista1 port 4 <->  arista2 port 4, standby link

    The NSOT lists every link at both ends (load_ports checks they agree),
    so only the end whose switch name sorts first is kept.

    Host and router ports are not links: they can never create a loop.
    """
    with open(path) as f:
        nsot = json.load(f)
    switches = nsot['switches']

    links = []
    for name, sw in switches.items():
        for port_str, p in sw['ports'].items():
            if ':' not in p['to']:
                continue                      # a host or router, not a switch
            peer, peer_port = p['to'].split(':')
            if name < peer:                   # keep each link once
                links.append(((sw['dpid'], int(port_str)),
                              (switches[peer]['dpid'], int(peer_port)),
                              bool(p.get('standby', False))))
    return links


def blocked_ports(links, down):
    """Decide which ports to block so the network has no loops.

    links: from load_links(), e.g. [((1, 2), (11, 1), False), ...]
    down:  set of (dpid, port) that are currently down, e.g. {(1, 3), (12, 1)}

    Returns the set of (dpid, port) to block. Example with the standby link
    arista1:4 <-> arista2:4 and everything up:  {(11, 4), (12, 4)}

    How: build a loop-free tree one link at a time (Kruskal's algorithm).
    A link that would connect two switches that are ALREADY connected some
    other way would close a loop, so it is left out and its ports blocked.
    """

    # Step 1: every switch starts in its own group (not connected to anyone).
    #         group[dpid] = the label of the group the switch is in.
    group = {}
    for (dpid_a, _), (dpid_b, _), _ in links:
        group[dpid_a] = dpid_a
        group[dpid_b] = dpid_b

    # Step 2: try normal links first and standby links last, so a standby
    #         link only joins the tree if nothing else can connect those
    #         switches. Ties are sorted by port, so the result is always the same.
    ordered = sorted(links, key=lambda link: (link[2], link[0], link[1]))

    blocked = set()
    for end_a, end_b, standby in ordered:
        # Step 3: a link with either end down carries nothing; skip it.
        if end_a in down or end_b in down:
            continue

        group_a = group[end_a[0]]
        group_b = group[end_b[0]]

        if group_a == group_b:
            # Step 4a: both switches are already connected through other
            #          links. Using this one too would make a loop: block it.
            blocked.add(end_a)
            blocked.add(end_b)
        else:
            # Step 4b: this link connects two separate groups: keep it in the
            #          tree, and merge the groups (relabel b's group as a's).
            for dpid in group:
                if group[dpid] == group_b:
                    group[dpid] = group_a

    return blocked


PORTS = load_ports(NSOT_PATH)

# In OpenFlow 1.3 a VLAN id in a rule must include this bit, which means
# "the packet has a VLAN tag". So VLAN 10 is written as 0x1000 + 10 = 4106.
VID_PRESENT = 0x1000

# Every switch-to-switch link, for loop protection and failover.
LINKS = load_links(NSOT_PATH)

# Cookie (a label) put on every flow the app learns. Lets the app delete all
# learned flows at once after a topology change, without touching the
# table-miss rule (cookie 0).
LEARNED = 0x10


class VlanSwitch13(app_manager.RyuApp):
    # Only talk OpenFlow 1.3 to switches. A switch offering only 1.0 is refused.
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        # Let Ryu set up the app first (logging, event handling, etc.).
        super(VlanSwitch13, self).__init__(*args, **kwargs)
        self.logger.info('loaded %d switches from %s', len(PORTS), NSOT_PATH)

        with open(NSOT_PATH) as f:
            self.nsot = json.load(f)

        # Objective 3 (A3): DNS Blacklist engine + Objective 6 REST / Web UI
        self.dns_engine = dns_blacklist.DnsBlacklistEngine(self.nsot, self.logger)
        # Objective 4 (A4): DHCP Unicast engine + Objective 6 REST / Web UI
        self.dhcp_engine = dhcp_unicast.DhcpUnicastEngine(self.nsot, LINKS, self.logger)
        wsgi = kwargs.get('wsgi')
        if wsgi is not None:
            wsgi.register(dns_blacklist.DnsRestController,
                          {'dns_engine': self.dns_engine})
            wsgi.register(dhcp_unicast.DhcpRestController,
                          {'dhcp_engine': self.dhcp_engine})
            # One web console for every app: http://<controller>:8080/lab9/ui
            wsgi.register(console.ConsoleController, {'nsot': self.nsot})
            # Objective 5 (A5): SDN trace. Reads the switches' flow tables
            # through this controller's own REST API (ofctl_rest, /stats/flow).
            rest = 'http://127.0.0.1:%d' % self.nsot['controller']['rest_port']
            self.trace_engine = sdn_trace.TraceEngine(self.nsot, sdn_trace.rest_flow_reader(rest))
            wsgi.register(sdn_trace.TraceRestController, {'trace_engine': self.trace_engine})

        # The controller's memory of where each host is.
        # Kept per switch, then per VLAN, so VLANs never mix:
        #
        #   self.mac_to_port[dpid][vlan][mac] = port
        #
        # Example after pc1 sends a packet into switch 1:
        #   {1: {10: {'00:00:00:00:00:01': 1}}}
        #   -> on switch 1, in VLAN 10, pc1's MAC is behind port 1
        #
        # It starts empty and fills up as packets arrive (learning).
        self.mac_to_port = {}

        # Loop protection / failover state:
        #   datapaths: dpid -> connection, to clear flows on every switch
        #   down:      {(dpid, port)} ports reported down by the switches
        #   blocked:   {(dpid, port)} ports kept out of the tree (no flooding,
        #              incoming packets ignored) so there is no loop
        self.datapaths = {}
        self.down = set()
        self.blocked = blocked_ports(LINKS, self.down)
        self.logger.info('%d switch links, blocked ports: %s',
                         len(LINKS), sorted(self.blocked) or 'none')

    # Runs once per switch, when the switch connects and tells the controller
    # what it can do (the "features reply").
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath         # the switch that just connected
        parser = dp.ofproto_parser   # builds OpenFlow messages for this switch
        ofp = dp.ofproto             # OpenFlow constants (port numbers, flags)

        # Table-miss rule: the safety net at the bottom of the flow table.
        #
        #   match:    empty, so it matches every packet
        #   priority: 0, the lowest, so any other rule wins over it
        #   action:   send the whole packet to the controller
        #
        # Without it the switch silently drops any packet with no rule,
        # and the controller never learns anything.
        #
        # OFPCML_NO_BUFFER: send the full packet, not a short piece of it,
        # so the controller can read the VLAN tag and the addresses.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        # Objective 3 (A3): force all IPv4 UDP/53 (DNS) traffic to the controller
        # at priority 50 (cookie 0x30) so it wins over priority-1 learned flows.
        dns_blacklist.install_dns_intercept_flow(dp)

        # Objective 4 (A4): force all IPv4 UDP 68->67 (DHCP client requests) to
        # the controller at priority 50 (cookie 0x40) so edge broadcast requests
        # are rewritten to unicast and sent directly to the router.
        dhcp_unicast.install_dhcp_intercept_flow(dp)

        self.logger.info('switch %s connected, table-miss + DNS + DHCP rules installed', dp.id)

        # Remember the connection, and ask which of its ports are up or down
        # (a cable may already be unplugged when the switch connects).
        self.datapaths[dp.id] = dp
        dp.send_msg(parser.OFPPortDescStatsRequest(dp, 0))

    def add_flow(self, dp, priority, match, actions, idle_timeout=0, cookie=0):
        """Install one rule on a switch.

        priority:     higher number wins when several rules match a packet
        match:        which packets the rule applies to
        actions:      what to do with them (tag, untag, output, ...)
        idle_timeout: seconds without traffic before the switch deletes the
                      rule; 0 means keep it forever
        cookie:       a label on the rule (LEARNED for learned paths)
        """
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # OpenFlow 1.3 wraps actions in an "instruction".
        # APPLY_ACTIONS means: run these actions on the packet right away.
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        # FlowMod is the OpenFlow message that adds a rule to the flow table.
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle_timeout,
                                cookie=cookie)
        dp.send_msg(mod)

    def ports_in_vlan(self, dpid, vid):
        """Return every port on this switch that carries VLAN vid.

        Used when flooding: a packet whose destination is unknown is sent to
        every port in its VLAN, and only those, so VLANs stay separate.

        Returns a list of (port, role) pairs, for example on switch 1:
          ports_in_vlan(1, 10) -> [(1, 'access'), (3, 'trunk')]
          ports_in_vlan(1, 20) -> [(2, 'access'), (3, 'trunk')]

        The role is returned too, because the caller needs it to decide
        whether the packet leaves that port tagged (trunk) or untagged (access).
        """
        result = []

        # PORTS.get(dpid, {}): a switch missing from PORTS has no ports,
        # so nothing gets flooded on it (safe default instead of a crash).
        for port, (role, vlans) in PORTS.get(dpid, {}).items():
            # never flood out a blocked port (loop) or a port that is down
            if not self.usable(dpid, port):
                continue
            # access port: vlans is one number, e.g. 10
            if role == 'access' and vlans == vid:
                result.append((port, role))
            # trunk port: vlans is a list, e.g. [10, 20]
            elif role == 'trunk' and vid in vlans:
                result.append((port, role))

        return result


    # the whole point of this function is basically making it act like a vlan switch
    def egress_actions(self, parser, vid, arrived_tagged, out_ports):
        """Build the actions that send one packet out of one or more ports,
        with the VLAN tag correct on each port.

        parser:         builds OpenFlow actions for this switch
        vid:            the packet's VLAN, e.g. 10
        arrived_tagged: True if the packet came in on a trunk (has a tag),
                        False if it came in on an access port (no tag)
        out_ports:      list of (port, role) to send to, e.g.
                        [(1, 'access'), (3, 'trunk')]

        The rule is simple:
          out a trunk port  -> the packet must have the tag
          out an access port -> the packet must not have the tag

        The tricky part: OpenFlow runs actions in order, on one copy of the
        packet. Changing the tag affects every output after it. So:
          1. first output to the ports that want the packet as it arrived
          2. then change the tag once (add it, or remove it)
          3. then output to the remaining ports

        Example A - pc1 (untagged, VLAN 10) floods on switch 1:
          out_ports = [(3, 'trunk')]
          -> push_vlan, set vlan_vid=4106, output:3

        Example B - tagged VLAN 10 arrives from the trunk, flood on switch 2:
          out_ports = [(1, 'access')]
          -> pop_vlan, output:1

        Example C - pc1 floods on a switch with another VLAN 10 host on port 4:
          out_ports = [(4, 'access'), (3, 'trunk')]
          -> output:4, push_vlan, set vlan_vid=4106, output:3
        """
        # Split the output ports into two groups.
        # A trunk port wants a tag; an access port does not.
        # "same":  ports that want the packet exactly as it arrived
        # "other": ports that need the tag changed first
        same = []
        other = []
        for port, role in out_ports:
            wants_tag = (role == 'trunk')
            if wants_tag == arrived_tagged:
                same.append(port)
            else:
                other.append(port)

        # Step 1: send to the ports that want the packet unchanged.
        actions = [parser.OFPActionOutput(port) for port in same]

        if other:
            # Step 2: change the tag once.
            if arrived_tagged:
                # Came in tagged (from a trunk), going to access ports:
                # remove the 802.1Q tag.
                actions.append(parser.OFPActionPopVlan())
            else:
                # Came in untagged (from an access port), going to trunks:
                # add an empty 802.1Q tag, then write the VLAN number into it.
                # VID_PRESENT | vid = 0x1000 + 10 = 4106 for VLAN 10.
                actions.append(parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q))
                actions.append(parser.OFPActionSetField(vlan_vid=VID_PRESENT | vid))

            # Step 3: send to the remaining ports.
            for port in other:
                actions.append(parser.OFPActionOutput(port))

        # An empty list means "drop". That happens when there is nowhere to send
        # the packet, e.g. the only port in the VLAN is the one it came in on.
        return actions

    # Runs every time a switch sends a packet to the controller. That happens
    # when a packet matches no rule except the table-miss rule.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath            # the switch that sent the packet
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        dpid = dp.id                 # its DPID, to look it up in PORTS
        in_port = msg.match['in_port']  # the port the packet came in on

        # Read the packet's headers.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # LLDP is link-discovery traffic between switches, not user traffic.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # The 802.1Q tag, or None if the packet has no tag.
        tag = pkt.get_protocol(vlan.vlan)

        # ---- Step 1: which VLAN is this packet in? ---------------------------
        # A blocked port (loop protection) or a down port carries nothing:
        # ignore the packet before learning anything from it.
        if not self.usable(dpid, in_port):
            return

        # The port it came in on decides. (None, None) = port not in PORTS.
        role, vlans = PORTS.get(dpid, {}).get(in_port, (None, None))

        if role == 'access' and tag is None:
            # Untagged packet from a host: it belongs to the port's VLAN.
            vid = vlans
        elif role == 'trunk' and tag is not None and tag.vid in vlans:
            # Tagged packet from another switch, and the trunk allows this VLAN.
            vid = tag.vid
        else:
            # Anything else is dropped:
            #   - a port that is not in PORTS
            #   - a tagged packet on an access port (a host trying to hop VLANs)
            #   - an untagged packet on a trunk
            #   - a VLAN the trunk does not allow
            self.logger.debug('drop: dpid=%s port=%s role=%s tag=%s',
                              dpid, in_port, role, tag.vid if tag else None)
            return

        # ---- Step 2: learn where the sender is -------------------------------
        # "On this switch, in this VLAN, this MAC is behind this port."
        # setdefault creates the empty inner dicts the first time.
        table = self.mac_to_port.setdefault(dpid, {}).setdefault(vid, {})
        table[eth.src] = in_port

        # ---- Step 2b (A3): DNS Blacklist check -------------------------------
        # If this packet is a DNS query (UDP dst 53) for a blacklisted domain,
        # dns_engine sends a forged DNS reply pointing to the blocked page server
        # and returns True so we stop here and never forward the blocked query.
        if self.dns_engine.handle_packet(dp, in_port, role, vid, pkt, msg.data):
            return

        # ---- Step 2c (A4): DHCP Unicast to Router ----------------------------
        # If this packet is a DHCP client request (UDP 68 -> 67), dhcp_engine
        # rewrites broadcast -> unicast (router MAC + gateway IP) and sends it
        # out the single port toward r1, returning True so it is never flooded.
        if self.dhcp_engine.handle_packet(dp, in_port, role, vid, pkt, msg.data,
                                          PORTS, self.blocked, self.down):
            return

        udp_hdr = pkt.get_protocol(udp.udp)
        is_dns = bool(udp_hdr and udp_hdr.dst_port == 53)

        # ---- Step 3: where should the packet go? -----------------------------
        if eth.dst in table:
            # Known destination: one port.
            out_port = table[eth.dst]
            if out_port == in_port:
                # Destination is behind the port it came from; nothing to do.
                return
            out_ports = [(out_port, PORTS[dpid][out_port][0])]
        else:
            # Unknown destination (or broadcast, e.g. ARP): flood, but only to
            # ports in this VLAN, and never back out the port it came in on.
            out_ports = [(port, r) for port, r in self.ports_in_vlan(dpid, vid)
                         if port != in_port]

        arrived_tagged = tag is not None
        actions = self.egress_actions(parser, vid, arrived_tagged, out_ports)

        # ---- Step 4: install a rule, but only for a known destination --------
        # Later packets of this conversation then stay in the switch and never
        # reach the controller. Floods get no rule: the destination is not
        # known yet, so the controller has to keep seeing them to learn it.
        # DNS packets (is_dns) always come to the controller via priority 50.
        if eth.dst in table and not is_dns:
            # Match the same things Step 1 looked at: in_port + VLAN tag state.
            #   tagged:   vlan_vid = 0x1000 | vid  ("has tag, VLAN vid")
            #   untagged: vlan_vid = OFPVID_NONE   ("has no tag")
            if arrived_tagged:
                match_vid = VID_PRESENT | vid
            else:
                match_vid = ofp.OFPVID_NONE
            # The SOURCE MAC is matched too (like Ryu's simple_switch_13).
            # Without it, a rule "to pc1 -> port 2" also carries pc2's replies
            # to pc1, so the controller never sees pc2 at this switch, never
            # learns where pc2 is, and floods every packet to pc2 through the
            # controller forever (found by applications/tests/test_trace.py).
            # With eth_src, each new sender/receiver pair reaches the
            # controller once per switch, so both ends are always learned.
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst,
                                    vlan_vid=match_vid)
            # Priority 1 beats the table-miss rule (0).
            # idle_timeout=60: the switch deletes the rule after 60 s of no
            # traffic, so stale rules clean themselves up (e.g. a host moved).
            self.add_flow(dp, 1, match, actions, idle_timeout=60, cookie=LEARNED)
            self.logger.info('flow: dpid=%s vlan=%s in_port=%s src=%s dst=%s -> port %s',
                             dpid, vid, in_port, eth.src, eth.dst, out_port)

        # ---- Step 5: send this packet now ------------------------------------
        # The rule only covers future packets; this one is still waiting at
        # the controller. PacketOut sends it with the same actions.
        # OFP_NO_BUFFER + data: the switch did not keep a copy (table-miss used
        # OFPCML_NO_BUFFER), so the whole packet is sent back.
        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    # =======================================================================
    # Loop protection and failover
    #
    # The switches report every port that goes down or comes back up
    # (OpenFlow PORT_STATUS). After each report the controller rebuilds the
    # loop-free tree (blocked_ports). If the blocked ports changed, every
    # learned path is forgotten so traffic re-learns over the new tree.
    # =======================================================================

    # Port states when a switch connects: the answer to the request sent in
    # switch_features_handler (Ryu also asks once by itself while connecting,
    # hence both dispatcher phases).
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def port_desc_handler(self, ev):
        dp = ev.msg.datapath
        for p in ev.msg.body:
            self.set_port(dp.id, p.port_no, self.is_down(dp, p))
        self.update_tree()

    # A port went down or came back up (cable pulled, switch died, port shut).
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        p = msg.desc
        gone = msg.reason == dp.ofproto.OFPPR_DELETE     # port removed entirely
        self.set_port(dp.id, p.port_no, gone or self.is_down(dp, p))
        self.logger.info('port %s:%s is %s', dp.id, p.port_no,
                         'DOWN' if (dp.id, p.port_no) in self.down else 'up')
        self.update_tree()

    # A switch disconnected from the controller: stop sending it messages.
    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_gone_handler(self, ev):
        if ev.datapath.id in self.datapaths:
            del self.datapaths[ev.datapath.id]
            self.logger.info('switch %s disconnected', ev.datapath.id)

    def is_down(self, dp, p):
        """True if the port has no link, or was shut down administratively."""
        ofp = dp.ofproto
        return bool(p.state & ofp.OFPPS_LINK_DOWN or p.config & ofp.OFPPC_PORT_DOWN)

    def set_port(self, dpid, port, down):
        if down:
            self.down.add((dpid, port))
        else:
            self.down.discard((dpid, port))

    def usable(self, dpid, port):
        """A port may carry traffic only if it is neither blocked nor down."""
        return (dpid, port) not in self.blocked and (dpid, port) not in self.down

    def update_tree(self):
        """Rebuild the loop-free tree. If the blocked ports changed, forget
        every learned path, on the controller and on every switch."""
        new = blocked_ports(LINKS, self.down)
        if new == self.blocked:
            return
        self.logger.info('topology change: blocked ports %s -> %s',
                         sorted(self.blocked) or 'none', sorted(new) or 'none')
        self.blocked = new

        # Forget where hosts are: the next packets flood over the new tree
        # and the paths are learned again.
        self.mac_to_port.clear()

        # Delete every learned flow (cookie LEARNED) on every switch.
        # The table-miss rule has cookie 0, so it stays.
        for dp in self.datapaths.values():
            parser, ofp = dp.ofproto_parser, dp.ofproto
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                cookie=LEARNED, cookie_mask=0xffffffffffffffff,
                match=parser.OFPMatch()))
