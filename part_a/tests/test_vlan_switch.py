"""Offline test: feed packets to VlanSwitch13 and print what it would send.

No network needed. A fake switch records the messages the app sends, and each
message is encoded as real OpenFlow 1.3 to catch bad actions/matches.

Run on the controller VM (needs the Ryu venv):
  /home/sdn/ryu-py3/bin/python3 part_a/tests/test_vlan_switch.py
"""
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
# Must be set before the import: the app reads the NSOT when it is imported.
os.environ['LAB9_NSOT'] = os.path.join(HERE, 'nsot_step1.json')
from ryu.lib.packet import arp, ethernet, packet, vlan
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
import vlan_switch_13 as v

PC1, PC2, BCAST = '00:00:00:00:00:01', '00:00:00:00:00:02', 'ff:ff:ff:ff:ff:ff'


class FakeSwitch(object):
    def __init__(self, dpid):
        self.id = dpid
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
        self.sent = []

    def send_msg(self, msg):
        msg.serialize()          # proves the message encodes as valid OpenFlow 1.3
        self.sent.append(msg)


def frame(src, dst, vid=None):
    p = packet.Packet()
    if vid is None:
        p.add_protocol(ethernet.ethernet(dst=dst, src=src, ethertype=0x0806))
    else:
        p.add_protocol(ethernet.ethernet(dst=dst, src=src, ethertype=0x8100))
        p.add_protocol(vlan.vlan(vid=vid, ethertype=0x0806))
    p.add_protocol(arp.arp(src_mac=src, dst_mac=dst))
    p.serialize()
    return p.data


def send(app, sw, in_port, data, label):
    sw.sent = []
    msg = types.SimpleNamespace(datapath=sw, match={'in_port': in_port}, data=data)
    app.packet_in_handler(types.SimpleNamespace(msg=msg))
    print('\n%s' % label)
    if not sw.sent:
        print('   (dropped)')
    for m in sw.sent:
        if isinstance(m, ofproto_v1_3_parser.OFPFlowMod):
            print('   FlowMod  match=%s' % dict(m.match.items()))
            print('            actions=%s' % m.instructions[0].actions)
        else:
            print('   PacketOut actions=%s' % m.actions)


app = v.VlanSwitch13()
s1, s2 = FakeSwitch(1), FakeSwitch(2)

send(app, s1, 1, frame(PC1, BCAST), '1. s1: pc1 ARP broadcast (untagged, port 1)')
send(app, s2, 3, frame(PC1, BCAST, 10), '2. s2: same broadcast arrives tagged 10 on trunk')
send(app, s2, 1, frame(PC2, PC1), '3. s2: pc2 replies to pc1 (pc1 known via trunk)')
send(app, s1, 3, frame(PC2, PC1, 10), '4. s1: reply arrives tagged 10 on trunk (pc1 known on port 1)')
send(app, s1, 1, frame(PC1, BCAST, 20), '5. s1: tagged frame on access port (VLAN hopping)')
send(app, s1, 3, frame(PC1, BCAST, 30), '6. s1: VLAN 30 on trunk (not allowed)')
send(app, s1, 9, frame(PC1, BCAST), '7. s1: port 9 not in PORTS')
print('\nlearned: %s' % app.mac_to_port)
