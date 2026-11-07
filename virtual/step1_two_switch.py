#!/usr/bin/env python3
"""Step 1 test network: 2 switches, 4 hosts, 1 trunk.

Port numbers match PORTS in part_a/vlan_switch_13.py:

  h1 (VLAN 10) - port 1 -+                      +- port 1 - h3 (VLAN 10)
                         s1 - port 3 ==trunk== port 3 - s2
  h2 (VLAN 20) - port 2 -+                      +- port 2 - h4 (VLAN 20)

All hosts share one subnet (10.0.0.0/24) on purpose: then the only thing that
can stop h1 reaching h2 is VLAN separation, not missing routes.

The switches have no VLAN config. The controller does all VLAN work with flows.

The controller must run with this network's NSOT:
  LAB9_NSOT=part_a/tests/nsot_step1.json part_a/start_ryu.sh

Run on the Mininet VM (Mininet 2.3.0 for Python 3):
  sudo python3 step1_two_switch.py           # run the checks, then open the CLI
  sudo python3 step1_two_switch.py --no-cli  # run the checks and exit
"""
import sys
import time

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

CONTROLLER_IP = '10.224.78.132'   # controller VM, LAN address (not Tailscale)
CONTROLLER_PORT = 6633


class TwoSwitchTopo(Topo):
    def build(self):
        # dpid sets the switch ID the controller sees; it must match PORTS keys.
        s1 = self.addSwitch('s1', dpid='0000000000000001', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', dpid='0000000000000002', protocols='OpenFlow13')

        # Fixed MACs make the flow tables easy to read.
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # port1/port2 pin the switch port numbers so they match PORTS.
        self.addLink(h1, s1, port2=1)
        self.addLink(h2, s1, port2=2)
        self.addLink(s1, s2, port1=3, port2=3)   # the trunk
        self.addLink(h3, s2, port2=1)
        self.addLink(h4, s2, port2=2)


def wait_connected(switches, timeout=15):
    """Wait until every switch has an OpenFlow session to the controller."""
    for _ in range(timeout):
        if all(s.connected() for s in switches):
            return True
        time.sleep(1)
    return False


def show(title, text):
    print('\n===== %s =====\n%s' % (title, text.strip()))


def run_checks(net):
    s1, s2 = net.get('s1', 's2')
    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    ok = wait_connected([s1, s2])
    show('controller connection', '\n'.join(
        '%s connected=%s' % (s.name, s.connected()) for s in (s1, s2)))
    if not ok:
        print('switches did not connect; is the controller running?')
        return

    show('expected', 'h1<->h3 OK (VLAN 10), h2<->h4 OK (VLAN 20), '
                     'every other pair FAILS (different VLANs)')
    net.pingAll(timeout=1)

    # Capture on the trunk and on h1's access port while h1 pings h3.
    #   trunk  s1-eth3: frames must show "vlan 10"
    #   access s1-eth1: frames must have no VLAN tag
    # -U writes each packet immediately; no filter, so tags are never missed.
    for intf in ('s1-eth3', 's1-eth1'):
        s1.cmd('timeout 4 tcpdump -U -e -nn -i %s > /tmp/step1_%s.txt 2>&1 &'
               % (intf, intf))
    time.sleep(1)
    h1.cmd('ping -c 2 10.0.0.3')
    time.sleep(4)   # let both captures finish
    show('trunk s1-eth3 (must be tagged)', s1.cmd('cat /tmp/step1_s1-eth3.txt'))
    show('access s1-eth1 (must be untagged)', s1.cmd('cat /tmp/step1_s1-eth1.txt'))

    for s in (s1, s2):
        show('flows on %s' % s.name,
             s.cmd('ovs-ofctl -O OpenFlow13 dump-flows %s' % s.name))


def main():
    setLogLevel('info')
    net = Mininet(topo=TwoSwitchTopo(), switch=OVSSwitch, controller=None,
                  autoSetMacs=False)
    net.addController('c0', controller=RemoteController,
                      ip=CONTROLLER_IP, port=CONTROLLER_PORT)
    net.start()
    try:
        run_checks(net)
        if '--no-cli' not in sys.argv:
            CLI(net)
    finally:
        net.stop()


if __name__ == '__main__':
    main()
