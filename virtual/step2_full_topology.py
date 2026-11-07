#!/usr/bin/env python3
"""Step 2 network: the full Lab 9 topology, built from nsot.json.

SUPERSEDED by lab9_net.py (Step 3), which also builds the router and inet.
This script only understands the Step 2 NSOT (no "routers" section); kept so
the Step 2 build-log entry stays reproducible.

This script only does the "cabling": switches, hosts and links. It then
resets every switch to a bare state (no controller, no OpenFlow version,
no DPID, default fail mode), like a device fresh out of the box.
part_a/nsot_apply.py, run on the controller, must then configure them.

Once every switch is connected to the controller, the checks run.

Run on the Mininet VM (Mininet 2.3.0 for Python 3), with nsot.json next to it:
  sudo python3 step2_full_topology.py           # checks, then the Mininet CLI
  sudo python3 step2_full_topology.py --no-cli  # checks, then exit
"""
import json
import os
import sys
import time

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo

NSOT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nsot.json')
WAIT_FOR_APPLY = 600   # seconds to wait for nsot_apply.py


def show(title, text=''):
    # flush, so this output never mixes with Mininet's own messages
    sys.stdout.write('\n===== %s =====\n%s\n' % (title, text.strip()))
    sys.stdout.flush()


class NsotTopo(Topo):
    def build(self, nsot):
        for name in nsot['switches']:
            self.addSwitch(name)
        for name, host in nsot['hosts'].items():
            self.addHost(name, ip=host['ip'], mac=host['mac'])

        for name, sw in nsot['switches'].items():
            for port, p in sw['ports'].items():
                if ':' not in p['to']:                     # host port
                    self.addLink(p['to'], name, port2=int(port))
                else:                                      # switch link: add once
                    peer, peer_port = p['to'].split(':')
                    if name < peer:
                        self.addLink(name, peer, port1=int(port), port2=int(peer_port))


def reset_to_bare(switches):
    """Remove everything nsot_apply.py is supposed to set."""
    for s in switches:
        s.cmd('ovs-vsctl del-controller %s'
              ' -- clear bridge %s protocols fail_mode'
              ' -- remove bridge %s other-config datapath-id' % (s, s, s))


def bridge_state(switches):
    lines = []
    for s in switches:
        out = s.cmd('ovs-vsctl get bridge %s protocols other-config fail_mode'
                    ' -- get-controller %s' % (s, s))
        lines.append('%-8s %s' % (s.name, ' | '.join(out.split())))
    return '\n'.join(lines)


def is_connected(s):
    # Mininet's own s.connected() caches the controller record, which goes
    # stale when nsot_apply.py replaces it; re-read it every time instead.
    return any('true' in s.vsctl('-- get Controller', uuid, 'is_connected')
               for uuid in s.controllerUUIDs(update=True))


def wait_all_connected(switches, timeout):
    start = time.time()
    while time.time() - start < timeout:
        if all(is_connected(s) for s in switches):
            return True
        time.sleep(2)
    return False


def run_checks(net, nsot):
    switches = net.switches
    hosts = dict((h.name, h) for h in net.hosts)

    show('flows on every switch',
         '\n'.join('--- %s\n%s' % (s.name, s.cmd('ovs-ofctl -O OpenFlow13 dump-flows %s' % s))
                   for s in switches))

    show('pingall (expect only same-VLAN pairs: 8/20 received)')
    net.pingAll(timeout=1)
    sys.stdout.flush()

    show('vm1 -> vm2 (VLAN 20, path ovs1 > arista1 > cisco1 > arista2 > ovs2)',
         hosts['vm1'].cmd('ping -c 2 %s' % nsot['hosts']['vm2']['ip'].split('/')[0]))


def main():
    setLogLevel('info')
    with open(NSOT_PATH) as f:
        nsot = json.load(f)

    net = Mininet(topo=NsotTopo(nsot=nsot), switch=OVSSwitch, controller=None,
                  autoSetMacs=False)
    net.start()
    try:
        reset_to_bare(net.switches)
        show('switches reset to bare (protocols | other-config | fail_mode | controller)',
             bridge_state(net.switches))
        show('waiting', 'run part_a/nsot_apply.py on the controller now '
                        '(waiting up to %d s)' % WAIT_FOR_APPLY)

        if wait_all_connected(net.switches, WAIT_FOR_APPLY):
            show('after nsot_apply (protocols | other-config | fail_mode | controller)',
                 bridge_state(net.switches))
            run_checks(net, nsot)
        else:
            show('timeout', 'not every switch connected')

        if '--no-cli' not in sys.argv:
            CLI(net)
    finally:
        net.stop()


if __name__ == '__main__':
    main()
