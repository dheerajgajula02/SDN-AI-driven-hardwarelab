#!/usr/bin/env python3
"""A2: configure every switch in the NSOT for OpenFlow, then verify it.

For each switch, nsot.json says:
  mgmt.ip, mgmt.user, mgmt.ssh_key   how to log in to the device (SSH)
  mgmt.driver                        which commands the device understands
  dpid                               the switch ID the controller must see
  openflow.version                   OpenFlow version, e.g. "1.3"
  openflow.transport                 how to reach the controller, e.g. "tcp"
and the "controller" section says where every switch must connect.

Only the "ovs" driver exists so far. On lab day, Arista/HP/Cisco drivers are
added next to it; everything else stays the same.

Run on the controller VM (Python 3.5, standard library only):
  python3 nsot_apply.py              apply the NSOT, then verify
  python3 nsot_apply.py --dry-run    print the commands, change nothing
  python3 nsot_apply.py --verify     only verify
"""

import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

NSOT_PATH = os.environ.get(
    'LAB9_NSOT',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nsot.json'))

# NSOT version text -> the name OVS uses for it.
OVS_PROTOCOLS = {'1.0': 'OpenFlow10', '1.3': 'OpenFlow13'}

# How long to wait for every switch to show up at the controller.
CONNECT_WAIT = 30


def ssh(mgmt, command):
    """Run one command on a device over SSH. Returns (ok, output).

    BatchMode: never stop to ask for a password; fail instead.
    """
    cmd = ['ssh', '-i', os.path.expanduser(mgmt['ssh_key']),
           '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
           '%s@%s' % (mgmt['user'], mgmt['ip']), command]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True, timeout=30)
    except subprocess.TimeoutExpired:
        return False, 'ssh timed out'
    return result.returncode == 0, result.stdout.strip()


# ---------------------------------------------------------------------------
# OVS driver: Open vSwitch, managed with ovs-vsctl.
# ---------------------------------------------------------------------------

def ovs_apply_commands(sw, controller):
    """The commands that put one OVS bridge into the state the NSOT describes.

    One ovs-vsctl call with "--" between parts is one transaction: either all
    of it is applied or none of it.
      protocols        which OpenFlow version the bridge may speak
      datapath-id      the DPID, as 16 hex digits (11 -> 000000000000000b)
      fail-mode secure if the controller is unreachable, forward nothing
                       (the default, standalone, makes OVS act as a plain
                       learning switch and silently bypass the controller)
      set-controller   where to connect, e.g. tcp:10.224.78.132:6633
    """
    bridge = sw['mgmt']['bridge']
    of = sw['openflow']
    target = '%s:%s:%s' % (of['transport'], controller['ip'], controller['openflow_port'])
    return ['sudo -n ovs-vsctl'
            ' set bridge %s protocols=%s other-config:datapath-id=%016x'
            ' -- set-fail-mode %s secure'
            ' -- set-controller %s %s'
            % (bridge, OVS_PROTOCOLS[of['version']], sw['dpid'], bridge, bridge, target)]


def ovs_read_back(sw):
    """Ask the device what it is actually configured with."""
    bridge = sw['mgmt']['bridge']
    # Prints 3 or 4 lines, e.g.:
    #   ["OpenFlow13"]                          protocols ([] if not set)
    #   {datapath-id="000000000000000b"}        other-config ({} if not set)
    #   secure                                  fail_mode ([] if not set)
    #   tcp:10.224.78.132:6633                  controller (no line if not set)
    ok, out = ssh(sw['mgmt'], 'sudo -n ovs-vsctl'
                              ' get bridge %s protocols other-config fail_mode'
                              ' -- get-controller %s' % (bridge, bridge))
    if not ok:
        return {'error': out}
    lines = out.splitlines() + ['']
    match = re.search(r'datapath-id="?([0-9a-fA-F]+)', lines[1])
    return {'protocols': lines[0].strip('[]').replace('"', ''),
            'dpid': int(match.group(1), 16) if match else None,
            'fail_mode': lines[2].strip('[]'),
            'controller': lines[3]}


def ovs_read_ports(sw):
    """OpenFlow port numbers on the bridge. Returns ({port: interface}, error)."""
    bridge = sw['mgmt']['bridge']
    ok, out = ssh(sw['mgmt'], 'for i in $(sudo -n ovs-vsctl list-ifaces %s); do '
                              'echo "$i $(sudo -n ovs-vsctl get interface $i ofport)"; done'
                              % bridge)
    if not ok:
        return None, out
    ports = {}
    for line in out.splitlines():
        name, ofport = line.split()
        if ofport.isdigit():              # skip ports OVS has not numbered ([] or -1)
            ports[int(ofport)] = name
    return ports, None


DRIVERS = {
    'ovs': {'apply': ovs_apply_commands, 'read_back': ovs_read_back,
            'read_ports': ovs_read_ports},
}


# ---------------------------------------------------------------------------

def check_switch(name, sw, mgmt_subnet=None):
    """Refuse NSOT values this script cannot apply. Returns an error or None."""
    of = sw.get('openflow', {})
    if sw.get('mgmt', {}).get('driver') not in DRIVERS:
        return 'no driver for %r' % sw.get('mgmt', {}).get('driver')
    if of.get('version') not in OVS_PROTOCOLS:
        return 'unsupported OpenFlow version %r' % of.get('version')
    if of.get('transport') != 'tcp':
        return 'transport %r not supported yet (only tcp)' % of.get('transport')
    if mgmt_subnet:
        net = ipaddress.ip_network(mgmt_subnet)
        ip = ipaddress.ip_address(sw['mgmt']['ip'])
        if ip not in net:
            return 'mgmt.ip %s is outside management subnet %s' % (ip, net)
    return None


def expected_settings(sw, controller):
    """What the device's OpenFlow settings must be, according to the NSOT."""
    of = sw['openflow']
    return {
        'protocols': OVS_PROTOCOLS[of['version']],
        'dpid': sw['dpid'],
        'fail_mode': 'secure',
        'controller': '%s:%s:%s' % (of['transport'], controller['ip'],
                                    controller['openflow_port']),
    }


def controller_dpids(controller):
    """DPIDs the controller currently has a session with (Ryu REST API).

    This script runs on the controller, so it asks 127.0.0.1.
    """
    url = 'http://127.0.0.1:%s/stats/switches' % controller['rest_port']
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return set(json.loads(r.read().decode()))
    except Exception:
        return set()


def apply_all(nsot, dry_run):
    """Push the NSOT to every switch. Returns the names that failed."""
    failed = []
    mgmt_subnet = nsot.get('management', {}).get('subnet')
    for name, sw in sorted(nsot['switches'].items(), key=lambda kv: kv[1]['dpid']):
        problem = check_switch(name, sw, mgmt_subnet)
        if problem:
            print('  %-8s SKIPPED: %s' % (name, problem))
            failed.append(name)
            continue
        driver = DRIVERS[sw['mgmt']['driver']]
        for command in driver['apply'](sw, nsot['controller']):
            if dry_run:
                print('  %-8s would run on %s: %s' % (name, sw['mgmt']['ip'], command))
                continue
            ok, out = ssh(sw['mgmt'], command)
            print('  %-8s %s%s' % (name, 'applied' if ok else 'FAILED', '' if ok else ': ' + out))
            if not ok:
                failed.append(name)
    return failed


def verify_all(nsot):
    """Check each switch on both sides: the device's own settings, and
    whether the controller sees its DPID. Returns True if all are correct."""
    switches = nsot['switches']
    controller = nsot['controller']
    wanted = set(sw['dpid'] for sw in switches.values())

    # Give the switches time to connect after a change.
    deadline = time.time() + CONNECT_WAIT
    seen = controller_dpids(controller)
    while not wanted <= seen and time.time() < deadline:
        time.sleep(2)
        seen = controller_dpids(controller)

    print('  %-8s %-5s %-12s %-10s %-26s %-10s %s'
          % ('switch', 'dpid', 'protocols', 'fail_mode', 'controller', 'ctl sees', 'result'))
    all_ok = True
    mgmt_subnet = nsot.get('management', {}).get('subnet')
    for name, sw in sorted(switches.items(), key=lambda kv: kv[1]['dpid']):
        problem = check_switch(name, sw, mgmt_subnet)
        if problem:
            print('  %-8s %-5s (cannot verify: %s)' % (name, sw['dpid'], problem))
            all_ok = False
            continue
        actual = DRIVERS[sw['mgmt']['driver']]['read_back'](sw)
        if 'error' in actual:
            print('  %-8s %-5s read back FAILED: %s' % (name, sw['dpid'], actual['error']))
            all_ok = False
            continue
        expected = expected_settings(sw, controller)
        wrong = sorted(k for k in expected if actual[k] != expected[k])
        sees = sw['dpid'] in seen
        ok = not wrong and sees
        all_ok = all_ok and ok
        print('  %-8s %-5s %-12s %-10s %-26s %-10s %s'
              % (name, actual['dpid'], actual['protocols'], actual['fail_mode'],
                 actual['controller'], 'yes' if sees else 'NO',
                 'OK' if ok else 'WRONG: ' + ', '.join(wrong or ['not connected'])))

    extra = seen - wanted
    if extra:
        print('  controller also sees DPIDs not in the NSOT: %s' % sorted(extra))
    return all_ok


def main():
    dry_run = '--dry-run' in sys.argv
    verify_only = '--verify' in sys.argv
    with open(NSOT_PATH) as f:
        nsot = json.load(f)
    print('NSOT: %s (%d switches)' % (NSOT_PATH, len(nsot['switches'])))

    failed = []
    if not verify_only:
        print('\n== apply%s ==' % (' (dry run, nothing changed)' if dry_run else ''))
        failed = apply_all(nsot, dry_run)
        if dry_run:
            return 0

    print('\n== verify ==')
    ok = verify_all(nsot)
    print('\nRESULT: %s' % ('all switches match the NSOT and are connected'
                            if ok and not failed else 'PROBLEMS, see above'))
    return 0 if ok and not failed else 1


if __name__ == '__main__':
    sys.exit(main())
