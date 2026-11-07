"""Offline test: the NSOT loader accepts the real NSOT and refuses broken ones.

Run on the controller VM (needs the Ryu venv, because it imports the app):
  /home/sdn/ryu-py3/bin/python3 part_a/tests/test_nsot_loader.py
"""
import copy
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
os.environ['LAB9_NSOT'] = os.path.join(HERE, 'nsot_step1.json')
import vlan_switch_13 as v

REAL = os.path.join(HERE, '..', 'nsot.json')


def try_load(nsot):
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(nsot, f)
    try:
        return 'loaded %d switches' % len(v.load_ports(f.name))
    except ValueError as e:
        return 'REFUSED: %s' % e
    finally:
        os.unlink(f.name)


good = json.load(open(REAL))
print('real nsot.json -> %s' % try_load(good))
print('  ports: %s' % v.load_ports(REAL))


def broken(label, change):
    nsot = copy.deepcopy(good)
    change(nsot)
    print('%-28s -> %s' % (label, try_load(nsot)))


sw = lambda n, name: n['switches'][name]
broken('duplicate dpid', lambda n: sw(n, 'arista2').update(dpid=11))
broken('one-sided link', lambda n: sw(n, 'ovs1')['ports'].pop('1'))
broken('link VLANs disagree', lambda n: sw(n, 'hp1')['ports']['1'].update(vlans=[20]))
broken('undefined VLAN', lambda n: sw(n, 'arista1')['ports']['2'].update(vlan=30))
broken('unknown port mode', lambda n: sw(n, 'arista1')['ports']['2'].update(mode='hybrid'))
broken('vlan_mode switch', lambda n: sw(n, 'hp1').update(vlan_mode='switch'))
broken('mgmt overlaps VLAN', lambda n: n['management'].update(subnet='10.10.10.0/24'))
broken('switch mgmt on data VLAN', lambda n: sw(n, 'arista1')['mgmt'].update(ip='10.10.10.99'))
