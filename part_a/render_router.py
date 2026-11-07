#!/usr/bin/env python3
"""Print the Cisco IOS config for each router in the NSOT.

This is the "golden config" for the traditional router, generated from the
same NSOT the controller and the virtual network use. It only prints; it does
not log in to anything. Paste it on the router on lab day (after checking the
interface names in nsot.json against "show ip interface brief").

Run anywhere with Python 3:
  python3 render_router.py            # all routers
  python3 render_router.py r1         # one router
"""

import ipaddress
import json
import os
import sys

NSOT_PATH = os.environ.get(
    'LAB9_NSOT',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nsot.json'))


def router_vlans(nsot, r):
    sw_name, port = r['lan']['to'].split(':')
    return nsot['switches'][sw_name]['ports'][port]['vlans']


def render(nsot, name):
    r = nsot['routers'][name]
    lan, wan = r['lan']['ios_interface'], r['wan']['ios_interface']
    wan_if = ipaddress.ip_interface(r['wan']['ip'])
    vlans = router_vlans(nsot, r)
    nat = r.get('nat')
    out = ['! %s: generated from the NSOT by render_router.py' % name,
           '!', 'hostname %s' % name, '!']

    out += ['interface %s' % wan,
            ' description WAN (Internet)',
            ' ip address %s %s' % (wan_if.ip, wan_if.netmask)]
    out += [' ip nat outside'] if nat else []
    out += [' no shutdown', '!',
            'interface %s' % lan,
            ' description trunk to %s, VLANs %s' % (r['lan']['to'], ','.join(map(str, vlans))),
            ' no ip address', ' no shutdown', '!']

    # Router-on-a-stick: one subinterface per VLAN; IP = the VLAN's gateway.
    for vid in vlans:
        v = nsot['vlans'][str(vid)]
        net = ipaddress.ip_network(v['subnet'])
        out += ['interface %s.%d' % (lan, vid),
                ' description VLAN %d %s' % (vid, v['name']),
                ' encapsulation dot1Q %d' % vid,
                ' ip address %s %s' % (v['gateway'], net.netmask)]
        out += [' ip nat inside'] if nat else []
        out += ['!']

    # DHCP: Cisco hands out the whole subnet minus "excluded-address" ranges,
    # so exclude everything outside the NSOT pool.
    for vid, pool in sorted(r.get('dhcp', {}).items(), key=lambda kv: int(kv[0])):
        v = nsot['vlans'][vid]
        net = ipaddress.ip_network(v['subnet'])
        start, end = ipaddress.ip_address(pool['start']), ipaddress.ip_address(pool['end'])
        first, last = net.network_address + 1, net.broadcast_address - 1
        if start > first:
            out.append('ip dhcp excluded-address %s %s' % (first, start - 1))
        if end < last:
            out.append('ip dhcp excluded-address %s %s' % (end + 1, last))
        out += ['ip dhcp pool VLAN%s' % vid,
                ' network %s %s' % (net.network_address, net.netmask),
                ' default-router %s' % v['gateway'], '!']

    if nat:
        out.append('ip access-list standard NAT_INSIDE')
        for vid in vlans:
            net = ipaddress.ip_network(nsot['vlans'][str(vid)]['subnet'])
            out.append(' permit %s %s' % (net.network_address, net.hostmask))
        out += ['ip nat inside source list NAT_INSIDE interface %s overload' % wan, '!']

    out += ['ip route 0.0.0.0 0.0.0.0 %s' % r['wan']['next_hop'], '!', 'end']
    return '\n'.join(out)


def main():
    with open(NSOT_PATH) as f:
        nsot = json.load(f)
    names = sys.argv[1:] or sorted(nsot.get('routers', {}))
    for name in names:
        print(render(nsot, name))
        print()


if __name__ == '__main__':
    main()
