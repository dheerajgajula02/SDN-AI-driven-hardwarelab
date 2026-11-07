#!/usr/bin/env python3
"""Proves on the wire that A3 (DNS filter) and A4 (DHCP to router) work.

A host getting the right answer is not enough: the answer could be right for
the wrong reason. So each check also captures packets on switch ports and on
the router to show where each packet went, and where it did NOT go.

Needs: the network running (lab9_net.py) and Ryu running (start_ryu.sh).
Run on the laptop:
  SSHPASS=<mininet password> python3 lab9/applications/tests/test_dataflow.py
"""

import re
import sys
import time

from mininet_host import capture, on_host, on_root, resolve

BLOCKED = '10.10.20.21'          # blocked-page server (srv1)
GW10, GW20 = '10.10.10.1', '10.10.20.1'
ROUTER_MAC = '00:00:00:00:01:01'
PC2_MAC = '00:00:00:00:10:12'
SWITCHES = ['cisco1', 'arista1', 'arista2', 'hp1', 'ovs1', 'ovs2']

results = []


def check(name, passed, detail=''):
    results.append((name, bool(passed)))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('\n        ' + str(detail)) if detail else ''))
    sys.stdout.flush()


def show(lines, limit=4):
    """A few captured packet lines, shortened, for the report."""
    return '\n        '.join(l.split(' ', 1)[-1][:150] for l in lines[:limit]) or '(no packets)'


def client_to_server(lines):
    """DHCP packets sent by a client (UDP port 68 -> 67)."""
    return [l for l in lines if re.search(r'\.68 > [\d.]+\.67:', l)]


def dhcp(host='pc2'):
    """Ask for a DHCP lease from `host`; True if a lease was obtained."""
    out = on_host(host, 'busybox udhcpc -i %s-eth0 -n -q -t 3 -s /tmp/lab9-udhcpc.sh 2>&1' % host)
    return 'Lease of' in out


# ===========================================================================
# DNS filter (A3)
# ===========================================================================

def test_dns():
    # ---- D1: the protected intercept rules exist on every switch -----------
    out = on_root('for b in %s; do echo "== $b"; ovs-ofctl -O OpenFlow13 dump-flows $b | '
                  'grep -E "cookie=0x(30|40)"; done' % ' '.join(SWITCHES))
    per_switch = out.split('== ')[1:]
    ok = len(per_switch) == 6 and all(
        'priority=50,udp,tp_dst=53' in s and 'tp_src=68,tp_dst=67' in s for s in per_switch)
    check('D1 all 6 switches have the DNS (0x30) and DHCP (0x40) intercept rules, priority 50', ok)

    # Record where r1's DNS log is now, so D7 only looks at this run.
    log_start = int(on_host('r1', 'wc -l < /tmp/r1-dnsmasq.log').strip() or 0)

    # ---- D2: an allowed lookup really goes to the router --------------------
    got = {}
    cap = capture([('root', 'cisco1-eth1')], 53,
                  lambda: got.update(a=resolve('pc1', 'example.com', GW10)))
    at_router = [l for l in cap['cisco1-eth1'] if 'example.com' in l]
    check('D2 allowed: example.com query reaches the router port (cisco1 port 1), real answer',
          at_router and got['a'] and BLOCKED not in got['a'],
          'answer %s\n        %s' % (got['a'], show(at_router, 2)))

    # ---- D3: a blocked lookup never reaches the router ----------------------
    cap = capture([('root', 'cisco1-eth1'), ('pc1', 'pc1-eth0')], 53,
                  lambda: got.update(b=resolve('pc1', 'evil.com', GW10)))
    leaked = [l for l in cap['cisco1-eth1'] if 'evil.com' in l]
    forged = [l for l in cap['pc1-eth0'] if '%s.53 >' % GW10 in l and BLOCKED in l]
    check('D3 blocked: evil.com query NEVER reaches the router port', not leaked and got['b'],
          'router port saw %d evil.com packets' % len(leaked))
    check('D3 blocked: pc1 receives a reply "from 10.10.10.1" pointing to the blocked page',
          got['b'] == [BLOCKED] and forged, show(forged, 1))

    # ---- D4: asking a public resolver directly does not bypass the filter ---
    cap = capture([('pc1', 'pc1-eth0')], 53,
                  lambda: got.update(c=resolve('pc1', 'evil.com', '8.8.8.8'),
                                     d=resolve('pc1', 'example.com', '8.8.8.8')))
    forged = [l for l in cap['pc1-eth0'] if '8.8.8.8.53 >' in l and BLOCKED in l]
    check('D4 bypass attempt: evil.com via 8.8.8.8 is still blocked (forged reply "from 8.8.8.8")',
          got['c'] == [BLOCKED] and forged, show(forged, 1))
    check('D4 bypass check: example.com via 8.8.8.8 is allowed and answered from the Internet',
          got['d'] and BLOCKED not in got['d'], got['d'])

    # ---- D5: the blocked page actually loads over HTTP ----------------------
    out = on_host('pc1', 'dns-test evil.com %s 2>&1' % GW10)
    check('D5 browsing to evil.com loads the blocked page', 'ACCESS_BLOCKED' in out, out.strip()[-90:])

    # ---- D6: VLAN 20 host on an OVS server, Cloudflare verdict --------------
    got['e'] = resolve('vm2', 'phishing.testcategory.com', GW20)
    check('D6 vm2 (VLAN 20, behind ovs2): Cloudflare-flagged domain is blocked', got['e'] == [BLOCKED], got['e'])

    # ---- D7: the router's own log agrees ------------------------------------
    log = on_host('r1', 'tail -n +%d /tmp/r1-dnsmasq.log' % (log_start + 1))
    queries = re.findall(r'query\[\w+\] (\S+) from', log)
    check('D7 router log: example.com was asked; evil.com and phishing.testcategory.com never were',
          'example.com' in queries and 'evil.com' not in queries
          and 'phishing.testcategory.com' not in queries, 'router saw: %s' % sorted(set(queries)))


# ===========================================================================
# DHCP to router (A4)
# ===========================================================================

def test_dhcp():
    # ---- H1: broadcast in at the edge, unicast on every link after it -------
    leak_points = [('pc1', 'pc1-eth0'),          # another VLAN 10 host
                   ('root', 'arista2-eth3'),      # arista2 -> ovs2 trunk (VLAN 10 allowed)
                   ('root', 'arista2-eth4'),      # standby link
                   ('root', 'cisco1-eth2'),       # cisco1 -> arista1 trunk
                   ('root', 'cisco1-eth4'),       # cisco1 -> hp1 trunk
                   ('root', 'arista1-eth3')]      # arista1 -> ovs1 trunk
    path_points = [('pc2', 'pc2-eth0'), ('root', 'arista2-eth1'), ('r1', 'r1-eth0')]
    got = {}
    cap = capture(path_points + leak_points, 67, lambda: got.update(lease=dhcp()), seconds=10)

    sent = client_to_server(cap['pc2-eth0'])
    trunk = client_to_server(cap['arista2-eth1'])
    router = client_to_server(cap['r1-eth0'])
    check('H1 pc2 gets a lease from the router', got['lease'])
    check('H1 pc2 sends a broadcast (ff:ff:ff:ff:ff:ff)',
          sent and all('> ff:ff:ff:ff:ff:ff' in l for l in sent), show(sent, 1))
    check('H1 leaving the edge switch it is unicast to the router MAC, on every request',
          trunk and all('> %s' % ROUTER_MAC in l for l in trunk), show(trunk, 2))
    check('H1 the router receives it addressed to its own MAC',
          router and all('> %s' % ROUTER_MAC in l for l in router), show(router, 1))
    leaks = {i: len(cap[i]) for _, i in leak_points if cap[i]}
    check('H1 no DHCP packet on any other link in the VLAN (6 links watched)', not leaks,
          'leaked onto: %s' % leaks if leaks else 'all 6 links: 0 packets')

    # ---- H2: a client that already has an IP: IP destination rewritten too --
    # Sends a DHCPINFORM from pc2's current address to 255.255.255.255; the
    # controller must change it to the gateway 10.10.10.1 (the branch that
    # changes the IP destination; see dhcp_unicast.py Step 4).
    pc2_ip = re.search(r'inet ([\d.]+)', on_host('pc2', 'ip -4 -o addr show pc2-eth0')).group(1)
    on_root("cat > /tmp/df-inform.py <<'EOF'\n" + INFORM_SCRIPT + "EOF")
    cap = capture([('r1', 'r1-eth0')], 67,
                  lambda: got.update(inform=on_host('pc2', 'python3 /tmp/df-inform.py %s %s'
                                                    % (pc2_ip, PC2_MAC))))
    router = client_to_server(cap['r1-eth0'])
    rewritten = [l for l in router if '%s.68 > %s.67' % (pc2_ip, GW10) in l and '> %s' % ROUTER_MAC in l]
    check('H2 client with an IP (%s): router receives it with IP dst %s and router MAC' % (pc2_ip, GW10),
          rewritten, show(router, 1))
    check('H2 the router answers it (DHCPACK back to pc2)', 'reply type 5' in got['inform'],
          got['inform'].strip())


# Tiny DHCPINFORM client (Python 3 standard library only).
INFORM_SCRIPT = r'''
import random, socket, struct, sys
ip, mac = sys.argv[1], bytes.fromhex(sys.argv[2].replace(':', ''))
xid = random.randint(1, 2**31)
pkt = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', 1, 1, 6, 0, xid, 0, 0,
                  socket.inet_aton(ip), b'\0' * 4, b'\0' * 4, b'\0' * 4,
                  mac + b'\0' * 10, b'\0' * 64, b'\0' * 128)
pkt += b'\x63\x82\x53\x63' + bytes([53, 1, 8, 55, 2, 1, 3, 255])   # INFORM
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 68))
s.settimeout(4)
s.sendto(pkt, ('255.255.255.255', 67))
try:
    while True:
        data, addr = s.recvfrom(1500)
        if data[4:8] == pkt[4:8]:
            i = 240
            while i < len(data) and data[i] != 255:
                if data[i] == 53:
                    print('reply type %d from %s' % (data[i + 2], addr[0]))
                    break
                i += 2 + data[i + 1] if data[i] else 1
            break
except socket.timeout:
    print('no reply')
'''


# ===========================================================================
# Both apps while a link is cut (failover)
# ===========================================================================

def test_failover():
    cut = 'ip link set cisco1-eth3 down; ip link set arista2-eth1 down'
    fix = 'ip link set cisco1-eth3 up; ip link set arista2-eth1 up'
    try:
        # ---- F1: cut cisco1 <-> arista2 (pc2's normal way to the router) ----
        on_root(cut)
        time.sleep(3)
        got = {}
        cap = capture([('root', 'arista2-eth4'), ('root', 'arista2-eth1')], 67,
                      lambda: got.update(lease=dhcp()), seconds=10)
        standby = client_to_server(cap['arista2-eth4'])
        check('F1 link cut: pc2 still gets a lease', got['lease'])
        check('F1 link cut: DHCP goes over the standby link (arista2 port 4), unicast to the router',
              standby and all('> %s' % ROUTER_MAC in l for l in standby), show(standby, 1))
        bad, good = resolve('pc2', 'evil.com', GW10), resolve('pc2', 'example.com', GW10)
        check('F1 link cut: DNS still filtered (evil.com blocked, example.com allowed)',
              bad == [BLOCKED] and good and BLOCKED not in good, 'evil %s, example %s' % (bad, good))
    finally:
        on_root(fix)

    # ---- F2: link restored: back to the normal path ------------------------
    time.sleep(3)
    got = {}
    cap = capture([('root', 'arista2-eth4'), ('root', 'arista2-eth1')], 67,
                  lambda: got.update(lease=dhcp()), seconds=10)
    check('F2 link restored: lease again, via arista2 port 1, nothing on the standby link',
          got['lease'] and client_to_server(cap['arista2-eth1']) and not cap['arista2-eth4'],
          'port 1: %d, standby: %d packets' % (len(cap['arista2-eth1']), len(cap['arista2-eth4'])))


if __name__ == '__main__':
    print('== DNS filter ==')
    test_dns()
    print('\n== DHCP to router ==')
    test_dhcp()
    print('\n== Failover ==')
    test_failover()
    passed = sum(1 for _, ok in results if ok)
    print('\n%d/%d checks passed' % (passed, len(results)))
    sys.exit(0 if passed == len(results) else 1)
