#!/usr/bin/env python3
"""The Lab 9 virtual network, built entirely from nsot.json.

1. Cabling: switches, hosts, the router (r1) and the Internet stand-in (inet).
2. Switches are reset to bare; part_a/nsot_apply.py (on the controller) must
   configure them. The script waits until every switch is connected.
3. r1 is configured as the "traditional router" from the NSOT:
     router-on-a-stick  one trunk to the core switch, one VLAN subinterface
                        per VLAN, IP = that VLAN's gateway
     WAN + default route to inet
     NAT (masquerade) toward inet, like Cisco "ip nat inside ... overload"
     DHCP server (dnsmasq) with one pool per VLAN
   Hosts get their VLAN's gateway as default route.
4. Checks run, then the Mininet CLI opens (unless --no-cli).

In the physical lab, r1 is the Cisco router; part_a/render_router.py prints
its IOS config from the same NSOT.

Run on the Mininet VM, with nsot.json next to it:
  sudo python3 lab9_net.py              # Step 3 checks, then the Mininet CLI
  sudo python3 lab9_net.py --no-cli     # Step 3 checks, then exit
  sudo python3 lab9_net.py --failover   # Step 4 link-failure tests instead
"""
import ipaddress
import json
import os
import re
import sys
import time

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo

HERE = os.path.dirname(os.path.abspath(__file__))
NSOT_PATH = os.path.join(HERE, 'nsot.json')
WAIT_FOR_APPLY = 600   # seconds to wait for nsot_apply.py
UDHCPC_SCRIPT = '/tmp/lab9-udhcpc.sh'


def show(title, text=''):
    sys.stdout.write('\n===== %s =====\n%s\n' % (title, text.strip()))
    sys.stdout.flush()


def gateway(nsot, vid):
    return nsot['vlans'][str(vid)]['gateway']


def prefixlen(nsot, vid):
    return ipaddress.ip_network(nsot['vlans'][str(vid)]['subnet']).prefixlen


def host_vlan(nsot, host):
    """The VLAN of the access port the host is plugged into."""
    for sw in nsot['switches'].values():
        for p in sw['ports'].values():
            if p['to'] == host and p['mode'] == 'access':
                return p['vlan']
    return None


def router_vlans(nsot, router):
    """The VLANs on the switch trunk the router is plugged into."""
    sw_name, port = nsot['routers'][router]['lan']['to'].split(':')
    return nsot['switches'][sw_name]['ports'][port]['vlans']


# ---------------------------------------------------------------------------
# 1. Cabling
# ---------------------------------------------------------------------------

class NsotTopo(Topo):
    def build(self, nsot):
        for name in nsot['switches']:
            self.addSwitch(name)

        for name, r in nsot.get('routers', {}).items():
            # Mininet's pingall uses this IP; the live address ends up on the
            # VLAN subinterface (see configure_router).
            first = router_vlans(nsot, name)[0]
            self.addHost(name, ip='%s/%d' % (gateway(nsot, first), prefixlen(nsot, first)),
                         mac=r['lan']['mac'])

        for name, h in nsot['hosts'].items():
            vid = host_vlan(nsot, name)
            self.addHost(name, ip=h['ip'], mac=h['mac'],
                         defaultRoute='via %s' % gateway(nsot, vid))

        for name, e in nsot.get('external', {}).items():
            self.addHost(name, ip=e['ip'], mac=e['mac'])

        # Switch ports (to hosts, routers and other switches), in NSOT order.
        for name, sw in nsot['switches'].items():
            for port, p in sorted(sw['ports'].items(), key=lambda kv: int(kv[0])):
                if ':' not in p['to']:
                    self.addLink(p['to'], name, port2=int(port))
                else:
                    peer, peer_port = p['to'].split(':')
                    if name < peer:
                        self.addLink(name, peer, port1=int(port), port2=int(peer_port))

        # Router WAN links (router <-> external network).
        for name, e in nsot.get('external', {}).items():
            router = e['to'].split(':')[0]
            self.addLink(router, name)


# ---------------------------------------------------------------------------
# 2. Switches: bare, then wait for nsot_apply.py
# ---------------------------------------------------------------------------

def reset_to_bare(switches):
    for s in switches:
        s.cmd('ovs-vsctl del-controller %s'
              ' -- clear bridge %s protocols fail_mode'
              ' -- remove bridge %s other-config datapath-id' % (s, s, s))


def bridge_state(switches):
    return '\n'.join('%-8s %s' % (s.name, ' | '.join(
        s.cmd('ovs-vsctl get bridge %s protocols other-config fail_mode'
              ' -- get-controller %s' % (s, s)).split())) for s in switches)


def is_connected(s):
    return any('true' in s.vsctl('-- get Controller', uuid, 'is_connected')
               for uuid in s.controllerUUIDs(update=True))


def wait_all_connected(switches, timeout):
    start = time.time()
    while time.time() - start < timeout:
        if all(is_connected(s) for s in switches):
            return True
        time.sleep(2)
    return False


# ---------------------------------------------------------------------------
# 3. The router
# ---------------------------------------------------------------------------

def configure_router(net, nsot, name):
    """Turn a Mininet host into the router described in the NSOT."""
    r = nsot['routers'][name]
    node = net.get(name)
    core = net.get(r['lan']['to'].split(':')[0])
    lan = node.connectionsTo(core)[0][0].name           # e.g. r1-eth0
    ext_name = [e for e, v in nsot.get('external', {}).items()
                if v['to'].split(':')[0] == name][0]
    wan = node.connectionsTo(net.get(ext_name))[0][0].name   # e.g. r1-eth1

    cmds = ['ip addr flush dev %s' % lan, 'ip link set %s up' % lan]
    # Router-on-a-stick: one subinterface per VLAN on the trunk.
    for vid in router_vlans(nsot, name):
        sub = '%s.%d' % (lan, vid)
        cmds += ['ip link add link %s name %s type vlan id %d' % (lan, sub, vid),
                 'ip addr add %s/%d dev %s' % (gateway(nsot, vid), prefixlen(nsot, vid), sub),
                 'ip link set %s up' % sub]
    # WAN, default route, forwarding.
    cmds += ['ip addr flush dev %s' % wan,
             'ip addr add %s dev %s' % (r['wan']['ip'], wan),
             'ip link set %s up' % wan,
             'ip route replace default via %s dev %s' % (r['wan']['next_hop'], wan),
             'sysctl -qw net.ipv4.ip_forward=1']
    # NAT: everything leaving the WAN gets the WAN address as source.
    if r.get('nat'):
        cmds += ['iptables -t nat -F POSTROUTING',
                 'iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' % wan]
    for c in cmds:
        out = node.cmd(c)
        if out.strip():
            show('router command output', '%s\n%s' % (c, out))

    # DHCP + DNS server: one DHCP pool per VLAN; real Internet domains are
    # forwarded upstream to 8.8.8.8, and *.lab9.lan resolves to inet (203.0.113.2).
    if r.get('dhcp'):
        ranges = ' '.join('--dhcp-range=%s,%s,12h' % (p['start'], p['end'])
                          for p in r['dhcp'].values())
        subs = ' '.join('--interface=%s.%s' % (lan, vid) for vid in r['dhcp'])
        inet_ip = nsot['external']['inet']['ip'].split('/')[0]
        node.cmd('dnsmasq --conf-file=/dev/null --port=53 --no-resolv'
                 ' --server=8.8.8.8 --address=/lab9.lan/%s'
                 ' --bind-interfaces %s %s'
                 ' --dhcp-leasefile=/tmp/%s-dhcp.leases --pid-file=/tmp/%s-dnsmasq.pid'
                 ' --log-dhcp --log-queries --log-facility=/tmp/%s-dnsmasq.log'
                 % (inet_ip, subs, ranges, name, name, name))
    return lan, wan


def connect_real_internet(net, nsot):
    """Connect the `inet` node (203.0.113.2) out to the VM's real Internet
    while blocking the out-of-band management subnet (10.224.0.0/16) so data
    VLAN hosts can reach real websites (example.com, google.com) through r1
    without ever reaching management IPs."""
    inet = net.get('inet')
    mgmt_subnet = nsot.get('management', {}).get('subnet', '10.224.0.0/16')

    # Create a veth pair between root namespace (lab9-nat) and inet (inet-wan)
    os.system('ip link del lab9-nat 2>/dev/null')
    os.system('ip link add lab9-nat type veth peer name inet-wan')
    os.system('ip link set inet-wan netns %d' % inet.pid)
    os.system('ip addr add 198.51.100.1/30 dev lab9-nat && ip link set lab9-nat up')
    os.system('ip route replace 203.0.113.0/30 via 198.51.100.2 dev lab9-nat')
    os.system('sysctl -qw net.ipv4.ip_forward=1')
    os.system('iptables -t nat -C POSTROUTING -s 203.0.113.0/30 -o eth0 -j MASQUERADE 2>/dev/null || '
              'iptables -t nat -A POSTROUTING -s 203.0.113.0/30 -o eth0 -j MASQUERADE')

    inet.cmd('ip addr add 198.51.100.2/30 dev inet-wan')
    inet.cmd('ip link set inet-wan up')
    inet.cmd('ip route replace default via 198.51.100.1 dev inet-wan')
    inet.cmd('sysctl -qw net.ipv4.ip_forward=1')
    # Enforce out-of-band management isolation: never route data traffic to 10.224.0.0/16
    inet.cmd('iptables -F FORWARD')
    inet.cmd('iptables -A FORWARD -d %s -j DROP' % mgmt_subnet)


def start_web_servers(net, nsot):
    """Start HTTP servers on inet (local test site) and srv1 (blocked page)."""
    connect_real_internet(net, nsot)
    inet, srv1 = net.get('inet', 'srv1')
    for h, label in ((inet, 'REAL_INTERNET_SITE'), (srv1, 'ACCESS_BLOCKED_BY_SDN_CONTROLLER')):
        script = '/tmp/lab9-http-%s.py' % h.name
        with open(script, 'w') as f:
            f.write(
                'from http.server import BaseHTTPRequestHandler, HTTPServer\n'
                'class H(BaseHTTPRequestHandler):\n'
                '    def do_GET(self):\n'
                '        host = self.headers.get("Host", "unknown")\n'
                '        body = ("<h1>%s</h1><p>Host: " + host + " (served by %s)</p>\\n").encode()\n'
                '        self.send_response(200)\n'
                '        self.send_header("Content-Type", "text/html")\n'
                '        self.send_header("Content-Length", str(len(body)))\n'
                '        self.end_headers()\n'
                '        self.wfile.write(body)\n'
                '    def log_message(self, *a): pass\n'
                'HTTPServer(("0.0.0.0", 80), H).serve_forever()\n'
                % (label, h.name)
            )
        h.cmd('python3 %s >/dev/null 2>&1 &' % script)


def stop_router(net, name):
    net.get(name).cmd('kill $(cat /tmp/%s-dnsmasq.pid) 2>/dev/null' % name)
    for h in ('inet', 'srv1'):
        net.get(h).cmd('pkill -f lab9-http-%s.py 2>/dev/null' % h)
    os.system('ip link del lab9-nat 2>/dev/null')


def router_state(net, name):
    node = net.get(name)
    return '\n'.join([
        node.cmd('ip -br addr 2>/dev/null || ip -o -4 addr show'),
        node.cmd('ip route'),
        'ip_forward=' + node.cmd('sysctl -n net.ipv4.ip_forward').strip(),
        node.cmd('iptables -t nat -S POSTROUTING'),
        'dnsmasq pid: ' + node.cmd('cat /tmp/%s-dnsmasq.pid 2>/dev/null' % name).strip(),
    ])


# ---------------------------------------------------------------------------
# 4. Checks
# ---------------------------------------------------------------------------

def ttl_of(host, ip):
    out = host.cmd('ping -c 1 -W 1 %s' % ip)
    m = re.search(r'ttl=(\d+)', out)
    return m.group(1) if m else 'no reply'


def capture(node, intf, seconds, action):
    """Capture on intf while action() runs; returns the tcpdump output."""
    f = '/tmp/lab9-cap-%s.txt' % intf
    node.cmd('timeout %d tcpdump -U -e -nn -i %s icmp or vlan > %s 2>&1 &' % (seconds, intf, f))
    time.sleep(1)
    action()
    time.sleep(seconds)
    return node.cmd('cat %s' % f)


def write_udhcpc_script():
    # busybox udhcpc calls this with the lease in env vars. Only sets the IP
    # and default route, so the VM's /etc/resolv.conf is never touched.
    with open(UDHCPC_SCRIPT, 'w') as f:
        f.write('#!/bin/sh\n'
                'case "$1" in\n'
                '  bound|renew)\n'
                '    ip addr flush dev "$interface"\n'
                '    ip addr add "$ip/$subnet" dev "$interface"\n'
                '    [ -n "$router" ] && ip route replace default via ${router%% *} dev "$interface"\n'
                '    echo "LEASE ip=$ip subnet=$subnet router=$router server=$serverid lease=${lease}s" ;;\n'
                'esac\n')
    os.chmod(UDHCPC_SCRIPT, 0o755)


def run_checks(net, nsot):
    ip = lambda h: (nsot['hosts'].get(h) or nsot['external'][h])['ip'].split('/')[0]
    pc1, pc2, srv1, inet = net.get('pc1', 'pc2', 'srv1', 'inet')
    r1, cisco1 = net.get('r1', 'cisco1')
    lan = r1.connectionsTo(cisco1)[0][1].name           # the switch side: cisco1-eth1

    show('router r1', router_state(net, 'r1'))

    show('pingall: expect 36/42 (all but inet -> inside, blocked by NAT)')
    net.pingAll(timeout=1)
    sys.stdout.flush()

    show('TTL: switched vs routed',
         'pc1 -> pc2  (same VLAN, switched): ttl=%s  expect 64\n'
         'pc1 -> srv1 (VLAN 10 -> 20, via r1): ttl=%s  expect 63\n'
         'pc1 -> inet (via r1 + NAT):          ttl=%s  expect 63'
         % (ttl_of(pc1, ip('pc2')), ttl_of(pc1, ip('srv1')), ttl_of(pc1, ip('inet'))))

    show('router-on-a-stick: cisco1 port 1 (%s) during pc1 -> srv1' % lan,
         capture(cisco1, lan, 3, lambda: pc1.cmd('ping -c 1 %s' % ip('srv1'))))

    show('NAT: what inet sees during pc1 -> inet (source must be 203.0.113.1)',
         capture(inet, 'inet-eth0', 3, lambda: pc1.cmd('ping -c 1 %s' % ip('inet'))))

    ctl_ip = nsot['controller']['ip']
    sw_mgmt_ip = nsot['switches']['cisco1']['mgmt']['ip']
    show('management isolation: data VLAN hosts cannot reach management subnet (%s)'
         % nsot['management']['subnet'],
         'pc1  (VLAN 10) -> controller (%s): %s\n'
         'pc1  (VLAN 10) -> switch mgmt (%s): %s\n'
         'srv1 (VLAN 20) -> controller (%s): %s\n'
         'srv1 (VLAN 20) -> switch mgmt (%s): %s'
         % (ctl_ip, ttl_of(pc1, ctl_ip),
            sw_mgmt_ip, ttl_of(pc1, sw_mgmt_ip),
            ctl_ip, ttl_of(srv1, ctl_ip),
            sw_mgmt_ip, ttl_of(srv1, sw_mgmt_ip)))

    show('flows on cisco1 (port 1 = router)',
         cisco1.cmd('ovs-ofctl -O OpenFlow13 dump-flows cisco1 | grep -v OFPST'))

    write_udhcpc_script()
    show('DHCP: pc2 drops its static IP and asks the router',
         pc2.cmd('busybox udhcpc -i pc2-eth0 -n -q -t 5 -s %s 2>&1' % UDHCPC_SCRIPT) +
         '\n' + pc2.cmd('ip -4 addr show pc2-eth0 | grep inet; ip route') +
         '\nping srv1 from the leased address:\n' + pc2.cmd('ping -c 2 %s' % ip('srv1')) +
         '\nlease table on r1:\n' + r1.cmd('cat /tmp/r1-dhcp.leases'))


def ping_while(host, dst, action, count=80, interval=0.1, action_at=3):
    """Ping dst every `interval` s; run action() after `action_at` s.
    Returns a one-line summary: lost pings, gap, duplicates (a loop sign)."""
    f = '/tmp/lab9-ping-%s.txt' % host.name
    host.cmd('ping -i %s -c %d -W 1 %s > %s 2>&1 &' % (interval, count, dst, f))
    time.sleep(action_at)
    action()
    time.sleep(count * interval - action_at + 2)
    out = host.cmd('cat %s' % f)
    got = set(int(s) for s in re.findall(r'bytes from .*icmp_seq=(\d+)', out))
    lost = [s for s in range(1, count + 1) if s not in got]
    dups = out.count('DUP!')
    where = ('seq %d-%d' % (lost[0], lost[-1])) if lost else '-'
    return ('%d/%d replies, lost %d (%s, ~%.1f s), duplicates %d'
            % (len(got), count, len(lost), where, len(lost) * interval, dups))


def standby_flows(net):
    """Learned flows that use the standby link (port 4 on arista1/arista2)."""
    lines = []
    for name in ('arista1', 'arista2'):
        s = net.get(name)
        for l in s.cmd('ovs-ofctl -O OpenFlow13 dump-flows %s' % name).splitlines():
            if 'in_port=4' in l or 'output:4' in l:
                lines.append('%s: %s' % (name, l.split('priority=')[-1]))
    return '\n'.join(lines) or '(none)'


def run_failover_checks(net, nsot):
    ip = lambda h: nsot['hosts'][h]['ip'].split('/')[0]
    pc1, pc2 = net.get('pc1', 'pc2')
    link = lambda a, b, state: (lambda: net.configLinkStatus(a, b, state))

    show('A. baseline, standby link blocked: pingall (expect 36/42, no storm)')
    net.pingAll(timeout=1)
    show('A. flows using the standby link (expect none)', standby_flows(net))

    show('B. FAILOVER: pc2 -> srv1 every 0.1 s, cut cisco1-arista2 after 3 s',
         ping_while(pc2, ip('srv1'), link('cisco1', 'arista2', 'down')))
    show('B. flows using the standby link (expect some)', standby_flows(net))
    show('B. pingall while cisco1-arista2 is down (expect 36/42)')
    net.pingAll(timeout=1)

    show('C. RECOVERY: pc2 -> srv1 every 0.1 s, restore cisco1-arista2 after 3 s',
         ping_while(pc2, ip('srv1'), link('cisco1', 'arista2', 'up')))
    show('C. flows using the standby link (expect none: blocked again)', standby_flows(net))
    show('C. pingall after recovery (expect 36/42)')
    net.pingAll(timeout=1)

    show('D. other side: pc1 -> srv1, cut cisco1-arista1',
         ping_while(pc1, ip('srv1'), link('cisco1', 'arista1', 'down')))
    show('D. restore cisco1-arista1',
         ping_while(pc1, ip('srv1'), link('cisco1', 'arista1', 'up')))

    show('E. LIMIT: pc1 -> srv1, cut cisco1-hp1 (no backup; expect loss until restored)',
         ping_while(pc1, ip('srv1'), link('cisco1', 'hp1', 'down')))
    net.configLinkStatus('cisco1', 'hp1', 'up')
    time.sleep(2)
    show('E. pingall after restoring cisco1-hp1 (expect 36/42)')
    net.pingAll(timeout=1)
    sys.stdout.flush()


def run_dns_checks(net, nsot):
    """Objective 3 (A3): test allowed vs blacklisted DNS queries + blocked page."""
    pc1, r1, arista1 = net.get('pc1', 'r1', 'arista1')
    dns_server = nsot['vlans']['10']['gateway']   # 10.10.10.1 (r1)

    # Warm up ARP/routing so pc1 can reach r1, srv1 (blocked page), and inet (real site)
    pc1.cmd('ping -c 1 -W 1 %s >/dev/null 2>&1' % dns_server)
    pc1.cmd('ping -c 1 -W 1 %s >/dev/null 2>&1' % nsot['hosts']['srv1']['ip'].split('/')[0])
    pc1.cmd('ping -c 1 -W 1 %s >/dev/null 2>&1' % nsot['external']['inet']['ip'].split('/')[0])

    show('A3.1 DNS intercept flow on arista1 (expect priority=50, cookie=0x30, udp,tp_dst=53 -> CONTROLLER)',
         arista1.cmd('ovs-ofctl -O OpenFlow13 dump-flows arista1 | grep tp_dst=53'))

    # Write a tiny helper on the VM that performs a standard UDP/53 DNS A-query
    # to `dns_server` and then fetches http://<resolved_ip>/ with Host: <domain>
    probe = '/tmp/lab9-dns-probe.py'
    with open(probe, 'w') as f:
        f.write(
            '#!/usr/bin/env python3\n'
            'import random, re, socket, struct, subprocess, sys\n'
            'domain = sys.argv[1]\n'
            'server = sys.argv[2] if len(sys.argv) > 2 else "10.10.10.1"\n'
            'txid = random.randint(1, 65534)\n'
            'qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".")) + b"\\x00"\n'
            'pkt = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)\n'
            's = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n'
            's.settimeout(4.0)\n'
            's.sendto(pkt, (server, 53))\n'
            'resp, _ = s.recvfrom(512)\n'
            'ip = socket.inet_ntoa(resp[-4:])\n'
            'print("1. DNS Reply (%s:53): %s -> %s" % (server, domain, ip))\n'
            'if ip == "10.10.20.21":\n'
            '    out = subprocess.check_output(["curl", "-s", "-m", "4", "-H", "Host: " + domain, "http://10.10.20.21/"]).decode("utf-8", errors="ignore")\n'
            'else:\n'
            '    out = subprocess.check_output(["curl", "-sL", "-m", "5", "--resolve", "%s:80:%s" % (domain, ip), "http://" + domain]).decode("utf-8", errors="ignore")\n'
            'snippet = " ".join(out.split())\n'
            'm = re.search(r"<(h1|title)[^>]*>(.*?)</\\1>", snippet, re.I)\n'
            'print("2. Browser / HTTP Page:    %s" % (m.group(0) if m else snippet[:120]))\n'
        )
    os.system('install -m 755 %s /usr/local/bin/dns-test' % probe)

    for dom, expect in (
        ('example.com',               'ALLOW -> real Internet IP (<title>Example Domain</title>)'),
        ('phishing.testcategory.com', 'BLOCK by Cloudflare 1.1.1.3 JSON -> 10.10.20.21 (ACCESS_BLOCKED)'),
        ('evil.com',                  'BLOCK by custom blacklist -> 10.10.20.21 (ACCESS_BLOCKED)'),
        ('good.lab9.lan',             'ALLOW -> 203.0.113.2 (REAL_INTERNET_SITE)'),
        ('bad.lab9.lan',              'BLOCK -> 10.10.20.21 (ACCESS_BLOCKED_BY_SDN_CONTROLLER)'),
    ):
        show('A3 DNS + HTTP test from pc1: %s (expect %s)' % (dom, expect),
             pc1.cmd('dns-test %s %s 2>&1' % (dom, dns_server)))

    show('A3 r1 dnsmasq log (blocked domains must NOT appear here — controller intercepted them)',
         r1.cmd('tail -n 20 /tmp/r1-dnsmasq.log'))
    sys.stdout.flush()


def run_dhcp_checks(net, nsot):
    """Objective 4 (A4): prove edge DHCP broadcasts are rewritten to unicast
    toward the router and never flooded to other hosts in the VLAN."""
    pc1, pc2, r1 = net.get('pc1', 'pc2', 'r1')
    arista2, cisco1 = net.get('arista2', 'cisco1')
    trunk_intf = arista2.connectionsTo(cisco1)[0][0].name   # arista2-eth1

    write_udhcpc_script()
    show('A4.1 DHCP intercept flow on arista2 (expect priority=50, cookie=0x40, udp,tp_src=68,tp_dst=67 -> CONTROLLER)',
         arista2.cmd('ovs-ofctl -O OpenFlow13 dump-flows arista2 | grep tp_dst=67'))

    # Capture simultaneously on:
    #   1. pc2-eth0     (what pc2 sends: broadcast ff:ff:ff:ff:ff:ff / 255.255.255.255)
    #   2. arista2-eth1 (leaving edge switch on trunk: must be UNICAST 00:00:00:00:01:01 / 10.10.10.1)
    #   3. pc1-eth0     (another VLAN 10 host: must see 0 DHCP packets — no flood!)
    pc2.cmd('timeout 5 tcpdump -U -e -nn -i pc2-eth0 udp port 67 or port 68 > /tmp/cap-pc2.txt 2>&1 &')
    arista2.cmd('timeout 5 tcpdump -U -e -nn -i %s vlan and udp port 67 or port 68 > /tmp/cap-trunk.txt 2>&1 &' % trunk_intf)
    pc1.cmd('timeout 5 tcpdump -U -e -nn -i pc1-eth0 udp port 67 or port 68 > /tmp/cap-pc1.txt 2>&1 &')
    time.sleep(1)

    lease_out = pc2.cmd('busybox udhcpc -i pc2-eth0 -n -q -t 3 -s %s 2>&1' % UDHCPC_SCRIPT)
    time.sleep(4)

    show('A4.2 pc2 DHCP client output + leased address',
         lease_out + '\n' + pc2.cmd('ip -4 addr show pc2-eth0 | grep inet'))
    show('A4.3 BEFORE edge switch (pc2-eth0): host sends BROADCAST (ff:ff:ff:ff:ff:ff / 255.255.255.255)',
         pc2.cmd('cat /tmp/cap-pc2.txt'))
    show('A4.4 AFTER edge switch (%s trunk): rewritten to UNICAST frame (eth dst 00:00:00:00:01:01)' % trunk_intf,
         arista2.cmd('cat /tmp/cap-trunk.txt'))
    show('A4.5 OTHER VLAN 10 HOST (pc1-eth0): expect 0 packets captured (never flooded)',
         pc1.cmd('cat /tmp/cap-pc1.txt'))
    sys.stdout.flush()


def main():
    setLogLevel('info')
    with open(NSOT_PATH) as f:
        nsot = json.load(f)

    net = Mininet(topo=NsotTopo(nsot=nsot), switch=OVSSwitch, controller=None,
                  autoSetMacs=False)
    net.start()
    try:
        for name in nsot.get('routers', {}):
            configure_router(net, nsot, name)
        start_web_servers(net, nsot)

        reset_to_bare(net.switches)
        show('switches reset to bare (protocols | other-config | fail_mode | controller)',
             bridge_state(net.switches))
        show('waiting', 'run part_a/nsot_apply.py on the controller now '
                        '(waiting up to %d s)' % WAIT_FOR_APPLY)

        if wait_all_connected(net.switches, WAIT_FOR_APPLY):
            show('after nsot_apply', bridge_state(net.switches))
            if '--failover' in sys.argv:
                run_failover_checks(net, nsot)
            elif '--dns' in sys.argv:
                run_dns_checks(net, nsot)
            elif '--dhcp' in sys.argv:
                run_dhcp_checks(net, nsot)
            else:
                run_checks(net, nsot)
                run_dns_checks(net, nsot)
                run_dhcp_checks(net, nsot)
        else:
            show('timeout', 'not every switch connected')

        if '--no-cli' not in sys.argv:
            CLI(net)
    finally:
        for name in nsot.get('routers', {}):
            stop_router(net, name)
        net.stop()


if __name__ == '__main__':
    main()
