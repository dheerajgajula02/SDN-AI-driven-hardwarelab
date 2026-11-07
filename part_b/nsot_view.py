"""Lab 9 Part B: read the NSOT the same way everywhere (B1, B2, B3, validator).

The NSOT is the single source of truth: no Part B file hard-codes a switch,
host, port or address. These helpers answer the questions the AI layer keeps
asking: where does a host plug in, what is this MAC, which switch is the core.
Standard library only.
"""


# ===========================================================================
# Function 1: who plugs in where
# ===========================================================================

def attachments(nsot):
    """{device: {'switch', 'port' (int), 'vlan' (int or None)}} for every
    host and router, read from the switches' port lists."""
    out = {}
    for sw, s in nsot['switches'].items():
        for port, p in s['ports'].items():
            # Step 1: "to" without ":" is a host or router, not another switch.
            to = p.get('to', '')
            if to and ':' not in to:
                out[to] = {'switch': sw, 'port': int(port), 'vlan': p.get('vlan')}
    return out


def host_ip(nsot, host):
    """'10.10.10.11' (the NSOT stores '10.10.10.11/24')."""
    return nsot['hosts'][host]['ip'].split('/')[0]


# ===========================================================================
# Function 2: addresses -> names
# ===========================================================================

def mac_names(nsot):
    """{mac: name} for hosts, routers and the external node."""
    names = dict((h['mac'].lower(), n) for n, h in nsot['hosts'].items())
    for n, r in nsot.get('routers', {}).items():
        names[r['lan']['mac'].lower()] = n
    for n, e in nsot.get('external', {}).items():
        names[e['mac'].lower()] = n
    return names


def ip_names(nsot):
    """{ip: name} for hosts, router gateways and the external node."""
    names = dict((host_ip(nsot, n), n) for n in nsot['hosts'])
    r_name = router(nsot)[0]
    for vid, v in nsot['vlans'].items():
        names[v['gateway']] = '%s (VLAN %s gateway)' % (r_name, vid)
    for n, e in nsot.get('external', {}).items():
        names[e['ip'].split('/')[0]] = n
    return names


# ===========================================================================
# Function 3: the router and the core switch
# ===========================================================================

def router(nsot):
    """(name, mac, switch, port) of the (first) router."""
    name = sorted(nsot.get('routers', {}))[0]
    sw, port = nsot['routers'][name]['lan']['to'].split(':')
    return name, nsot['routers'][name]['lan']['mac'].lower(), sw, int(port)


def standby_links(nsot):
    """['arista1:4-arista2:4', ...] (each standby link once)."""
    seen = []
    for sw, s in sorted(nsot['switches'].items()):
        for port, p in sorted(s['ports'].items()):
            if p.get('standby'):
                a, b = '%s:%s' % (sw, port), p['to']
                if '%s-%s' % (b, a) not in seen:
                    seen.append('%s-%s' % (a, b))
    return seen


# ===========================================================================
# Function 4: the network in a few sentences (for prompts)
# ===========================================================================

def describe_network(nsot):
    """A short text description of the network, built ONLY from the NSOT,
    for model prompts (so prompts never hard-code names)."""
    att = attachments(nsot)
    r_name, r_mac, core, r_port = router(nsot)
    # Step 1: switches by role.
    hw = sorted(n for n, s in nsot['switches'].items() if s['vendor'] != 'ovs' and n != core)
    ovs = sorted(n for n, s in nsot['switches'].items() if s['vendor'] == 'ovs')
    lines = ['- Core switch: %s (%s); the router %s plugs into it (port %d).'
             % (core, nsot['switches'][core]['vendor'], r_name, r_port),
             '- Hardware access switches: %s.' % ', '.join('%s (%s)' % (n, nsot['switches'][n]['vendor']) for n in hw),
             '- Open vSwitch servers: %s.' % ', '.join(ovs)]
    # Step 2: hosts per VLAN, with where they plug in.
    for vid, v in sorted(nsot['vlans'].items()):
        hosts = sorted(h for h in nsot['hosts'] if att.get(h, {}).get('vlan') == int(vid))
        lines.append('- VLAN %s (%s, %s): %s.' % (vid, v['name'], v['subnet'], ', '.join(
            '%s %s on %s port %d' % (h, host_ip(nsot, h), att[h]['switch'], att[h]['port']) for h in hosts)))
    # Step 3: the router's job and the standby links.
    lines.append('- %s routes between VLANs and to the Internet (NAT), and serves DHCP and DNS.' % r_name)
    lines.append('- Standby (redundant) links: %s.' % (', '.join(standby_links(nsot)) or 'none'))
    return '\n'.join(lines)
