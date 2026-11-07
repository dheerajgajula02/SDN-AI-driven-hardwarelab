"""Lab 9 Part B: the NSOT validator. Every AI action passes here first.

B2 (intents) and B3 (responses) never install or delete a rule themselves:
they build a proposal, and only a proposal this file accepts is sent to the
controller. The rules come from the NSOT (ai_policy, protected_flows,
flow_cookies, switches, hosts), never from a prompt:

  validate_rule(proposal)   may this rule be INSTALLED?
    1. the switch exists in the NSOT (and is connected)
    2. cookie and priority are the AI's own (ai_policy: 0xB0/0xB1, 20-40)
    3. only allowed match fields, real ports, NSOT hosts/addresses only,
       never the management network, never "match everything"
    4. only allowed actions; "meter" only if the switch has meters
    5. protected-flow simulation: example DNS/DHCP/management packets for
       every host are run through the rule; refused if it would catch one
       that no higher-priority protected rule catches first
    6. conflicts with rules already on the switch (duplicate, or same
       traffic with a different action)
  validate_delete(rule)     may this rule be DELETED? (never a protected one)

Standard library only.
"""

import ipaddress

import nsot_view

# Ryu's ofctl_rest shows OpenFlow 1.0-style names; proposals use OF 1.3 names.
OFCTL_NAMES = {'dl_src': 'eth_src', 'dl_dst': 'eth_dst', 'dl_type': 'eth_type', 'nw_proto': 'ip_proto',
               'nw_src': 'ipv4_src', 'nw_dst': 'ipv4_dst'}
IP_FIELDS = ('ipv4_src', 'ipv4_dst')
MAC_FIELDS = ('eth_src', 'eth_dst')
PORT_FIELDS = ('tcp_src', 'tcp_dst', 'udp_src', 'udp_dst')
BROADCAST = 'ff:ff:ff:ff:ff:ff'


# ===========================================================================
# Function 1: match fields in one naming, and "does a rule match a packet?"
# ===========================================================================

def normalize_match(match):
    """Rule match from ofctl_rest (dl_src, nw_dst, tp_dst, ...) -> OF 1.3
    names (eth_src, ipv4_dst, tcp_dst/udp_dst, ...). Values as given."""
    out = {}
    proto = match.get('nw_proto', match.get('ip_proto'))
    for k, v in match.items():
        if k in ('tp_src', 'tp_dst'):
            # Step 1: tp_* means tcp_* or udp_* depending on the IP protocol.
            k = ('tcp_' if int(proto or 0) == 6 else 'udp_') + k[3:]
        out[OFCTL_NAMES.get(k, k)] = v
    return out


def field_matches(field, want, have):
    """One rule field against one packet field."""
    if field in IP_FIELDS:
        # Step 1: IPs may be written with a mask ("10.10.10.0/24").
        return ipaddress.ip_address(str(have)) in ipaddress.ip_network(str(want), strict=False)
    if field in MAC_FIELDS:
        return str(want).lower() == str(have).lower()
    return int(str(want), 0) == int(str(have), 0)


def rule_matches_packet(match, packet, in_ports):
    """True if `match` (OF 1.3 names) catches `packet`.
    in_ports: the ports the packet can arrive on at this switch (a set);
    the rule's in_port must be one of them."""
    for k, want in match.items():
        if k == 'in_port':
            if int(want) not in in_ports:
                return False
        elif k not in packet:
            return False                   # e.g. rule needs TCP, packet is UDP
        elif not field_matches(k, want, packet[k]):
            return False
    return True


def matches_overlap(a, b):
    """True if some packet could match both matches: every field they share
    must agree (IP ranges overlapping)."""
    for k in set(a) & set(b):
        if k in IP_FIELDS:
            na = ipaddress.ip_network(str(a[k]), strict=False)
            nb = ipaddress.ip_network(str(b[k]), strict=False)
            if not na.overlaps(nb):
                return False
        elif k in MAC_FIELDS:
            if str(a[k]).lower() != str(b[k]).lower():
                return False
        elif int(str(a[k]), 0) != int(str(b[k]), 0):
            return False
    return True


# ===========================================================================
# Function 2: the protected packets (built from the NSOT, for every host)
# ===========================================================================

def protected_packets(nsot):
    """Example packets of every protected flow, for every host.
    Returns [(description, packet fields, source device)]."""
    r_name, r_mac, _, _ = nsot_view.router(nsot)
    att = nsot_view.attachments(nsot)
    out = []
    for h, info in sorted(nsot['hosts'].items()):
        ip, mac = nsot_view.host_ip(nsot, h), info['mac'].lower()
        vlan = att.get(h, {}).get('vlan')
        gw = nsot['vlans'][str(vlan)]['gateway'] if vlan is not None else None
        ipv4 = {'eth_type': 0x0800}
        # Step 1: DNS both ways (query to the gateway, reply back).
        out.append(('DNS query %s -> %s' % (h, r_name),
                    dict(ipv4, eth_src=mac, eth_dst=r_mac, ip_proto=17, ipv4_src=ip, ipv4_dst=gw,
                         udp_src=40000, udp_dst=53), h))
        out.append(('DNS reply %s -> %s' % (r_name, h),
                    dict(ipv4, eth_src=r_mac, eth_dst=mac, ip_proto=17, ipv4_src=gw, ipv4_dst=ip,
                         udp_src=53, udp_dst=40000), r_name))
        # Step 2: DHCP both ways (broadcast discover, unicast renew, replies).
        out.append(('DHCP request %s (broadcast)' % h,
                    dict(ipv4, eth_src=mac, eth_dst=BROADCAST, ip_proto=17, ipv4_src='0.0.0.0',
                         ipv4_dst='255.255.255.255', udp_src=68, udp_dst=67), h))
        out.append(('DHCP renew %s -> %s' % (h, r_name),
                    dict(ipv4, eth_src=mac, eth_dst=r_mac, ip_proto=17, ipv4_src=ip, ipv4_dst=gw,
                         udp_src=68, udp_dst=67), h))
        out.append(('DHCP reply %s -> %s' % (r_name, h),
                    dict(ipv4, eth_src=r_mac, eth_dst=mac, ip_proto=17, ipv4_src=gw, ipv4_dst=ip,
                         udp_src=67, udp_dst=68), r_name))
        out.append(('DHCP reply %s -> %s (broadcast)' % (r_name, h),
                    dict(ipv4, eth_src=r_mac, eth_dst=BROADCAST, ip_proto=17, ipv4_src=gw,
                         ipv4_dst='255.255.255.255', udp_src=67, udp_dst=68), r_name))
    # Step 3: management (OpenFlow, REST, SSH) between the controller and
    #         every device's management address.
    ctl = nsot['controller']['ip']
    mgmt_ips = sorted(set(s['mgmt']['ip'] for s in nsot['switches'].values()))
    for m in mgmt_ips:
        for port, what in ((nsot['controller']['openflow_port'], 'OpenFlow'),
                           (nsot['controller']['rest_port'], 'REST'), (22, 'SSH')):
            out.append(('management %s %s -> controller' % (what, m),
                        {'eth_type': 0x0800, 'ip_proto': 6, 'ipv4_src': m, 'ipv4_dst': ctl, 'tcp_src': 50000,
                         'tcp_dst': port}, 'management'))
            out.append(('management %s controller -> %s' % (what, m),
                        {'eth_type': 0x0800, 'ip_proto': 6, 'ipv4_src': ctl, 'ipv4_dst': m, 'tcp_src': port,
                         'tcp_dst': 50000}, 'management'))
    return out


def possible_in_ports(nsot, switch, source):
    """Ports a packet from `source` can arrive on at `switch`: the host's own
    port at its edge switch, otherwise any switch-to-switch or router port
    (conservative: if unsure, assume it can arrive there)."""
    att = nsot_view.attachments(nsot)
    ports = nsot['switches'][switch]['ports']
    if source in att and att[source]['switch'] == switch:
        return set([att[source]['port']])
    # Step 1: everything that is not another host's access port.
    return set(int(p) for p, info in ports.items()
               if info.get('mode') == 'trunk' or ':' in info.get('to', '') or info.get('to') == source)


def protected_intercepts(nsot):
    """[(name, priority, match)] of the protected rules that sit above the AI
    band (e.g. DNS/DHCP intercept at priority 50)."""
    return [(n, f['priority'], f['match']) for n, f in sorted(nsot['protected_flows'].items())
            if isinstance(f, dict) and 'priority' in f and f.get('match')]


# ===========================================================================
# Function 3: may this rule be installed?
# ===========================================================================

def validate_rule(nsot, proposal, live_rules=None, connected=None, meter_switches=()):
    """proposal = {'switch', 'purpose': 'intent'|'response', 'priority',
                   'match' (OF 1.3 names), 'action': 'drop'|'meter',
                   'meter_id' (if meter), 'hard_timeout'}
    live_rules: the switch's current rules (collector format) for conflicts.
    connected:  names of connected switches (None = don't check).
    meter_switches: switches that reported meter support.
    Returns {'ok': bool, 'errors': [..], 'checked': [what passed]}."""
    pol = nsot['ai_policy']
    errors, checked = [], []
    sw = proposal.get('switch')
    match = dict(proposal.get('match') or {})

    # Step 1: the switch.
    if sw not in nsot['switches']:
        return {'ok': False, 'errors': ['switch "%s" is not in the NSOT' % sw], 'checked': []}
    if connected is not None and sw not in connected:
        errors.append('switch %s is not connected to the controller' % sw)
    checked.append('switch %s is in the NSOT' % sw)

    # Step 2: cookie and priority: the AI's own band only.
    want_cookie = pol['cookies'].get(proposal.get('purpose'))
    if want_cookie is None:
        errors.append('purpose must be one of %s' % sorted(pol['cookies']))
    prio = proposal.get('priority')
    if not isinstance(prio, int) or not pol['priority_min'] <= prio <= pol['priority_max']:
        errors.append('priority %r is outside the AI band %d-%d' % (prio, pol['priority_min'], pol['priority_max']))
    else:
        checked.append('priority %d is inside the AI band %d-%d (below the protected rules at 50)'
                       % (prio, pol['priority_min'], pol['priority_max']))

    # Step 3: the match: allowed fields, real ports, NSOT addresses only.
    bad = sorted(set(match) - set(pol['allowed_match_fields']))
    if bad:
        errors.append('match fields not allowed for AI rules: %s' % ', '.join(bad))
    if not set(match) & set(['in_port', 'eth_src', 'eth_dst', 'ipv4_src', 'ipv4_dst']):
        errors.append('the match names no host or port: it would hit every packet on %s' % sw)
    if 'in_port' in match and str(match['in_port']) not in nsot['switches'][sw]['ports']:
        errors.append('%s has no port %s in the NSOT' % (sw, match['in_port']))
    known_macs = nsot_view.mac_names(nsot)
    for k in MAC_FIELDS:
        if k in match and str(match[k]).lower() not in known_macs:
            errors.append('%s %s is not a device in the NSOT' % (k, match[k]))
    mgmt = ipaddress.ip_network(nsot['management']['subnet'])
    host_ips = set(nsot_view.ip_names(nsot))
    for k in IP_FIELDS:
        if k in match:
            try:
                net = ipaddress.ip_network(str(match[k]), strict=False)
            except ValueError:
                errors.append('%s %r is not an IP address' % (k, match[k]))
                continue
            if net.overlaps(mgmt):
                errors.append('%s %s is in the management network %s (protected)' % (k, match[k], mgmt))
            elif net.prefixlen == 32 and str(net.network_address) not in host_ips \
                    and any(net.overlaps(ipaddress.ip_network(v['subnet'])) for v in nsot['vlans'].values()):
                errors.append('%s %s is inside a VLAN but is not a host in the NSOT' % (k, match[k]))
    for k in PORT_FIELDS:
        if k in match and int(match[k]) in nsot['protected_flows']['management']['tcp_ports'] and k.startswith('tcp'):
            errors.append('%s %s is a management port (protected)' % (k, match[k]))
    protected_udp = set()
    for n, f in nsot['protected_flows'].items():
        if isinstance(f, dict):
            for k in ('udp_src', 'udp_dst'):
                if k in f.get('match', {}):
                    protected_udp.add(int(f['match'][k]))
    for k in ('udp_src', 'udp_dst'):
        if k in match and int(match[k]) in protected_udp:
            # The protected rule (priority 50) would win anyway, so such a
            # rule is either useless or (for replies) harmful: refuse it.
            errors.append('%s %s targets a protected flow (DNS/DHCP ports %s)'
                          % (k, match[k], sorted(protected_udp)))
    if (set(match) & set(PORT_FIELDS)) and 'ip_proto' not in match:
        errors.append('a TCP/UDP port needs ip_proto (6 or 17) in the match')
    if (set(match) & set(IP_FIELDS + ('ip_proto',))) and int(match.get('eth_type', 0)) != 0x0800:
        errors.append('IP fields need eth_type 2048 (IPv4) in the match')
    if not errors:
        checked.append('match fields, ports and addresses all exist in the NSOT; no management address')

    # Step 4: the action.
    action = proposal.get('action')
    if action not in pol['allowed_actions']:
        errors.append('action %r not allowed (allowed: %s)' % (action, ', '.join(pol['allowed_actions'])))
    if action == 'meter' and sw not in meter_switches:
        errors.append('%s does not support meters (/stats/meterfeatures reports max_meter 0)' % sw)
    ht = proposal.get('hard_timeout', 0)
    limit = pol['response_hard_timeout'] if proposal.get('purpose') == 'response' else pol['intent_hard_timeout_max']
    if not isinstance(ht, int) or not 0 < ht <= limit:
        errors.append('hard_timeout must be 1-%d s so the rule removes itself (got %r)' % (limit, ht))

    # Step 5: protected-flow simulation.
    hits = []
    if not errors:
        for desc, pkt, source in protected_packets(nsot):
            ports = possible_in_ports(nsot, sw, source)
            if not rule_matches_packet(match, pkt, ports):
                continue
            saved_by = [n for n, p, m in protected_intercepts(nsot)
                        if p > prio and rule_matches_packet(normalize_match(m), pkt, ports)]
            if not saved_by:
                hits.append(desc)
        if hits:
            errors.append('would disrupt protected traffic: %s%s' % ('; '.join(hits[:4]),
                                                                    ' (+%d more)' % (len(hits) - 4) if len(hits) > 4 else ''))
        else:
            checked.append('simulated %d protected packets (DNS, DHCP, management): none disrupted'
                           % len(protected_packets(nsot)))

    # Step 6: conflicts with what is already on the switch.
    if not errors and live_rules is not None:
        for r in live_rules:
            if r.get('owner') not in ('ai_intent', 'ai_response'):
                continue
            other = normalize_match(r['match'])
            other_action = 'drop' if r.get('drop') else ('meter' if any('METER' in a for a in r['actions']) else 'other')
            if other == normalize_match(match) and r['priority'] == prio:
                errors.append('duplicate: the same rule already exists on %s (%s, cookie %s)'
                              % (sw, r['owner'], r['cookie']))
            elif matches_overlap(other, match) and other_action != action:
                errors.append('conflict: an existing %s rule on %s %ss overlapping traffic (%s)'
                              % (r['owner'], sw, other_action, r['match']))
        if not errors:
            checked.append('no duplicate or conflicting AI rule on %s' % sw)

    return {'ok': not errors, 'errors': errors, 'checked': checked}


# ===========================================================================
# Function 4: may this rule be deleted?
# ===========================================================================

def validate_delete(nsot, rule):
    """rule: a live rule (collector format, with 'cookie' and 'owner').
    AI may delete its own rules, learned rules, and rules nobody owns
    (unauthorized). Never a protected rule (table-miss, DNS, DHCP, sensor)."""
    pol = nsot['ai_policy']
    cookie = rule.get('cookie')
    # Step 1: unknown cookie = installed by none of our apps -> may go.
    if str(cookie) not in nsot['flow_cookies']:
        return {'ok': True, 'errors': [], 'checked': ['cookie %s is not ours: unauthorized rule' % cookie]}
    # Step 2: one of ours: only the cookies ai_policy allows.
    if cookie in pol['may_delete_cookies']:
        return {'ok': True, 'errors': [], 'checked': ['cookie %s (%s) may be deleted by the AI'
                                                      % (cookie, nsot['flow_cookies'][str(cookie)])]}
    return {'ok': False, 'errors': ['cookie %s (%s) is protected: the AI never deletes it'
                                    % (cookie, nsot['flow_cookies'][str(cookie)])], 'checked': []}


# ===========================================================================
# Function 5: the REST body for an accepted proposal
# ===========================================================================

def to_flowentry(nsot, proposal):
    """Body for POST /stats/flowentry/add (Ryu ofctl_rest)."""
    pol = nsot['ai_policy']
    actions = [] if proposal['action'] == 'drop' else [{'type': 'METER', 'meter_id': proposal['meter_id']}]
    return {'dpid': nsot['switches'][proposal['switch']]['dpid'], 'table_id': 0,
            'cookie': pol['cookies'][proposal['purpose']], 'priority': proposal['priority'],
            'hard_timeout': proposal['hard_timeout'], 'idle_timeout': 0,
            'match': proposal['match'], 'actions': actions}
