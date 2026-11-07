"""Lab 9 Objective 3 (A3) & Objective 6 (A6): DNS Blacklist SDN Application.

What this application does:
  1. Force DNS to Controller (`install_dns_intercept_flow`):
     When any OpenFlow switch connects, installs a high-priority (priority 50,
     cookie 0x30) flow rule matching IPv4 UDP destination port 53 and sending
     the packet to the controller (`OFPP_CONTROLLER`).

  2. Parse the DNS Query (`parse_dns_query`):
     Extracts the DNS transaction ID, flags, queried domain name (e.g.
     "bad.lab9.lan"), query type (A = 1), and raw question bytes directly from
     the UDP payload.

  3. External JSON Verdict Check (`query_external_verdict`):
     Sends an HTTP GET request FROM the controller to the external JSON verdict
     service (`http://127.0.0.1:8053/check?domain=<qname>`), which returns:
       {"domain": "...", "verdict": "good" | "bad", "reason": "..."}

  4. Enforce Verdict & Forged "Blocked Page" DNS Reply (`build_dns_reply`,
     `send_forged_dns_response`):
     - If verdict == "good": returns False so the controller forwards the DNS
       query along its normal VLAN path to the DNS server (router r1).
     - If verdict == "bad": crafts a valid DNS A-record response pointing the
       blocked domain to the Blocked-Page Web Server IP (`10.10.20.21`, srv1),
       wraps it in UDP / IPv4 / Ethernet (adding an 802.1Q tag if the ingress
       port is a trunk), and sends it straight back to the host via PacketOut.
       The real DNS server never sees the blocked query, and the host's browser
       or curl immediately loads the "ACCESS BLOCKED" web page.

  5. REST API & Web UI (`DnsRestController`):
     Exposes the application on Ryu's WSGI REST server (port 8080):
       GET  /lab9/dns/ui         -> Web UI to monitor and control DNS filtering
       GET  /lab9/dns/status     -> JSON stats, config, blacklist, recent log
       GET  /lab9/dns/check      -> Test external verdict for ?domain=<name>
       POST /lab9/dns/blacklist  -> Add or remove a domain via the controller
       POST /lab9/dns/config     -> Update sinkhole IP or external verdict URL
"""

import json
import os
import socket
import struct
import time
import urllib.parse
import urllib.request

from ryu.app.wsgi import ControllerBase, Response, route
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, udp, vlan

from .console import console_response, json_response

# Priority and cookie for the DNS intercept flow rule.
# Learned L2 flows have priority 1 (cookie 0x10), so priority 50 always wins
# for UDP port 53, and cookie 0x30 marks it as a protected flow (never deleted
# during topology changes or AI actions).
DNS_PRIORITY = 50
DNS_COOKIE = 0x30


# ===========================================================================
# Function 1: Install the OpenFlow rule forcing DNS (UDP/53) to controller
# ===========================================================================

def install_dns_intercept_flow(dp):
    """Install a priority-50 rule on switch `dp` that forces all IPv4 UDP/53
    (DNS query) packets to the controller."""
    ofp = dp.ofproto
    parser = dp.ofproto_parser

    match = parser.OFPMatch(
        eth_type=ether_types.ETH_TYPE_IP,   # 0x0800 = IPv4
        ip_proto=17,                        # 17 = UDP
        udp_dst=53                          # 53 = DNS query port
    )
    actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
    mod = parser.OFPFlowMod(
        datapath=dp,
        priority=DNS_PRIORITY,
        cookie=DNS_COOKIE,
        match=match,
        instructions=inst,
    )
    dp.send_msg(mod)


# ===========================================================================
# Function 2: Parse a raw DNS query payload (RFC 1035 wire format)
# ===========================================================================

def parse_dns_query(raw_bytes):
    """Parse a raw UDP DNS query payload.

    DNS Header is 12 bytes:
      [0:2]  Transaction ID (txid)
      [2:4]  Flags (bit 15 QR: 0 = query, 1 = response)
      [4:6]  QDCOUNT (number of questions)
      [6:12] ANCOUNT, NSCOUNT, ARCOUNT

    Followed by Question section:
      Label-encoded domain name (e.g. \x03bad\x04lab9\x03lan\x00)
      2-byte QTYPE  (1 = A record, 28 = AAAA, etc.)
      2-byte QCLASS (1 = IN)

    Returns a dict with txid, qname, qtype, qclass, question_bytes, or None
    if the payload is not a valid DNS query.
    """
    if not raw_bytes or len(raw_bytes) < 17:
        return None

    txid, flags, qdcount, _, _, _ = struct.unpack('!HHHHHH', raw_bytes[:12])
    # QR bit (highest bit of flags) must be 0 (query) and must have >=1 question
    if (flags & 0x8000) != 0 or qdcount < 1:
        return None

    # Walk label lengths starting at byte 12 until the 0x00 terminator byte
    idx = 12
    labels = []
    while idx < len(raw_bytes):
        length = raw_bytes[idx]
        idx += 1
        if length == 0:
            break
        # Compression pointers (top 2 bits == 11) are not expected in a single question
        if length & 0xC0 or idx + length > len(raw_bytes):
            return None
        labels.append(raw_bytes[idx:idx + length].decode('ascii', errors='ignore'))
        idx += length

    if idx + 4 > len(raw_bytes) or not labels:
        return None

    qtype, qclass = struct.unpack('!HH', raw_bytes[idx:idx + 4])
    question_bytes = raw_bytes[12:idx + 4]
    qname = '.'.join(labels).lower()

    return {
        'txid': txid,
        'flags': flags,
        'qname': qname,
        'qtype': qtype,
        'qclass': qclass,
        'question_bytes': question_bytes,
    }


# ===========================================================================
# Function 3: Build a modified DNS response payload pointing to the blocked IP
# ===========================================================================

def build_dns_reply(query, redirect_ip, ttl=60):
    """Build a raw DNS response payload for `query` answering with `redirect_ip`.

    - Copies the client's Transaction ID (`txid`) so the client accepts it.
    - Sets Flags = 0x8180 (Standard query response, Recursion Desired + Available,
      No error) for IPv4 A queries (QTYPE=1), with ANCOUNT=1.
    - For non-A queries (such as IPv6 AAAA QTYPE=28), returns ANCOUNT=0 so the
      client uses the IPv4 A record pointing to the blocked page.
    """
    # Only attach an IPv4 A-record answer when the question asks for A (1) or ANY (255)
    if query['qtype'] in (1, 255):
        header = struct.pack('!HHHHHH', query['txid'], 0x8180, 1, 1, 0, 0)
        # Answer RR:
        #   0xC00C = pointer to question name at byte offset 12
        #   TYPE   = 1 (A), CLASS = 1 (IN), TTL = ttl, RDLENGTH = 4, RDATA = IPv4
        rdata = socket.inet_aton(redirect_ip)
        answer = struct.pack('!HHHLH', 0xC00C, 1, 1, ttl, 4) + rdata
        return header + query['question_bytes'] + answer
    else:
        # Empty NOERROR reply for AAAA so curl/browsers don't hang waiting on IPv6
        header = struct.pack('!HHHHHH', query['txid'], 0x8180, 1, 0, 0, 0)
        return header + query['question_bytes']


# ===========================================================================
# Function 4: Query the External JSON Verdict API from the Controller
# ===========================================================================

def query_external_verdict(verdict_url, domain, timeout=1.5):
    """Send `domain` to the external JSON verdict URL and return its dict.

    Initiated strictly by the controller over HTTP. Returns:
      {"domain": ..., "verdict": "good" | "bad", "reason": ..., "source": ...}
    """
    sep = '&' if '?' in verdict_url else '?'
    url = '%s%sdomain=%s' % (verdict_url, sep, urllib.parse.quote(domain))
    try:
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            verdict = str(data.get('verdict', 'good')).lower()
            return {
                'domain': domain,
                'verdict': 'bad' if verdict == 'bad' else 'good',
                'reason': data.get('reason', 'external verdict'),
                'source': data.get('source', verdict_url),
            }
    except Exception as e:
        return {
            'domain': domain,
            'verdict': 'good',
            'reason': 'verdict service unreachable (%s), fail-open' % e,
            'source': 'fallback',
        }


# ===========================================================================
# Function 5: Wrap the forged DNS reply in Ethernet / VLAN / IPv4 / UDP
# ===========================================================================

def build_forged_packet(eth_req, ip_req, udp_req, vlan_id, tagged_out, dns_reply_bytes):
    """Build a complete Ethernet frame carrying `dns_reply_bytes` back to the host.

    Swaps source and destination MACs, IPs, and UDP ports so the host believes
    the reply came directly from the DNS server it queried.
    """
    pkt = packet.Packet()
    if tagged_out:
        pkt.add_protocol(ethernet.ethernet(
            src=eth_req.dst,
            dst=eth_req.src,
            ethertype=ether_types.ETH_TYPE_8021Q,
        ))
        pkt.add_protocol(vlan.vlan(vid=vlan_id, ethertype=ether_types.ETH_TYPE_IP))
    else:
        pkt.add_protocol(ethernet.ethernet(
            src=eth_req.dst,
            dst=eth_req.src,
            ethertype=ether_types.ETH_TYPE_IP,
        ))

    pkt.add_protocol(ipv4.ipv4(
        src=ip_req.dst,
        dst=ip_req.src,
        proto=17,
        ttl=64,
    ))
    pkt.add_protocol(udp.udp(
        src_port=udp_req.dst_port,
        dst_port=udp_req.src_port,
    ))
    pkt.add_protocol(dns_reply_bytes)
    pkt.serialize()
    return pkt.data


# ===========================================================================
# Class 1: DnsBlacklistEngine (called by VlanSwitch13 on UDP/53 packets)
# ===========================================================================

class DnsBlacklistEngine(object):
    """Stateful DNS filter attached to the controller application."""

    def __init__(self, nsot, logger):
        self.logger = logger
        dns_cfg = nsot.get('dns_blacklist', {})
        self.enabled = dns_cfg.get('enabled', True)
        self.verdict_url = dns_cfg.get('verdict_url', 'http://127.0.0.1:8053/check')
        self.blocked_page_ip = dns_cfg.get(
            'blocked_page_ip',
            nsot.get('hosts', {}).get('srv1', {}).get('ip', '10.10.20.21/24').split('/')[0],
        )

        # Counters and history for the REST API / UI
        self.stats = {'total_queries': 0, 'allowed': 0, 'blocked': 0}
        self.history = []          # newest last, capped at 100 entries
        self._recent_good = {}     # (src_ip, txid, qname, qtype) -> expiry timestamp
        self._verdict_cache = {}   # qname -> (result_dict, expiry) for parallel A/AAAA/HTTPS browser queries

    def handle_packet(self, dp, in_port, role, packet_vlan, pkt, raw_data):
        """Inspect a packet arriving at the controller.

        Returns True if this function handled/blocked the packet (so the switch
        app must NOT forward it further), or False if the packet should be
        forwarded normally along its VLAN path.
        """
        if not self.enabled:
            return False

        ip_hdr = pkt.get_protocol(ipv4.ipv4)
        udp_hdr = pkt.get_protocol(udp.udp)
        if not ip_hdr or not udp_hdr or udp_hdr.dst_port != 53:
            return False

        # Extract the UDP payload (bytes after the 8-byte UDP header)
        dns_payload = self._extract_udp_payload(raw_data)
        query = parse_dns_query(dns_payload)
        if not query:
            return False

        # Avoid duplicate HTTP verdict checks when an already-allowed DNS query
        # traverses subsequent trunk switches on its way to the router.
        now = time.time()
        cache_key = (ip_hdr.src, query['txid'], query['qname'], query['qtype'])
        if self._recent_good.get(cache_key, 0) > now:
            return False

        # Initiate the external JSON verdict lookup from the controller
        # (cached for 5s so a real browser's parallel A + AAAA + HTTPS queries
        # get answered immediately without waiting on 3 separate HTTP calls).
        cached = self._verdict_cache.get(query['qname'])
        if cached and cached[1] > now:
            result = cached[0]
        else:
            result = query_external_verdict(self.verdict_url, query['qname'])
            self._verdict_cache[query['qname']] = (result, now + 5.0)
        verdict = result['verdict']

        self.stats['total_queries'] += 1
        if verdict == 'bad':
            self.stats['blocked'] += 1
        else:
            self.stats['allowed'] += 1

        entry = {
            'time': time.strftime('%H:%M:%S'),
            'dpid': dp.id,
            'in_port': in_port,
            'vlan': packet_vlan,
            'src_ip': ip_hdr.src,
            'dst_ip': ip_hdr.dst,
            'domain': query['qname'],
            'qtype': 'A' if query['qtype'] == 1 else ('AAAA' if query['qtype'] == 28 else str(query['qtype'])),
            'verdict': verdict,
            'action': ('forged reply -> %s' % self.blocked_page_ip) if verdict == 'bad' else 'forwarded to DNS server',
            'reason': result.get('reason', ''),
        }
        self.history.append(entry)
        if len(self.history) > 100:
            self.history.pop(0)

        self.logger.info('DNS [%s] src=%s domain=%s (%s) -> %s',
                         verdict.upper(), ip_hdr.src, query['qname'],
                         entry['qtype'], entry['action'])

        if verdict != 'bad':
            # Remember for 3 seconds so intermediate switches forward without re-querying
            self._recent_good[cache_key] = now + 3.0
            return False

        # Verdict is BAD: craft and send the modified DNS reply back out `in_port`
        eth_hdr = pkt.get_protocol(ethernet.ethernet)
        dns_reply = build_dns_reply(query, self.blocked_page_ip)
        reply_frame = build_forged_packet(
            eth_req=eth_hdr,
            ip_req=ip_hdr,
            udp_req=udp_hdr,
            vlan_id=packet_vlan,
            tagged_out=(role == 'trunk'),
            dns_reply_bytes=dns_reply,
        )

        ofp = dp.ofproto
        parser = dp.ofproto_parser
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=reply_frame,
        )
        dp.send_msg(out)
        return True

    @staticmethod
    def _extract_udp_payload(raw_data):
        """Return the bytes after the Ethernet (+ optional 802.1Q) + IPv4 + UDP headers."""
        if len(raw_data) < 14 + 20 + 8:
            return b''
        eth_type = struct.unpack('!H', raw_data[12:14])[0]
        ip_offset = 18 if eth_type == ether_types.ETH_TYPE_8021Q else 14
        if len(raw_data) < ip_offset + 20:
            return b''
        ip_header_len = (raw_data[ip_offset] & 0x0F) * 4
        udp_offset = ip_offset + ip_header_len
        if len(raw_data) < udp_offset + 8:
            return b''
        return raw_data[udp_offset + 8:]

    def fetch_blacklist(self):
        """Ask the external verdict service for its current domain blacklist."""
        base = self.verdict_url.rsplit('/', 1)[0]
        try:
            with urllib.request.urlopen(base + '/blacklist', timeout=1.5) as r:
                return json.loads(r.read().decode('utf-8')).get('blocked_domains', [])
        except Exception:
            return []

    def update_blacklist(self, domain, action):
        """Add or remove a domain on the external verdict service."""
        base = self.verdict_url.rsplit('/', 1)[0]
        body = json.dumps({'domain': domain, 'action': action}).encode('utf-8')
        req = urllib.request.Request(
            base + '/blacklist', data=body,
            headers={'Content-Type': 'application/json'}, method='POST',
        )
        with urllib.request.urlopen(req, timeout=2.0) as r:
            return json.loads(r.read().decode('utf-8')).get('blocked_domains', [])


# ===========================================================================
# Class 2: Ryu WSGI REST Controller (Objective 6 + Web UI)
# ===========================================================================

class DnsRestController(ControllerBase):
    """REST endpoints mounted on Ryu's WSGI server (port 8080)."""

    def __init__(self, req, link, data, **config):
        super(DnsRestController, self).__init__(req, link, data, **config)
        self.engine = data['dns_engine']

    def _json(self, payload, status=200):
        return json_response(payload, status)

    # Old URL, kept working: serves the shared console, opened on the DNS tab.
    @route('lab9_dns', '/lab9/dns/ui', methods=['GET'])
    def serve_ui(self, req, **kwargs):
        return console_response()

    @route('lab9_dns', '/lab9/dns/status', methods=['GET'])
    def get_status(self, req, **kwargs):
        return self._json({
            'enabled': self.engine.enabled,
            'verdict_url': self.engine.verdict_url,
            'blocked_page_ip': self.engine.blocked_page_ip,
            'stats': self.engine.stats,
            'blocked_domains': self.engine.fetch_blacklist(),
            'recent_queries': list(reversed(self.engine.history[-30:])),
        })

    @route('lab9_dns', '/lab9/dns/check', methods=['GET'])
    def check_domain(self, req, **kwargs):
        domain = req.params.get('domain', '')
        return self._json(query_external_verdict(self.engine.verdict_url, domain))

    @route('lab9_dns', '/lab9/dns/blacklist', methods=['POST'])
    def modify_blacklist(self, req, **kwargs):
        data = json.loads(req.body.decode('utf-8') or '{}')
        domain = (data.get('domain') or '').strip()
        action = (data.get('action') or 'add').strip()
        if action == 'clear_history':
            self.engine.history.clear()
            self.engine._verdict_cache.clear()
            self.engine.stats = {'total_queries': 0, 'allowed': 0, 'blocked': 0}
            return self._json({'ok': True, 'stats': self.engine.stats})
        updated = self.engine.update_blacklist(domain, action)
        self.engine._verdict_cache.clear()
        return self._json({'ok': True, 'blocked_domains': updated})

    @route('lab9_dns', '/lab9/dns/config', methods=['POST'])
    def update_config(self, req, **kwargs):
        data = json.loads(req.body.decode('utf-8') or '{}')
        if 'enabled' in data:
            self.engine.enabled = bool(data['enabled'])
        if 'blocked_page_ip' in data and data['blocked_page_ip']:
            self.engine.blocked_page_ip = str(data['blocked_page_ip']).strip()
        if 'verdict_url' in data and data['verdict_url']:
            self.engine.verdict_url = str(data['verdict_url']).strip()
        return self._json({
            'ok': True,
            'enabled': self.engine.enabled,
            'verdict_url': self.engine.verdict_url,
            'blocked_page_ip': self.engine.blocked_page_ip,
        })
