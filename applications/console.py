"""Lab 9 controller console: one web page for every controller app.

Serves applications/console.html on Ryu's REST port (8080):
  GET /lab9/ui            -> the console (DNS filter, DHCP to router, ...)
  GET /lab9/nsot/summary  -> names from the NSOT, so the page can show
                             "pc1" and "arista1" instead of IPs and DPIDs

The older per-app pages (/lab9/dns/ui, /lab9/dhcp/ui) serve the same console,
opened on that app's tab (see console_response).
"""

import json
import os

from ryu.app.wsgi import ControllerBase, Response, route

CONSOLE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'console.html')


# ===========================================================================
# Function 1: return the console page
# ===========================================================================

def console_response():
    """Read console.html from disk on every request, so an edited page shows
    up on the next browser refresh without restarting Ryu."""
    with open(CONSOLE_FILE, 'rb') as f:
        return Response(status=200, content_type='text/html; charset=utf-8', body=f.read())


def json_response(payload, status=200):
    """A JSON answer for every Lab 9 REST endpoint.

    The browser header is added AFTER the Response is made: passing
    headers={...} to Response replaces ALL its headers, which silently
    dropped "Content-Type: application/json" (found by
    tests/test_rest_api.py)."""
    resp = Response(status=status, content_type='application/json',
                    body=json.dumps(payload, indent=2).encode('utf-8'))
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


# ===========================================================================
# Function 2: the names the console needs, taken from the NSOT
# ===========================================================================

def nsot_summary(nsot):
    """Build a small, password-free view of the NSOT for the browser.

    Example result:
      {"controller": "10.224.78.132",
       "switches": {"1": "cisco1", "11": "arista1", ...},     dpid -> name
       "hosts_by_ip":  {"10.10.10.11": "pc1", ...},
       "hosts_by_mac": {"00:00:00:00:10:11": "pc1", ...},
       "router": "r1"}
    """
    # Step 1: switches, keyed by DPID (JSON keys are text, so str(dpid)).
    switches = {str(sw['dpid']): name for name, sw in nsot['switches'].items()}

    # Step 2: hosts by IP and by MAC. The router's LAN MAC is added too, so a
    #         DHCP path can end at "r1" instead of a bare MAC.
    hosts_by_ip = {}
    hosts_by_mac = {}
    for name, host in nsot.get('hosts', {}).items():
        hosts_by_ip[host['ip'].split('/')[0]] = name
        hosts_by_mac[host['mac'].lower()] = name
    router = None
    for name, r in nsot.get('routers', {}).items():
        router = name
        hosts_by_mac[r['lan']['mac'].lower()] = name
        for vlan in nsot['vlans'].values():
            hosts_by_ip[vlan['gateway']] = name

    return {
        'controller': nsot['controller']['ip'],
        'switches': switches,
        'hosts_by_ip': hosts_by_ip,
        'hosts_by_mac': hosts_by_mac,
        'router': router,
        'topology': nsot_topology(nsot),
    }


# ===========================================================================
# Function 3: the topology, for the "How it works" map
# ===========================================================================

def nsot_topology(nsot):
    """Everything the hop-by-hop map needs, straight from the NSOT.

    Example result (shortened):
      {"switches": {"arista1": {"dpid": 11, "vendor": "arista"}, ...},
       "links":    [{"a": "arista1", "a_port": 1, "b": "cisco1", "b_port": 2,
                     "standby": false}, ...],
       "attach":   {"pc1": {"switch": "arista1", "port": 2, "mode": "access", "vlan": 10},
                    "r1":  {"switch": "cisco1",  "port": 1, "mode": "trunk",  "vlan": null}},
       "hosts":    {"pc1": {"ip": "10.10.10.11", "mac": "00:00:00:00:10:11"}, ...},
       "router":   {"name": "r1", "mac": ..., "wan_ip": ..., "gateways": {"10": ...},
                    "dhcp": {"10": {"start": ..., "end": ...}}},
       "external": {"name": "inet", "ip": "203.0.113.2"},
       "blocked_page_ip": "10.10.20.21"}
    """
    # Step 1: switches, and every port: a switch-to-switch link ("to" has a
    #         colon, e.g. "cisco1:2"; each link is listed once) or the place a
    #         host or router plugs in ("to" is just a name, e.g. "pc1").
    switches = {}
    links = []
    attach = {}
    for name, sw in nsot['switches'].items():
        switches[name] = {'dpid': sw['dpid'], 'vendor': sw.get('vendor', '')}
        for port_str, p in sw['ports'].items():
            if ':' in p['to']:
                peer, peer_port = p['to'].split(':')
                if name < peer:
                    links.append({'a': name, 'a_port': int(port_str),
                                  'b': peer, 'b_port': int(peer_port),
                                  'standby': bool(p.get('standby'))})
            else:
                attach[p['to']] = {'switch': name, 'port': int(port_str),
                                   'mode': p['mode'], 'vlan': p.get('vlan')}

    # Step 2: hosts' addresses (without the /24).
    hosts = {name: {'ip': h['ip'].split('/')[0], 'mac': h['mac'].lower()}
             for name, h in nsot.get('hosts', {}).items()}

    # Step 3: the router (first one in the NSOT) and the Internet node.
    router = None
    for name, r in nsot.get('routers', {}).items():
        router = {'name': name, 'mac': r['lan']['mac'].lower(),
                  'wan_ip': r['wan']['ip'].split('/')[0],
                  'gateways': {vid: v['gateway'] for vid, v in nsot['vlans'].items()},
                  'subnets': {vid: v['subnet'] for vid, v in nsot['vlans'].items()},
                  'dhcp': r.get('dhcp', {})}
        break
    external = None
    for name, e in nsot.get('external', {}).items():
        external = {'name': name, 'ip': e['ip'].split('/')[0]}
        break

    return {
        'switches': switches,
        'links': links,
        'attach': attach,
        'hosts': hosts,
        'router': router,
        'external': external,
        'blocked_page_ip': nsot.get('dns_blacklist', {}).get('blocked_page_ip'),
    }


# ===========================================================================
# Class 1: REST routes for the console
# ===========================================================================

class ConsoleController(ControllerBase):
    """Registered by VlanSwitch13 with data {'nsot': <loaded nsot.json>}."""

    def __init__(self, req, link, data, **config):
        super(ConsoleController, self).__init__(req, link, data, **config)
        self.nsot = data['nsot']

    @route('lab9_console', '/lab9/ui', methods=['GET'])
    def serve_console(self, req, **kwargs):
        return console_response()

    @route('lab9_console', '/lab9/nsot/summary', methods=['GET'])
    def get_summary(self, req, **kwargs):
        return json_response(nsot_summary(self.nsot))
