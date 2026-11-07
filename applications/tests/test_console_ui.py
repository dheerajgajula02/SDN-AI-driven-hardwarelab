#!/usr/bin/env python3
"""End-to-end test of the controller console (applications/console.html).

What it proves:
  1. The buttons on the page really work (it clicks them in a real browser).
  2. Each click really changes the network (it checks from inside the Mininet
     hosts with nslookup / tcpdump / udhcpc after each click).

How it works:
  - Starts a private headless Chrome and drives it over the DevTools protocol:
    sets input values, clicks the real buttons, reads what the page shows.
  - Runs commands inside a Mininet host with `mnexec -a <host shell pid>`
    over SSH to the Mininet VM.

Needs: the network running (lab9_net.py) and Ryu running (start_ryu.sh).
Run on the laptop (password comes from the environment, never this file):
  SSHPASS=<mininet password> python3 lab9/applications/tests/test_console_ui.py
"""

import asyncio
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.request

import websockets

# Commands inside Mininet hosts (shared with test_dataflow.py).
from mininet_host import on_host, resolve

CONSOLE = 'http://100.110.3.67:8080/lab9/ui'
BLOCKED_PAGE_IP = '10.10.20.21'
DEBUG_PORT = 9333
PROFILE = '/tmp/opencode/chrome-console-test'

results = []   # (name, passed, detail)


# ===========================================================================
# Function 1: record one check
# ===========================================================================

def check(name, passed, detail=''):
    results.append((name, bool(passed), detail))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('  [%s]' % detail) if detail else ''))
    sys.stdout.flush()


# ===========================================================================
# Class 1: a tiny DevTools-protocol driver for one Chrome tab
# ===========================================================================

class Tab(object):
    def __init__(self, ws):
        self.ws = ws
        self.next_id = 0

    async def cdp(self, method, params=None):
        """Send one DevTools command and return its result."""
        self.next_id += 1
        my_id = self.next_id
        await self.ws.send(json.dumps({'id': my_id, 'method': method, 'params': params or {}}))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get('id') == my_id:          # skip events, wait for our answer
                return msg.get('result', {})

    async def js(self, expression):
        """Evaluate JavaScript in the page and return its value."""
        res = await self.cdp('Runtime.evaluate', {
            'expression': expression, 'returnByValue': True, 'awaitPromise': True})
        if 'exceptionDetails' in res:
            raise RuntimeError(res['exceptionDetails'].get('text', 'page error'))
        return res.get('result', {}).get('value')

    async def text(self, element_id):
        return await self.js('document.getElementById(%s).textContent' % json.dumps(element_id))

    async def wait_text(self, element_id, needle, timeout=8):
        """Wait until the element's text contains `needle`; return the text."""
        end = time.time() + timeout
        txt = ''
        while time.time() < end:
            txt = await self.text(element_id) or ''
            if needle in txt:
                return txt
            await asyncio.sleep(0.25)
        return txt

    async def click(self, selector):
        """Click a real element, exactly like a user (fires its handlers)."""
        await self.js('document.querySelector(%s).click()' % json.dumps(selector))

    async def type_into(self, element_id, value):
        await self.js('document.getElementById(%s).value = %s'
                      % (json.dumps(element_id), json.dumps(value)))


# ===========================================================================
# The tests, in the order a person would try them
# ===========================================================================

async def run_tests(tab):
    # ---- T1: page loads and shows all six switches as connected ------------
    await tab.wait_text('dns-feed', '', 1)
    await asyncio.sleep(3)   # first poll of /stats/switches
    lit = await tab.js("document.querySelectorAll('.jack.up').length")
    check('T1 page loads, 6 switches shown connected', lit == 6, '%s lit' % lit)

    # ---- T2: empty Block click gives a clear instruction --------------------
    await tab.type_into('block-input', '')
    await tab.click('#block-form button')
    t = await tab.wait_text('dns-notice', 'Type a domain')
    check('T2 empty "Block domain" explains what to do', 'Type a domain' in t, t)

    # ---- T3: block colorado.edu from the UI --------------------------------
    print('     before: vm1 resolves colorado.edu ->', resolve('vm1', 'colorado.edu', '10.10.20.1'))
    await tab.type_into('block-input', 'colorado.edu')
    await tab.click('#block-form button')
    t = await tab.wait_text('dns-notice', 'Blocked colorado.edu')
    listed = 'colorado.edu' in (await tab.text('blocklist'))
    check('T3 "Block domain" adds colorado.edu to the list', 'Blocked colorado.edu' in t and listed, t)

    # ---- T4: the network obeys: vm1 now gets the blocked page --------------
    addrs = resolve('vm1', 'colorado.edu', '10.10.20.1')
    check('T4 network: vm1 gets the blocked page for colorado.edu', addrs == [BLOCKED_PAGE_IP], addrs)

    # ---- T5: the lookup appears at the top of the feed as Blocked ----------
    # Wait for the TOP row itself to change (the page refreshes every 2 s);
    # "Blocked" anywhere in the feed could be an older row.
    first = ''
    end = time.time() + 8
    while time.time() < end:
        first = await tab.js("(document.querySelector('#dns-feed .row') || {}).innerText || ''")
        if 'colorado.edu' in first and 'Blocked' in first:
            break
        await asyncio.sleep(0.25)
    check('T5 feed shows the lookup as blocked at the top',
          first and 'colorado.edu' in first and 'Blocked' in first, (first or '').replace('\n', ' | ')[:120])

    # ---- T6/T7: unblock from the UI, network goes back to the real site ----
    await tab.click('#blocklist button[data-unblock="colorado.edu"]')
    t = await tab.wait_text('dns-notice', 'Unblocked colorado.edu')
    still = 'colorado.edu' in (await tab.text('blocklist'))
    check('T6 "Unblock" removes colorado.edu from the list', 'Unblocked' in t and not still, t)
    addrs = resolve('vm1', 'colorado.edu', '10.10.20.1')
    check('T7 network: vm1 gets the real colorado.edu again',
          addrs and BLOCKED_PAGE_IP not in addrs, addrs)

    # ---- T8: "Check a domain" for a bad and a good domain ------------------
    for dom, want in (('evil.com', 'would be blocked'), ('example.com', 'would be allowed')):
        await tab.type_into('check-input', dom)
        await tab.click('#check-form button')
        t = await tab.wait_text('check-out', 'would be')
        check('T8 "Check" %s says "%s"' % (dom, want), want in t, ' '.join(t.split())[:100])

    # ---- T9: turn filtering off, then on, and check the network each time --
    await tab.click('#dns-toggle')
    t = await tab.wait_text('dns-now', 'Filtering is off')
    check('T9a "Turn filtering off" shows filtering is off', 'off' in t, t)
    addrs = resolve('pc1', 'evil.com', '10.10.10.1')
    check('T9b network: with filtering off, evil.com is NOT the blocked page',
          addrs and BLOCKED_PAGE_IP not in addrs, addrs)
    await tab.click('#dns-toggle')
    t = await tab.wait_text('dns-now', 'Filtering is on')
    check('T9c "Turn filtering on" shows filtering is on', 'is on' in t, t)
    addrs = resolve('pc1', 'evil.com', '10.10.10.1')
    check('T9d network: with filtering on, evil.com is the blocked page', addrs == [BLOCKED_PAGE_IP], addrs)

    # ---- T10: clear history empties the feed --------------------------------
    await tab.click('#dns-clear')
    t = await tab.wait_text('dns-feed', 'No lookups yet')
    check('T10 "Clear history" empties the DNS feed', 'No lookups yet' in t)

    # ---- T11: DHCP tab -------------------------------------------------------
    await tab.click('#tab-dhcp')
    t = await tab.wait_text('dhcp-now', 'Unicast forcing is')
    hash_ok = await tab.js('location.hash') == '#dhcp'
    check('T11 DHCP tab opens and shows its state', 'Unicast forcing is on' in t and hash_ok, t)

    # ---- T12: forcing ON: pc2 gets a lease, pc1 sees nothing ----------------
    def dhcp_round():
        # </dev/null + & so the SSH call returns at once while tcpdump runs
        on_host('pc1', 'timeout 7 tcpdump -nn -i pc1-eth0 udp port 67 < /dev/null > /tmp/ui-test-pc1.txt 2>&1 &')
        time.sleep(1.5)
        lease = on_host('pc2', 'busybox udhcpc -i pc2-eth0 -n -q -t 3 -s /tmp/lab9-udhcpc.sh 2>&1')
        time.sleep(6)
        seen = on_host('pc1', 'cat /tmp/ui-test-pc1.txt')
        m = re.search(r'(\d+) packets? captured', seen)
        return 'Lease of' in lease, int(m.group(1)) if m else -1

    got, pc1_saw = dhcp_round()
    check('T12a network, forcing on: pc2 gets a lease', got)
    check('T12b network, forcing on: pc1 sees 0 DHCP packets', pc1_saw == 0, '%d captured' % pc1_saw)
    t = await tab.wait_text('dhcp-feed', 'r1', 6)
    check('T12c feed shows the request path ending at r1', 'pc2' in t and 'arista2' in t and 'r1' in t,
          ' '.join(t.split())[:110])

    # ---- T13: forcing OFF: the broadcast floods, so pc1 does see it ---------
    await tab.click('#dhcp-toggle')
    t = await tab.wait_text('dhcp-now', 'Unicast forcing is off')
    check('T13a "Turn unicast forcing off" shows it is off', 'off' in t, t)
    got, pc1_saw = dhcp_round()
    check('T13b network, forcing off: pc1 now sees the broadcast (proves the toggle is real)',
          pc1_saw > 0, '%d captured' % pc1_saw)
    await tab.click('#dhcp-toggle')
    t = await tab.wait_text('dhcp-now', 'Unicast forcing is on')
    check('T13c "Turn unicast forcing on" shows it is on again', 'is on' in t, t)

    # ---- T14: clear DHCP history --------------------------------------------
    await tab.click('#dhcp-clear')
    t = await tab.wait_text('dhcp-feed', 'No DHCP requests yet')
    check('T14 "Clear history" empties the DHCP feed', 'No DHCP requests yet' in t)

    # ---- T15: "Watch a request hop by hop" opens the map on that situation --
    await tab.click('[data-how="dhcp"]')
    await asyncio.sleep(0.5)
    t = await tab.text('how-count')
    on_map = await tab.js("current === 'how' && HOW.scenario === 'dhcp'")
    check('T15 "Watch a request hop by hop" opens the map on the DHCP request', on_map and 'Step 1 of' in t, t)

    # ---- T16: each situation's path follows the real network ----------------
    #   all hops of all steps, joined, e.g. "pc2>arista2|arista2>controller|..."
    hops_js = "HOW.steps.map(s => s.hops.join('>')).join('|')"
    expect = {
        'dns-good': ('pc1>arista1', 'r1>inet'),                    # out to the Internet
        'dns-bad':  ('arista1>pc1', 'hp1>srv1'),                   # fake answer, then blocked page
        'dhcp':     ('arista2>cisco1', 'cisco1>r1'),               # normal way up
        'dhcp-cut': ('arista2>arista1', 'arista1>cisco1'),         # around the cut, over standby
    }
    for sc, needles in expect.items():
        await tab.click('#how-scenarios [data-id="%s"]' % sc)
        hops = await tab.js(hops_js)
        check('T16 %s path goes %s' % (sc, ' and '.join(needles)), all(n in hops for n in needles))
    # the blocked lookup never reaches the router before the browser step
    await tab.click('#how-scenarios [data-id="dns-bad"]')
    early = await tab.js("HOW.steps.slice(0, -1).some(s => s.hops.includes('r1'))")
    check('T16 blocked lookup: the router is not on the lookup\'s path', early is False)
    # the cut scenario draws the cut and opens the standby link
    await tab.click('#how-scenarios [data-id="dhcp-cut"]')
    drawn = await tab.js("document.querySelectorAll('#how-svg .cut').length === 2 && "
                         "document.querySelector('#how-svg .l.standby').classList.contains('open')")
    check('T16 cable cut: the cut is drawn and the standby link is shown in use', drawn)

    # ---- T16b: the trace situations print the hops the real switches use ----
    #   (checked against `ovs-ofctl dump-flows` after pc1 pings srv1; see
    #    logs/step7_1_console/trace_rules_real_vs_predicted.txt)
    out_js = "HOW.steps.filter(s => s.out).map(s => s.out.replace(/ +/g, ' ')).join('|')"
    trace_expect = {
        'trace':      ['arista1 (dpid 11) in 2 -> out 1', 'cisco1 (dpid 1) in 2 -> out 1',
                       'r1 (router) VLAN 10 -> 20', 'cisco1 (dpid 1) in 1 -> out 4',
                       'hp1 (dpid 21) in 1 -> out 2', 'srv1 reached'],
        'trace-cut':  ['arista2 (dpid 12) in 2 -> out 4 (standby link)', 'arista1 (dpid 11) in 4 -> out 1'],
        'trace-miss': ['cisco1 (dpid 1) in 2 -> out 3', 'arista2 (dpid 12) in 1 -> no rule yet'],
    }
    for sc, lines in trace_expect.items():
        await tab.click('#how-scenarios [data-id="%s"]' % sc)
        out = await tab.js(out_js)
        missing = [l for l in lines if l not in out]
        check('T16 %s prints the expected hops' % sc, not missing, 'missing: %s' % missing if missing else '')

    # ---- T17: Next and Back move between steps -----------------------------
    await tab.click('#how-scenarios [data-id="dns-good"]')
    await tab.click('#how-next')
    a = await tab.wait_text('how-count', 'Step 2 of', 3)
    await tab.click('#how-back')
    b = await tab.wait_text('how-count', 'Step 1 of', 3)
    check('T17 Next goes to step 2, Back returns to step 1', 'Step 2 of' in a and 'Step 1 of' in b, '%s / %s' % (a, b))

    # ---- T18: Play moves the packet and advances by itself; Pause stops ------
    start = await tab.js("document.getElementById('how-dot').getAttribute('cx')")
    await tab.click('#how-play')
    await asyncio.sleep(0.3)
    moving = await tab.js("document.getElementById('how-dot').getAttribute('cx')")
    t = await tab.wait_text('how-count', 'Step 2 of', 12)
    await tab.click('#how-play')                                   # pause
    paused_at = await tab.text('how-count')
    await asyncio.sleep(4)
    still = await tab.text('how-count')
    label = await tab.text('how-play')
    check('T18 Play moves the packet and goes on to step 2 by itself', start != moving and 'Step 2 of' in t,
          'dot x %s -> %s' % (start, moving))
    check('T18 Pause stops it', paused_at == still and label == 'Play', '%s, button "%s"' % (still, label))

    # ---- T18b: Path trace tab: a live trace from the browser ----------------
    on_host('pc1', 'ping -c 2 -i 0.3 10.10.20.21 > /dev/null')     # make sure rules exist
    await tab.click('#tab-trace')
    await asyncio.sleep(0.5)
    await tab.js("document.getElementById('trace-src').value = 'pc1'; document.getElementById('trace-dst').value = 'srv1'")
    await tab.click('#trace-form button[type=submit]')
    head = await tab.wait_text('trace-head', 'reaches', 8)
    out = await tab.text('trace-out')
    lit = await tab.js("document.querySelectorAll('#trace-svg .l.on').length")
    check('T18b Path trace tab: "Trace path" shows pc1 reaching srv1 with every switch hop',
          'reaches' in head and 'arista1 (dpid 11)  in 2 -> out 1' in out and 'hp1 (dpid 21)      in 1 -> out 2' in out,
          head)
    check('T18b the traced path is lit on the map (5 links; cisco1-r1 is used both ways)', lit == 5,
          '%s links lit' % lit)

    # ---- T19: no JavaScript errors were thrown along the way ----------------
    # -1 = the error recorder is missing, so nothing was measured: a failure.
    errors = await tab.js('Array.isArray(window.__errors) ? JSON.stringify(window.__errors) : "-1"')
    check('T19 no JavaScript errors on the page (error recorder present)', errors == '[]', errors)


async def main():
    # Step 1: private headless Chrome with the DevTools port open.
    shutil.rmtree(PROFILE, ignore_errors=True)
    chrome = subprocess.Popen(
        ['google-chrome', '--headless=new', '--disable-gpu', '--no-sandbox',
         '--remote-debugging-port=%d' % DEBUG_PORT, '--user-data-dir=' + PROFILE, 'about:blank'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/json/version' % DEBUG_PORT, timeout=1)
                break
            except Exception:
                time.sleep(0.25)

        # Step 2: open the console in a new tab and connect to it.
        req = urllib.request.Request('http://127.0.0.1:%d/json/new?%s#dns' % (DEBUG_PORT, CONSOLE),
                                     method='PUT')
        target = json.loads(urllib.request.urlopen(req, timeout=5).read().decode())
        async with websockets.connect(target['webSocketDebuggerUrl'], max_size=None) as ws:
            tab = Tab(ws)
            # Step 3: record uncaught page errors. Installed so it runs before
            #         the page's own script, then the page is reloaded with it.
            #         (Page.enable is required: without it Chrome accepts the
            #         script but never runs it.)
            await tab.cdp('Page.enable')
            await tab.cdp('Page.addScriptToEvaluateOnNewDocument', {'source':
                "window.__errors = []; addEventListener('error', e => __errors.push(e.message));"
                "addEventListener('unhandledrejection', e => __errors.push(String(e.reason)));"})
            await tab.cdp('Page.reload')
            await asyncio.sleep(3)
            await run_tests(tab)
    finally:
        chrome.terminate()
        shutil.rmtree(PROFILE, ignore_errors=True)

    passed = sum(1 for _, ok, _ in results if ok)
    print('\n%d/%d checks passed' % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
