#!/usr/bin/env python3
"""Operator approval in the console, end to end: real B2 requests, real
model, a real browser clicking Approve / Reject, checked on the wire.

  A1 "Block pc1 from pinging srv1": the card appears in the AI tab (with the
     exact rule, the checks and a countdown; badge on the tab); a click on
     APPROVE -> rule installed on arista1; ping pc1 -> srv1 now fails
     (control: web pc1 -> srv1 still works)
  A2 "Allow pc1 to ping srv1 again": REJECT -> nothing changes (ping still
     fails, the block is still on arista1)
  A3 the same request, nobody answers (12 s) -> counts as no, the console
     shows "nobody answered in time", the block is still there
  A4 the same request, APPROVE -> the block is deleted, ping works again
  plus: the diagram shows "Asking the operator" and "Human: yes (console)",
  a second answer to a decided request is refused (409), no page errors.

Needs network + Ryu (with ai_approvals), SSHPASS=<mininet password>,
lab9/.env, google-chrome and the python websockets package.
  python3 lab9/part_b/tests/test_approvals_ui.py
"""

import asyncio
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(HERE, '..', '..', 'applications', 'tests'))

import websockets                     # noqa: E402

import approvals                      # noqa: E402
import b2_intent                      # noqa: E402
import collector                      # noqa: E402
import events                         # noqa: E402
import llm_client                     # noqa: E402
from mininet_host import on_host      # noqa: E402
from test_console_ui import Tab       # noqa: E402

BASE = 'http://100.110.3.67:8080'
NSOT = collector.load_nsot()
PORT, PROFILE = 9341, '/tmp/opencode/chrome-approvals'
OUT = os.path.join(HERE, '..', '..', 'logs', 'stepB2_approvals')
results = []


def check(name, passed, detail=''):
    results.append((name, bool(passed)))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('\n        %s' % (detail,)) if detail != '' else ''))
    sys.stdout.flush()


def ping_ok(src, dst_ip='10.10.20.21'):
    m = re.search(r'(\d+) received', on_host(src, 'ping -c 3 -i 0.3 -W 1 %s' % dst_ip))
    return bool(m and int(m.group(1)) > 0)


def web_ok(src):
    return on_host(src, 'curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.10.20.21/').strip() == '200'


def blocks():
    return [r for sw, r in b2_intent.list_intents(NSOT, BASE)]


def start_request(text, timeout):
    """Run one B2 request in a thread (it waits for the operator)."""
    box = {}
    t = threading.Thread(target=lambda: box.update(b2_intent.handle(text, NSOT, BASE, timeout=timeout)))
    t.daemon = True
    t.start()
    return t, box


async def wait_card(tab, seconds=90):
    """Wait until a pending approval card is shown; returns its text."""
    end = time.time() + seconds
    while time.time() < end:
        txt = await tab.js("(document.querySelector('#ai-approval-list .approval') || {}).innerText || ''")
        if txt:
            return txt
        await asyncio.sleep(0.5)
    return ''


async def click(tab, which):
    await tab.js("document.querySelector('#ai-approval-list .approval [data-decide=\"%s\"]').click()" % which)


async def main_async():
    shutil.rmtree(PROFILE, ignore_errors=True)
    chrome = subprocess.Popen(['google-chrome', '--headless=new', '--disable-gpu', '--no-sandbox', '--hide-scrollbars',
                               '--remote-debugging-port=%d' % PORT, '--user-data-dir=' + PROFILE,
                               '--window-size=1500,1300', 'about:blank'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/json/version' % PORT, timeout=1)
                break
            except Exception:
                time.sleep(0.25)
        tgt = json.loads(urllib.request.urlopen(urllib.request.Request(
            'http://127.0.0.1:%d/json/new?%s/lab9/ui#ai' % (PORT, BASE), method='PUT')).read().decode())
        async with websockets.connect(tgt['webSocketDebuggerUrl'], max_size=None) as ws:
            tab = Tab(ws)
            await tab.cdp('Page.enable')
            await tab.cdp('Page.addScriptToEvaluateOnNewDocument', {
                'source': "window.__errors=[];addEventListener('error',e=>__errors.push(e.message+' @'+e.lineno))"})
            await tab.cdp('Page.reload')
            await asyncio.sleep(3)
            await tab.js("document.getElementById('tab-dns').click()")     # badge must show from another tab

            # ---- A1: approve a block ----------------------------------------------------------
            check('control: pc1 pings srv1 and opens its web page; no intent rules',
                  ping_ok('pc1') and web_ok('pc1') and not blocks())
            t, box = start_request('Block pc1 from pinging srv1', 90)
            card = await wait_card(tab)
            badge = await tab.js("(document.querySelector('#tab-ai .badge') || {}).textContent || ''")
            check('A1 the request appears as a card, with a badge "1" on the AI layer tab (seen from the DNS tab)',
                  card and badge == '1', 'badge=%r' % badge)
            check('A1 the card shows the exact rule (arista1, DROP, ICMP), the validator checks and a countdown',
                  'arista1' in card and 'DROP' in card and '"ip_proto": 1' in card and 'protected packets' in card
                  and re.search(r'No answer in \d+ s', card), card[:400])
            await tab.js("document.getElementById('tab-ai').click()")
            await asyncio.sleep(2.5)
            shot = await tab.cdp('Page.captureScreenshot', {'format': 'png'})
            with open(os.path.join(OUT, 'approval_card.png'), 'wb') as f:
                f.write(base64.b64decode(shot['data']))
            check('A1 nothing is installed while waiting', not blocks())
            await click(tab, 'yes')
            t.join(30)
            check('A1 APPROVE in the console -> applied and verified on arista1, decided by "console"',
                  box.get('outcome') == 'applied' and box.get('by') == 'console'
                  and all(ok for _, ok in box.get('done', [])), (box.get('outcome'), box.get('by')))
            check('A1 on the wire: pc1 -> srv1 ping FAILS, web still WORKS (only ICMP blocked)',
                  not ping_ok('pc1') and web_ok('pc1'))
            rid = json.loads(urllib.request.urlopen(BASE + '/lab9/ai/approvals').read().decode())['approvals'][0]['id']
            try:
                approvals._post(BASE, '/lab9/ai/approvals/decide', {'id': rid, 'approve': False, 'by': 'late'})
                late = 200
            except urllib.error.HTTPError as e:
                late = e.code
            check('A1 a second answer to the decided request is refused (409: first answer wins)', late == 409, late)

            # ---- A2: reject ------------------------------------------------------------------------
            t, box = start_request('Allow pc1 to ping srv1 again', 90)
            card = await wait_card(tab)
            check('A2 "allow" request shown as a DELETE of the block on arista1', 'DELETE on arista1' in card, card[:300])
            await click(tab, 'no')
            t.join(30)
            check('A2 REJECT -> declined by "console", the block stays, ping still FAILS',
                  box.get('outcome') == 'declined' and box.get('by') == 'console' and len(blocks()) == 1
                  and not ping_ok('pc1'), (box.get('outcome'), box.get('by'), len(blocks())))

            # ---- A3: no answer ---------------------------------------------------------------------
            t, box = start_request('Allow pc1 to ping srv1 again', 12)
            card = await wait_card(tab)
            t.join(60)
            await asyncio.sleep(2.5)
            recent = await tab.text('ai-decided')
            check('A3 nobody answers in 12 s -> NO (by timeout), block stays, console says "nobody answered in time"',
                  box.get('outcome') == 'declined' and box.get('by') == 'timeout' and len(blocks()) == 1
                  and 'nobody answered in time' in recent, (box.get('outcome'), box.get('by'), recent[:200]))

            # ---- A4: approve the delete -------------------------------------------------------------
            t, box = start_request('Allow pc1 to ping srv1 again', 90)
            await wait_card(tab)
            await click(tab, 'yes')
            t.join(30)
            check('A4 APPROVE the allow -> block deleted (verified), ping pc1 -> srv1 WORKS again',
                  box.get('outcome') == 'applied' and not blocks() and ping_ok('pc1'), (box.get('outcome'), blocks()))

            # ---- the console after all of it ------------------------------------------------------------
            await asyncio.sleep(2.5)
            badge = await tab.js("(document.querySelector('#tab-ai .badge') || {}).textContent || ''")
            hidden = await tab.js("document.getElementById('ai-approvals').hidden")
            steps = await tab.text('ai-steps')
            check('C1 no request pending: badge gone, approval box hidden', badge == '' and hidden, (badge, hidden))
            check('C2 the diagram\'s steps for the last run include "Asking the operator" and "Human: yes (console)"',
                  'Asking the operator' in steps and 'Human: yes (console)' in steps, steps.replace('\n', ' | ')[:300])
            recent = await tab.text('ai-decided')
            check('C3 recent decisions list all four answers (approved, rejected, timeout, approved)',
                  recent.count('Approved') >= 2 and 'Rejected' in recent and 'nobody answered' in recent,
                  recent.replace('\n', ' | ')[:300])
            errs = await tab.js('JSON.stringify(__errors)')
            check('C4 no JavaScript errors on the page', errs == '[]', errs)
    finally:
        chrome.terminate()
        shutil.rmtree(PROFILE, ignore_errors=True)


def main():
    os.makedirs(OUT, exist_ok=True)
    events.configure(BASE)
    llm_client.EVENT_HOOK = events.llm_hook
    approvals.terminal_available = lambda stream=None: False     # the console is the only operator here
    b2_intent.clear_intents(NSOT, BASE)
    time.sleep(1)
    try:
        asyncio.run(main_async())
    finally:
        b2_intent.clear_intents(NSOT, BASE)
    passed = sum(1 for _, ok in results if ok)
    print('\n%d/%d checks passed  (model calls: %d)' % (passed, len(results), llm_client.calls_this_run()))
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
