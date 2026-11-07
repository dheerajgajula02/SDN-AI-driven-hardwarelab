"""Lab 9 Part B: report each step of the AI layer, for the console's AI tab.

emit('llm_request', app='b1', purpose=..., ...) does two things:
  1. POSTs the event to the controller (/lab9/ai/events), so the console's
     "AI layer" tab can animate where the call goes, live.
  2. Appends it to logs/ai_events.jsonl (the permanent record).
A failure to reach the controller never stops the AI layer: the event is
still written to the file.

Event kinds used by B1-B3 (the console draws each one as a hop):
  run_start / run_end   an app starts / finishes (app, mode)
  collect               AI layer -> controller -> switches (REST reads)
  detect                code detectors found something (B3)
  llm_request           AI layer -> model (purpose, prompt size)
  llm_response          model -> AI layer (valid?, tokens, cost, seconds)
  validate              NSOT validator verdict (ok, reasons)
  approval              human or auto decision
  apply                 AI layer -> controller -> switch (rule installed/deleted)
  verify                re-read after acting
  refuse                request refused (why)
  report                final text shown to the operator
"""

import json
import os
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.environ.get('LAB9_EVENT_LOG', os.path.join(HERE, '..', 'logs', 'ai_events.jsonl'))
_state = {'base': None, 'post_failures': 0, 'enabled': True}


# ===========================================================================
# Function 1: where to send events
# ===========================================================================

def configure(base_url, enabled=True):
    """Step 1: remember the controller URL (http://ip:port); enabled=False
    keeps events local only (offline tests)."""
    _state['base'] = base_url
    _state['enabled'] = enabled


# ===========================================================================
# Function 2: send one event
# ===========================================================================

def emit(kind, **fields):
    """Record one AI-layer step. Returns the event (a dict)."""
    # Step 1: the event itself, with the laptop's time.
    event = dict(fields, kind=kind, t=round(time.time(), 3))
    # Step 2: permanent local record (one JSON line).
    folder = os.path.dirname(LOG_FILE)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder)
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(event, sort_keys=True, default=str) + '\n')
    # Step 3: live feed on the controller (best effort, 2 s timeout).
    if _state['enabled'] and _state['base']:
        try:
            body = json.dumps(event, default=str).encode('utf-8')
            req = urllib.request.Request(_state['base'] + '/lab9/ai/events', body,
                                         {'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=2).read()
        except Exception:
            _state['post_failures'] += 1
    return event


def llm_hook(info):
    """Step 1: llm_client calls this after every model request and every
    answer check; turn it into llm_request / llm_response events."""
    emit(info.pop('kind'), **info)
