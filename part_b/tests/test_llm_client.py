#!/usr/bin/env python3
"""Tests part_b/llm_client.py.

Part 1 (free, offline): a fake model server on 127.0.0.1 answers exactly
what each test needs (good answer, 429, bad JSON, wrong schema, ...), so
every safety rule is exercised on purpose and the server counts how many
requests really arrived.
Part 2 (1 real call, < $0.001): the real model returns a valid answer and the
team cost log (logs/api_calls.jsonl) records tokens and cost.

Run:  python3 lab9/part_b/tests/test_llm_client.py          (both parts)
      python3 lab9/part_b/tests/test_llm_client.py --offline
"""

import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import llm_client                                   # noqa: E402
from llm_client import LLMError, call_llm, schema_errors   # noqa: E402

results = []
FAKE_KEY = 'sk-test-THIS-MUST-NEVER-APPEAR-IN-THE-LOG'
SCHEMA = {'type': 'object', 'additionalProperties': False, 'required': ['health', 'issues'],
          'properties': {'health': {'type': 'string', 'enum': ['ok', 'degraded']},
                         'issues': {'type': 'array', 'items': {'type': 'string'}, 'maxItems': 5}}}
GOOD = {'health': 'ok', 'issues': []}


def check(name, passed, detail=''):
    results.append((name, bool(passed)))
    print('%s  %s%s' % ('PASS' if passed else 'FAIL', name, ('\n        %s' % (detail,)) if detail != '' else ''))


# ===========================================================================
# The fake model server
# ===========================================================================

class Fake(object):
    script = []          # what to answer, one item per request: (status, content)
    requests = []        # what arrived


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])).decode())
        Fake.requests.append({'body': body, 'auth': self.headers.get('Authorization')})
        status, content = Fake.script.pop(0) if Fake.script else (200, json.dumps(GOOD))
        if status == 200:
            out = {'choices': [{'message': {'content': content}}],
                   'usage': {'prompt_tokens': 100, 'completion_tokens': 20,
                             'opencode': {'list_cost': 0.0001}}}
        else:
            out = {'error': 'fake %d' % status}
        raw = json.dumps(out).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


def run(script, max_calls=60, extra_check=None, model='test-model-from-env'):
    """One call_llm against the fake server. Returns (result or LLMError,
    requests that reached the server, log lines)."""
    Fake.script, Fake.requests = list(script), []
    llm_client._calls_this_run[0] = 0
    log = tempfile.mktemp(suffix='.jsonl')
    settings = {'key': FAKE_KEY, 'base_url': 'http://127.0.0.1:%d' % PORT, 'model': model,
                'max_calls': max_calls}
    try:
        out = call_llm('test', 'You check networks.', {'secret_prompt_marker': 'PROMPT-TEXT-XYZ'},
                       SCHEMA, extra_check=extra_check, settings=settings, log_file=log)
    except LLMError as e:
        out = e
    lines = open(log).read().splitlines() if os.path.exists(log) else []
    if os.path.exists(log):
        os.remove(log)
    return out, list(Fake.requests), [json.loads(l) for l in lines]


def offline():
    llm_client.time.sleep = lambda s: None          # no real pauses between retries

    # ---- L1: a good answer the first time ------------------------------------
    out, reqs, log = run([(200, json.dumps(GOOD))])
    check('L1 good answer: returned, 1 request, not repaired',
          not isinstance(out, LLMError) and out['answer'] == GOOD and len(reqs) == 1 and not out['repaired'])
    http = [l for l in log if 'status' in l]
    check('L1 cost log: 1 HTTP line with tokens + cost, 1 "valid" verdict line',
          len(http) == 1 and http[0]['prompt_tokens'] == 100 and http[0]['cost_usd'] == 0.0001
          and [l['valid'] for l in log if 'valid' in l] == [True], http)
    raw = json.dumps(log)
    check('L1 the log never contains the API key or the prompt text',
          FAKE_KEY not in raw and 'PROMPT-TEXT-XYZ' not in raw and 'secret_prompt_marker' not in raw)
    check('L1 the key is sent to the server (Authorization header)', reqs[0]['auth'] == 'Bearer ' + FAKE_KEY)
    system = reqs[0]['body']['messages'][0]['content']
    check('L1 the model is shown the schema (field names + allowed values in the system prompt)',
          '"enum"' in system and '"degraded"' in system and '"issues"' in system)
    check('L1 the request uses the model from the settings', reqs[0]['body']['model'] == 'test-model-from-env')

    # ---- L2: temporary error (429) is retried -----------------------------------
    out, reqs, log = run([(429, ''), (200, json.dumps(GOOD))])
    check('L2 HTTP 429 then OK: retried, answer returned, 2 requests logged',
          not isinstance(out, LLMError) and len(reqs) == 2 and [l.get('status') for l in log if 'status' in l] == [429, 200])

    # ---- L3: permanent error (401) is NOT retried ---------------------------------
    out, reqs, log = run([(401, '')])
    check('L3 HTTP 401 (bad key): fails at once, no retry (1 request)',
          isinstance(out, LLMError) and len(reqs) == 1, out)

    # ---- L4: a wrong answer gets ONE repair try, with the errors shown ----------
    out, reqs, log = run([(200, json.dumps({'health': 'fine', 'issues': []})), (200, json.dumps(GOOD))])
    repair = reqs[1]['body']['messages'][-1]['content'] if len(reqs) > 1 else ''
    check('L4 schema failure then fixed: repaired=True, 2 requests',
          not isinstance(out, LLMError) and out['repaired'] and len(reqs) == 2)
    check('L4 the repair request shows the model its exact error',
          "'fine' is not one of ['ok', 'degraded']" in repair, repair[:120])

    # ---- L5: wrong twice -> refused, the caller gets an error, never the answer ---
    bad = json.dumps({'health': 'ok', 'issues': [], 'action': 'delete all flows'})
    out, reqs, log = run([(200, bad), (200, bad)])
    check('L5 invalid twice (extra field "action"): LLMError, only 2 requests',
          isinstance(out, LLMError) and 'unexpected field "action"' in str(out) and len(reqs) == 2, out)

    # ---- L6: JSON in a code fence is accepted; prose is not -------------------------
    out, reqs, log = run([(200, '```json\n' + json.dumps(GOOD) + '\n```')])
    check('L6 answer inside a ```json fence is accepted', not isinstance(out, LLMError) and len(reqs) == 1)
    out, reqs, log = run([(200, 'The network looks healthy.'), (200, 'Still fine!')])
    check('L6 prose instead of JSON: rejected after the repair try', isinstance(out, LLMError)
          and 'not valid JSON' in str(out), out)

    # ---- L7: the caller's own check (e.g. names must exist in the NSOT) -----------
    nsot_names = ['pc1', 'srv1']
    chk = lambda a: ['unknown host %s' % h for h in a['issues'] if h not in nsot_names]
    out, reqs, log = run([(200, json.dumps({'health': 'degraded', 'issues': ['pc9']})),
                          (200, json.dumps({'health': 'degraded', 'issues': ['pc1']}))], extra_check=chk)
    check('L7 extra_check rejects an unknown host, the repair fixes it',
          not isinstance(out, LLMError) and out['answer']['issues'] == ['pc1'] and out['repaired'])

    # ---- L8: call cap: refused BEFORE anything is sent ----------------------------
    out, reqs, log = run([(500, ''), (500, ''), (500, '')], max_calls=2)
    check('L8 call cap 2: two 500s, the third request is never sent (cap reached)',
          isinstance(out, LLMError) and 'call cap' in str(out) and len(reqs) == 2, out)

    # ---- L9: kill switch: no request at all --------------------------------------
    stop = tempfile.mktemp()
    real_stop, llm_client.STOP_FILE = llm_client.STOP_FILE, stop
    try:
        open(stop, 'w').close()
        out, reqs, log = run([(200, json.dumps(GOOD))])
        check('L9 kill switch file present: refused, 0 requests reached the server',
              isinstance(out, LLMError) and 'kill switch' in str(out) and len(reqs) == 0, out)
    finally:
        os.remove(stop)
        llm_client.STOP_FILE = real_stop

    # ---- L9b: key, model and base URL come from the .env file -----------------------
    env = tempfile.mktemp()
    try:
        with open(env, 'w') as f:
            f.write('# comment\nLAB9_LLM_API_KEY=abc123\nLAB9_LLM_MODEL="some-other-model"\n'
                    'LAB9_LLM_BASE_URL=https://example.test/v1/\n')
        s = llm_client.load_settings(env)
        check('L9b settings are read from .env (key, model, base URL; quotes and trailing / handled)',
              s['key'] == 'abc123' and s['model'] == 'some-other-model' and s['base_url'] == 'https://example.test/v1'
              and s['max_calls'] == 60, dict(s, key='<hidden>'))
        with open(env, 'w') as f:
            f.write('LAB9_LLM_API_KEY=abc123\nLAB9_LLM_BASE_URL=https://example.test/v1\n')
        try:
            llm_client.load_settings(env)
            missing = None
        except LLMError as e:
            missing = e
        check('L9b no model in .env: refused with a clear message (nothing is guessed)',
              missing is not None and 'LAB9_LLM_MODEL' in str(missing), missing)
    finally:
        os.remove(env)

    # ---- L10: the schema checker on its own --------------------------------------
    s = {'type': 'object', 'required': ['n'], 'properties': {'n': {'type': 'integer', 'minimum': 1}}}
    check('L10 schema: true is not an integer, 1.5 is not, 0 is below the minimum, 3 is fine',
          schema_errors({'n': True}, s) and schema_errors({'n': 1.5}, s) and schema_errors({'n': 0}, s)
          and not schema_errors({'n': 3}, s))


def live():
    llm_client._calls_this_run[0] = 0
    before = sum(1 for _ in open(llm_client.LOG_FILE)) if os.path.exists(llm_client.LOG_FILE) else 0
    try:
        out = call_llm('test_llm_client', 'You are a network health checker.',
                       'All 6 switches are connected and every link is up. Report health.', SCHEMA, max_tokens=500)
    except LLMError as e:
        check('LIVE real model returns a schema-valid answer', False, e)
        return
    lines = [json.loads(l) for l in open(llm_client.LOG_FILE).read().splitlines()[before:]]
    http = [l for l in lines if l.get('status') == 200]
    check('LIVE real model returns a schema-valid answer', out['answer']['health'] in ('ok', 'degraded'),
          '%s  (%d call%s)' % (out['answer'], out['calls'], '' if out['calls'] == 1 else 's'))
    check('LIVE team cost log (logs/api_calls.jsonl) has tokens and a cost',
          http and http[0]['prompt_tokens'] and http[0]['cost_usd'] is not None, http and http[-1])
    key = llm_client.load_settings()['key']
    check('LIVE the real key is not in the cost log', key not in open(llm_client.LOG_FILE).read())


if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 0), Handler)
    PORT = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    real_sleep = llm_client.time.sleep
    offline()
    llm_client.time.sleep = real_sleep
    if '--offline' not in sys.argv:
        live()
    passed = sum(1 for _, ok in results if ok)
    print('\n%d/%d checks passed' % (passed, len(results)))
    sys.exit(0 if passed == len(results) else 1)
