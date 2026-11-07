"""Lab 9 Part B, step 2: the one door to the language model.

Every model call in B1, B2 and B3 goes through call_llm(). It does what the
Integration Rules and B5 ask for, in one place:

  1. Never trust model output: the answer must be JSON and must pass a schema
     (and an optional extra check in code). A bad answer gets ONE repair try
     with the exact errors shown to the model; after that the call fails.
  2. Retries only for temporary HTTP problems (408/429/5xx), with a pause.
  3. Cost log (B5): every HTTP call is one line in logs/api_calls.jsonl
     (time, purpose, model, tokens, cost, valid or not). Prompts and the API
     key are never written to the log.
  4. Budget (API Budget section): a hard cap on calls per run, and a kill
     switch: if the file part_b/STOP exists, no call is made at all.

Settings live ONLY in lab9/.env (never committed; see .env.example), so the
key, model and provider can be changed without touching code:
  LAB9_LLM_API_KEY     the key
  LAB9_LLM_MODEL       the model (team choice: deepseek-v4.1-flash)
  LAB9_LLM_BASE_URL    the provider's OpenAI-compatible URL
  LAB9_LLM_MAX_CALLS   optional: cap per run (default 60)
All three of key, model and base URL are required: nothing is guessed.

Any OpenAI-compatible chat-completions endpoint works. Standard library only.
"""

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
LAB9 = os.path.join(HERE, '..')
ENV_FILE = os.path.join(LAB9, '.env')
LOG_FILE = os.environ.get('LAB9_API_LOG', os.path.join(LAB9, 'logs', 'api_calls.jsonl'))
STOP_FILE = os.path.join(HERE, 'STOP')

RETRY_STATUS = (408, 429, 500, 502, 503, 504)   # temporary: worth another try
HTTP_TRIES = 3                                   # per answer
SCHEMA_TRIES = 2                                 # first answer + one repair

_calls_this_run = [0]                            # shared counter for the cap
# opencode's Go plan refuses requests without an x-opencode-session header
# (HTTP 400 MissingSessionID). One id per run groups this run's calls.
RUN_SESSION = 'lab9-' + uuid.uuid4().hex


class LLMError(Exception):
    """The model could not give a usable answer (HTTP failure, bad JSON,
    schema failure after the repair try, budget used up, kill switch)."""


# ===========================================================================
# Function 1: settings from lab9/.env
# ===========================================================================

def load_settings(env_file=ENV_FILE):
    """Read KEY=value lines from lab9/.env; real environment variables win.
    Returns {'key', 'base_url', 'model', 'max_calls'}."""
    # Step 1: the .env file (skip blank lines and # comments).
    values = {}
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    values[k.strip()] = v.strip().strip('"').strip("'")
    # Step 2: environment variables override the file (handy for one run).
    get = lambda k, d=None: os.environ.get(k) or values.get(k) or d
    # Step 3: key, model and base URL must all be set: no hidden defaults,
    #         so what runs is always exactly what .env says.
    missing = [k for k in ('LAB9_LLM_API_KEY', 'LAB9_LLM_MODEL', 'LAB9_LLM_BASE_URL') if not get(k)]
    if missing:
        raise LLMError('missing in lab9/.env: %s (see .env.example)' % ', '.join(missing))
    return {
        'key': get('LAB9_LLM_API_KEY'),
        'base_url': get('LAB9_LLM_BASE_URL').rstrip('/'),
        'model': get('LAB9_LLM_MODEL'),
        'max_calls': int(get('LAB9_LLM_MAX_CALLS', '60')),
    }


# ===========================================================================
# Function 2: check an answer against a JSON schema
# ===========================================================================

def schema_errors(value, schema, path='answer'):
    """Check `value` against a small JSON-schema subset; return a list of
    errors (empty = valid). Supported: type, enum, required, properties,
    additionalProperties: false, items, minItems, maxItems, minimum, maximum,
    maxLength. Kept small on purpose: every rule is readable here."""
    errors = []
    # Step 1: the type. JSON "integer" must not accept True/False or 1.5.
    kinds = {'object': dict, 'array': list, 'string': str, 'boolean': bool,
             'number': (int, float), 'integer': int, 'null': type(None)}
    want = schema.get('type')
    if want:
        allowed = want if isinstance(want, list) else [want]
        ok = False
        for t in allowed:
            if t in ('number', 'integer') and isinstance(value, bool):
                continue
            if isinstance(value, kinds[t]) and not (t == 'integer' and isinstance(value, float)):
                ok = True
        if not ok:
            return ['%s: expected %s, got %s' % (path, '/'.join(allowed), type(value).__name__)]
    # Step 2: allowed values and number/text limits.
    if 'enum' in schema and value not in schema['enum']:
        errors.append('%s: %r is not one of %s' % (path, value, schema['enum']))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if 'minimum' in schema and value < schema['minimum']:
            errors.append('%s: %s is below %s' % (path, value, schema['minimum']))
        if 'maximum' in schema and value > schema['maximum']:
            errors.append('%s: %s is above %s' % (path, value, schema['maximum']))
    if isinstance(value, str) and 'maxLength' in schema and len(value) > schema['maxLength']:
        errors.append('%s: longer than %d characters' % (path, schema['maxLength']))
    # Step 3: objects: required fields, each field's own schema, no extras.
    if isinstance(value, dict):
        props = schema.get('properties', {})
        for k in schema.get('required', []):
            if k not in value:
                errors.append('%s: missing field "%s"' % (path, k))
        for k, v in value.items():
            if k in props:
                errors.extend(schema_errors(v, props[k], '%s.%s' % (path, k)))
            elif schema.get('additionalProperties') is False:
                errors.append('%s: unexpected field "%s"' % (path, k))
    # Step 4: arrays: size limits and every item.
    if isinstance(value, list):
        if 'minItems' in schema and len(value) < schema['minItems']:
            errors.append('%s: needs at least %d items' % (path, schema['minItems']))
        if 'maxItems' in schema and len(value) > schema['maxItems']:
            errors.append('%s: at most %d items' % (path, schema['maxItems']))
        if 'items' in schema:
            for i, item in enumerate(value):
                errors.extend(schema_errors(item, schema['items'], '%s[%d]' % (path, i)))
    return errors


def parse_json_answer(text):
    """The model's text -> a JSON value. Accepts a bare JSON object or one
    wrapped in a ```json fence (models often add one). Raises ValueError."""
    # Step 1: strip a markdown code fence if there is one.
    t = (text or '').strip()
    if t.startswith('```'):
        t = t.split('\n', 1)[1] if '\n' in t else ''
        t = t.rsplit('```', 1)[0]
    # Step 2: parse; anything that is not JSON is an error, never "fixed up".
    return json.loads(t)


# ===========================================================================
# Function 3: the cost log (B5)
# ===========================================================================

def log_call(entry, log_file=None):
    """Append one line to logs/api_calls.jsonl. Never contains the key or
    the prompt text (only its size and a short fingerprint)."""
    # Step 1: make sure the folder exists; Step 2: one JSON object per line.
    log_file = log_file or LOG_FILE
    folder = os.path.dirname(log_file)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder)
    with open(log_file, 'a') as f:
        f.write(json.dumps(entry, sort_keys=True) + '\n')


def usage_fields(usage):
    """Tokens and cost from the provider's 'usage' block.
    opencode reports the price as usage.opencode.list_cost (US dollars)."""
    usage = usage or {}
    details = usage.get('completion_tokens_details') or {}
    oc = usage.get('opencode') or {}
    return {'prompt_tokens': usage.get('prompt_tokens'),
            'completion_tokens': usage.get('completion_tokens'),
            'reasoning_tokens': details.get('reasoning_tokens'),
            'cost_usd': oc.get('list_cost', usage.get('cost'))}


# ===========================================================================
# Function 4: one HTTP request to the model (with retries)
# ===========================================================================

def post_chat(settings, payload, purpose, attempt_label, log_file=None):
    """POST /chat/completions. Retries 408/429/5xx up to HTTP_TRIES times
    (pause 1 s, 2 s). Every try counts against the cap and is logged.
    Returns the parsed response JSON. Raises LLMError."""
    body = json.dumps(payload).encode('utf-8')
    headers = {'Authorization': 'Bearer ' + settings['key'],
               'Content-Type': 'application/json',
               # Cloudflare in front of opencode refuses Python's default
               # User-Agent (HTTP 403, "error code: 1010").
               'User-Agent': 'lab9-ai-layer/1.0',
               'x-opencode-session': RUN_SESSION}
    prompt_text = json.dumps(payload['messages'])
    last = None
    for n in range(1, HTTP_TRIES + 1):
        # Step 1: budget and kill switch BEFORE spending anything.
        if os.path.exists(STOP_FILE):
            raise LLMError('kill switch: %s exists, no model calls allowed' % STOP_FILE)
        if _calls_this_run[0] >= settings['max_calls']:
            raise LLMError('call cap reached (%d calls this run, LAB9_LLM_MAX_CALLS)' % settings['max_calls'])
        _calls_this_run[0] += 1

        # Step 2: the request.
        entry = {'time': datetime.now().isoformat(), 'purpose': purpose, 'model': settings['model'],
                 'attempt': '%s/http%d' % (attempt_label, n), 'run': RUN_SESSION,
                 'prompt_chars': len(prompt_text),
                 'prompt_sha1': hashlib.sha1(prompt_text.encode('utf-8')).hexdigest()[:12]}
        started = time.time()
        try:
            req = urllib.request.Request(settings['base_url'] + '/chat/completions', body, headers)
            with urllib.request.urlopen(req, timeout=90) as r:
                data = json.loads(r.read().decode('utf-8'))
            entry.update(status=200, seconds=round(time.time() - started, 2))
            entry.update(usage_fields(data.get('usage')))
            log_call(entry, log_file)
            return data
        except urllib.error.HTTPError as e:
            # Step 3: log the failure; retry only if it is temporary.
            entry.update(status=e.code, seconds=round(time.time() - started, 2),
                         error=e.read().decode('utf-8', 'replace')[:200])
            log_call(entry, log_file)
            last = 'HTTP %d: %s' % (e.code, entry['error'])
            if e.code not in RETRY_STATUS:
                break
        except Exception as e:                  # timeout, DNS, connection refused
            entry.update(status=None, seconds=round(time.time() - started, 2), error=str(e)[:200])
            log_call(entry, log_file)
            last = str(e)
        if n < HTTP_TRIES:
            time.sleep(n)                       # 1 s, then 2 s
    raise LLMError('model request failed: %s' % last)


# ===========================================================================
# Function 5: ask for a JSON answer that passes the schema (the main entry)
# ===========================================================================

def call_llm(purpose, system, user, schema, extra_check=None, max_tokens=4000,
             temperature=0, settings=None, log_file=None):
    """Ask the model; return {'answer': validated JSON, 'calls': n, 'repaired': bool}.

    purpose      short label for the cost log, e.g. "b1_analyst"
    system/user  the prompt (user may be a dict: it is sent as JSON)
    schema       the JSON schema the answer must pass
    extra_check  optional function(answer) -> list of error strings, for
                 rules a schema can't express (e.g. "switch must be in the NSOT")

    The first answer that fails gets ONE repair try: the model is shown its
    own answer and the exact errors. A second failure raises LLMError, so
    the caller never acts on an unchecked answer."""
    settings = settings or load_settings()
    if not isinstance(user, str):
        user = json.dumps(user, indent=1, sort_keys=True)
    # The model must SEE the schema it is checked against. (First live test
    # without it: the model invented its own field names and was refused
    # twice; logged in the B5 failure log.)
    messages = [{'role': 'system', 'content': system +
                 '\n\nAnswer with ONE JSON object only, no other text. It must match this JSON schema '
                 'exactly (same field names, allowed values only, no extra fields):\n' +
                 json.dumps(schema, indent=1, sort_keys=True)},
                {'role': 'user', 'content': user}]
    calls_before = _calls_this_run[0]
    errors = []
    for attempt in range(1, SCHEMA_TRIES + 1):
        # Step 1: ask (with HTTP retries inside post_chat).
        data = post_chat(settings, {'model': settings['model'], 'messages': messages,
                                    'max_tokens': max_tokens, 'temperature': temperature},
                         purpose, 'answer%d' % attempt, log_file)
        text = ((data.get('choices') or [{}])[0].get('message') or {}).get('content') or ''

        # Step 2: it must be JSON ...
        try:
            answer = parse_json_answer(text)
            # Step 3: ... pass the schema ...
            errors = schema_errors(answer, schema)
            # Step 4: ... and the caller's own checks (only if the schema passed).
            if not errors and extra_check:
                errors = list(extra_check(answer) or [])
        except ValueError as e:
            answer, errors = None, ['not valid JSON: %s' % e]

        # Step 5: record the verdict in the cost log, then return or repair.
        log_call({'time': datetime.now().isoformat(), 'purpose': purpose, 'model': settings['model'],
                  'attempt': 'answer%d/check' % attempt, 'valid': not errors, 'errors': errors[:5]}, log_file)
        if not errors:
            return {'answer': answer, 'calls': _calls_this_run[0] - calls_before, 'repaired': attempt > 1}
        messages = messages + [
            {'role': 'assistant', 'content': text[:4000]},
            {'role': 'user', 'content': 'Your answer was rejected by the validator:\n- ' + '\n- '.join(errors[:10]) +
                                        '\nSend the corrected JSON object only.'}]
    raise LLMError('answer still invalid after a repair try: ' + '; '.join(errors[:5]))


def calls_this_run():
    """How many HTTP calls this process has made (for loop summaries)."""
    return _calls_this_run[0]
