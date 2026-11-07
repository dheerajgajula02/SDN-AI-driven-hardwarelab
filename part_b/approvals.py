"""Lab 9 Part B: ask the operator, in the console AND the terminal.

ask_operator() is the human step of B2 (always) and B3 (HITL mode):
  1. POST the question to the controller (/lab9/ai/approvals): the console's
     "AI layer" tab shows it with Approve / Reject buttons and a countdown.
  2. At the same time, if this program runs in a terminal, ask y/N there.
  3. The FIRST answer wins (console click or terminal key). A terminal answer
     is also sent to the controller, so the console shows who decided.
  4. No answer before the deadline = NO. Anything unexpected (controller
     unreachable and no terminal) = NO. The safe answer is always "do nothing".
The plan stays here: an "approved" only lets THIS program apply the plan it
showed (already checked by the NSOT validator).
Standard library only.
"""

import json
import select
import sys
import time
import urllib.error
import urllib.request

import events

POLL_SECONDS = 1.0


# ===========================================================================
# Function 1: REST helpers
# ===========================================================================

def _post(base, path, body):
    req = urllib.request.Request(base + path, json.dumps(body).encode('utf-8'),
                                 {'Content-Type': 'application/json'})
    return json.loads(urllib.request.urlopen(req, timeout=5).read().decode('utf-8'))


def _get(base, path):
    return json.loads(urllib.request.urlopen(base + path, timeout=5).read().decode('utf-8'))


def decide(base, rid, approve, by):
    """Send a decision. Returns the controller's record: if someone else
    answered first (409), that earlier answer is returned instead."""
    try:
        return _post(base, '/lab9/ai/approvals/decide', {'id': rid, 'approve': approve, 'by': by})
    except urllib.error.HTTPError as e:
        if e.code == 409:
            return _get(base, '/lab9/ai/approvals?id=%d' % rid)
        raise


# ===========================================================================
# Function 2: ask, wait for the first answer
# ===========================================================================

def terminal_available(stream=None):
    stream = stream or sys.stdin
    try:
        return stream.isatty()
    except Exception:
        return False


def ask_operator(base, app, title, steps, checks=(), interpretation='', timeout=120,
                 terminal=None, out=print):
    """Returns (approved: bool, decided_by: 'console'|'terminal'|'timeout'|...)."""
    use_terminal = terminal_available() if terminal is None else terminal
    request = {'app': app, 'title': title, 'interpretation': interpretation, 'steps': list(steps),
               'checks': list(checks), 'timeout_s': int(timeout)}

    # Step 1: put the question in the console.
    rid = None
    try:
        rid = _post(base, '/lab9/ai/approvals', request)['id']
    except Exception as e:
        out('(console approval unavailable: %s)' % e)
        if not use_terminal:
            events.emit('approval', app=app, mode='human', decision=False, by='no operator reachable')
            return False, 'no operator reachable'
    events.emit('approval_request', app=app, title=title, approval_id=rid, timeout=timeout,
                where=' and '.join(w for w, ok in (('console', rid is not None), ('terminal', use_terminal)) if ok))

    # Step 2: say where to answer.
    where = []
    if rid is not None:
        where.append('in the console (%s/lab9/ui#ai)' % base)
    if use_terminal:
        where.append('here')
    out('Waiting for approval %s: answer %s. No answer in %d s = NO.' % (
        '#%s' % rid if rid else '', ' or '.join(where), timeout))
    if use_terminal:
        sys.stdout.write('Apply? [y/N] ')
        sys.stdout.flush()

    # Step 3: whichever answers first.
    deadline = time.time() + timeout
    while time.time() < deadline:
        if use_terminal:
            ready, _, _ = select.select([sys.stdin], [], [], POLL_SECONDS)
            if ready:
                yes = sys.stdin.readline().strip().lower() in ('y', 'yes')
                if rid is None:
                    return _done(app, yes, 'terminal', out)
                rec = decide(base, rid, yes, 'terminal')
                return _done(app, rec['status'] == 'approved', rec['decided_by'], out)
        else:
            time.sleep(POLL_SECONDS)
        if rid is not None:
            try:
                rec = _get(base, '/lab9/ai/approvals?id=%d' % rid)
            except Exception:
                continue                            # a missed poll is not an answer
            if rec['status'] != 'pending':
                if use_terminal:
                    print('')
                return _done(app, rec['status'] == 'approved', rec['decided_by'], out)

    # Step 4: nobody answered: NO (and tell the console, so it stops waiting).
    if rid is not None:
        try:
            rec = decide(base, rid, False, 'timeout')
            return _done(app, rec['status'] == 'approved', rec['decided_by'], out)
        except Exception:
            pass
    return _done(app, False, 'timeout', out)


def _done(app, yes, by, out):
    out('%s by %s' % ('APPROVED' if yes else 'NOT approved', by))
    events.emit('approval', app=app, mode='human', decision=yes, by=by)
    return yes, by
