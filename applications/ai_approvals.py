"""Lab 9 Part B: operator approvals for the AI layer, from the console.

B2 (intents) and B3 in HITL mode must ask a human before they change the
network. They ask in two places at once: the terminal they run in, and the
console's "AI layer" tab. The first answer wins; no answer before the
deadline is a NO.

What the controller stores is only the QUESTION and the ANSWER:
  1. The AI layer (laptop) POSTs a request: what it will change (the exact
     rules, as text), the model's interpretation, and what the NSOT
     validator checked. The plan itself stays on the laptop.
  2. The console lists pending requests with Approve / Reject buttons and a
     countdown; a click POSTs the decision.
  3. The AI layer polls the request; on "approved" it applies exactly the
     plan it showed (already validated), on anything else it does nothing.
So a decision can only say yes or no to a validated plan: nobody can put a
different rule into the network through this API.

  POST /lab9/ai/approvals              create {app, title, steps[], checks[],
                                        interpretation, timeout_s} -> record
  GET  /lab9/ai/approvals              all records (newest first) + pending count
  GET  /lab9/ai/approvals?id=N         one record
  POST /lab9/ai/approvals/decide       {id, approve: true|false, by} -> record
                                        (409 if it was already decided)

Lab-grade: no authentication (like the rest of Ryu's REST API on 8080), see
docs/B5_PRODUCTION_READINESS.md. Kept in memory (last 200 requests).
"""

import collections
import json
import time

from ryu.app.wsgi import ControllerBase, route

from .console import json_response

KEEP = 200
DEFAULT_TIMEOUT = 120
MIN_TIMEOUT, MAX_TIMEOUT = 10, 600
MAX_REQUEST_BYTES = 12000


# ===========================================================================
# Class 1: the approval store
# ===========================================================================

class ApprovalStore(object):
    """Pending and decided approval requests. Status of a request:
    pending -> approved | rejected | expired (no answer in time = no)."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.items = collections.OrderedDict()      # id -> record, oldest first
        self.next_id = 1

    def create(self, req):
        """Step 1: check the request's shape and size; Step 2: store it as
        pending with a deadline. Returns the record."""
        if not isinstance(req, dict):
            raise ValueError('an approval request is a JSON object')
        if len(json.dumps(req)) > MAX_REQUEST_BYTES:
            raise ValueError('request larger than %d bytes' % MAX_REQUEST_BYTES)
        for k in ('app', 'title'):
            if not isinstance(req.get(k), str) or not req[k]:
                raise ValueError('"%s" (text) is required' % k)
        steps = req.get('steps')
        if not isinstance(steps, list) or not steps or not all(isinstance(s, str) for s in steps):
            raise ValueError('"steps" must be a non-empty list of text (what will change)')
        checks = req.get('checks', [])
        if not isinstance(checks, list) or not all(isinstance(c, str) for c in checks):
            raise ValueError('"checks" must be a list of text')
        try:
            timeout = int(req.get('timeout_s', DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            raise ValueError('"timeout_s" must be a number')
        timeout = max(MIN_TIMEOUT, min(MAX_TIMEOUT, timeout))
        now = self.clock()
        rec = {'id': self.next_id, 'app': req['app'], 'title': req['title'],
               'interpretation': str(req.get('interpretation') or ''), 'steps': steps, 'checks': checks,
               'status': 'pending', 'created': now, 'expires': now + timeout, 'timeout_s': timeout,
               'decided': None, 'decided_by': None}
        self.next_id += 1
        self.items[rec['id']] = rec
        while len(self.items) > KEEP:
            self.items.popitem(last=False)
        return rec

    def _expire(self):
        """Pending requests past their deadline become 'expired' (= no)."""
        now = self.clock()
        for rec in self.items.values():
            if rec['status'] == 'pending' and now >= rec['expires']:
                rec.update(status='expired', decided=rec['expires'], decided_by='timeout')

    def get(self, rid):
        self._expire()
        rec = self.items.get(rid)
        return dict(rec, seconds_left=self._left(rec)) if rec else None

    def _left(self, rec):
        return max(0, round(rec['expires'] - self.clock(), 1)) if rec['status'] == 'pending' else 0

    def all(self):
        """Every record, newest first, with seconds left on pending ones."""
        self._expire()
        return [dict(r, seconds_left=self._left(r)) for r in reversed(list(self.items.values()))]

    def decide(self, rid, approve, by):
        """Step 1: only a pending request can be decided (first answer wins);
        Step 2: record yes/no and who answered. Raises KeyError / LookupError."""
        self._expire()
        rec = self.items.get(rid)
        if rec is None:
            raise KeyError('no approval request %s' % rid)
        if rec['status'] != 'pending':
            raise LookupError('request %s is already %s (by %s)' % (rid, rec['status'], rec['decided_by']))
        rec.update(status='approved' if approve else 'rejected', decided=self.clock(),
                   decided_by=str(by or 'console')[:40])
        return dict(rec, seconds_left=0)


# ===========================================================================
# Class 2: REST API
# ===========================================================================

class AiApprovalsRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(AiApprovalsRestController, self).__init__(req, link, data, **config)
        self.store = data['ai_approvals']

    @route('lab9_ai_approvals', '/lab9/ai/approvals', methods=['GET'])
    def get_approvals(self, req, **kwargs):
        if 'id' in req.params:
            try:
                rec = self.store.get(int(req.params['id']))
            except ValueError:
                return json_response({'error': 'id must be a number'}, 400)
            return json_response(rec) if rec else json_response({'error': 'no such request'}, 404)
        items = self.store.all()
        return json_response({'approvals': items, 'pending': sum(1 for r in items if r['status'] == 'pending')})

    @route('lab9_ai_approvals_post', '/lab9/ai/approvals', methods=['POST'])
    def post_approval(self, req, **kwargs):
        try:
            rec = self.store.create(json.loads(req.body.decode('utf-8')))
        except ValueError as e:
            return json_response({'error': str(e)}, 400)
        return json_response(dict(rec, seconds_left=rec['timeout_s']))

    @route('lab9_ai_approvals_decide', '/lab9/ai/approvals/decide', methods=['POST'])
    def decide(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode('utf-8'))
            if not isinstance(body.get('approve'), bool):
                raise ValueError('"approve" must be true or false')
            rec = self.store.decide(int(body.get('id')), body['approve'], body.get('by', 'console'))
        except (ValueError, TypeError) as e:
            return json_response({'error': str(e)}, 400)
        except KeyError as e:
            return json_response({'error': str(e).strip("'")}, 404)
        except LookupError as e:
            return json_response({'error': str(e)}, 409)
        return json_response(rec)
