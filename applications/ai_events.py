"""Lab 9 Part B: the AI layer's event feed, for the console's "AI layer" tab.

The AI layer (B1-B3) runs on the laptop; the console is served by this
controller. Each step the AI layer takes (read the switches, ask the model,
validator verdict, human approval, rule installed, ...) is POSTed here, and
the console polls it to animate where each call goes.

  POST /lab9/ai/events          one event {"kind": ..., ...} or a list of them
  GET  /lab9/ai/events?since=N  events with id > N (oldest first, max 300)

Only a display feed: it never changes the network. The last 1000 events are
kept in memory (lost on restart; the AI layer also writes its own log files).
"""

import collections
import json
import time

from ryu.app.wsgi import ControllerBase, route

from .console import json_response

KEEP = 1000
MAX_EVENT_BYTES = 8000


# ===========================================================================
# Class 1: the event store
# ===========================================================================

class AiEventStore(object):
    def __init__(self):
        self.events = collections.deque(maxlen=KEEP)
        self.next_id = 1

    def add(self, event):
        """Store one event; returns its id. Refuses anything that is not a
        small JSON object with a 'kind'."""
        # Step 1: shape and size check (it is a display feed, not a data dump).
        if not isinstance(event, dict) or not isinstance(event.get('kind'), str):
            raise ValueError('an event is a JSON object with a "kind"')
        if len(json.dumps(event)) > MAX_EVENT_BYTES:
            raise ValueError('event larger than %d bytes' % MAX_EVENT_BYTES)
        # Step 2: number it and stamp the controller's receive time.
        event = dict(event, id=self.next_id, received=time.time())
        self.next_id += 1
        self.events.append(event)
        return event['id']

    def since(self, last_id, limit=300):
        """Events newer than last_id, oldest first."""
        return [e for e in self.events if e['id'] > last_id][:limit]


# ===========================================================================
# Class 2: REST API
# ===========================================================================

class AiEventsRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(AiEventsRestController, self).__init__(req, link, data, **config)
        self.store = data['ai_events']

    @route('lab9_ai_events', '/lab9/ai/events', methods=['GET'])
    def get_events(self, req, **kwargs):
        try:
            since = int(req.params.get('since', 0))
        except ValueError:
            return json_response({'error': 'since must be a number'}, 400)
        return json_response({'events': self.store.since(since), 'last_id': self.store.next_id - 1})

    @route('lab9_ai_events_post', '/lab9/ai/events', methods=['POST'])
    def post_events(self, req, **kwargs):
        try:
            body = json.loads(req.body.decode('utf-8'))
            items = body if isinstance(body, list) else [body]
            ids = [self.store.add(e) for e in items[:50]]
        except ValueError as e:
            return json_response({'error': str(e)}, 400)
        return json_response({'stored': ids})
