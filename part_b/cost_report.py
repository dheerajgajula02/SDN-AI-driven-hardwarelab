#!/usr/bin/env python3
"""Lab 9 B5: the team's API call and cost report, from logs/api_calls.jsonl.

Every model request made through llm_client.py is one line in that log
(status, tokens, cost as reported by the provider); every answer check is
another line (valid or not). This prints, per purpose (b1_analyst_*,
b2_intent, b3_classify, tests, ...):
  requests, HTTP errors, answers checked, answers valid on the first try,
  tokens in / out / reasoning, cost in US dollars
and the totals. --markdown prints a table for the lab document.

  python3 part_b/cost_report.py
  python3 part_b/cost_report.py --markdown
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, '..', 'logs', 'api_calls.jsonl')


# ===========================================================================
# Function 1: read the log, group by purpose
# ===========================================================================

def summarise(path=LOG):
    rows = {}
    with open(path) as f:
        for line in f:
            e = json.loads(line)
            # Step 1: group: b1_analyst_v3_checklist -> b1_analyst (variant kept apart).
            p = rows.setdefault(e.get('purpose', '?'), {'requests': 0, 'http_errors': 0, 'checks': 0, 'valid': 0,
                                                         'first_try_valid': 0, 'in': 0, 'out': 0, 'reasoning': 0,
                                                         'cost': 0.0, 'seconds': 0.0})
            # Step 2: an HTTP line (has "status") or a check line (has "valid").
            if 'status' in e:
                p['requests'] += 1
                p['http_errors'] += 1 if e['status'] != 200 else 0
                p['in'] += e.get('prompt_tokens') or 0
                p['out'] += e.get('completion_tokens') or 0
                p['reasoning'] += e.get('reasoning_tokens') or 0
                p['cost'] += e.get('cost_usd') or 0
                p['seconds'] += e.get('seconds') or 0
            elif 'valid' in e:
                p['checks'] += 1
                p['valid'] += 1 if e['valid'] else 0
                p['first_try_valid'] += 1 if e['valid'] and e.get('attempt', '').startswith('answer1') else 0
    return rows


# ===========================================================================
# Function 2: print it
# ===========================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--markdown', action='store_true')
    ap.add_argument('--log', default=LOG)
    args = ap.parse_args()
    rows = summarise(args.log)
    tot = dict((k, sum(r[k] for r in rows.values())) for k in next(iter(rows.values())))
    cols = ('requests', 'http_errors', 'checks', 'valid', 'in', 'out', 'reasoning', 'cost')
    if args.markdown:
        print('| purpose | requests | HTTP errors | answers checked | valid | tokens in | out | of which reasoning | cost (USD) |')
        print('|---|---|---|---|---|---|---|---|---|')
        for name, r in sorted(rows.items()) + [('**total**', tot)]:
            print('| %s | %d | %d | %d | %d | %d | %d | %d | %.4f |' % ((name,) + tuple(r[c] for c in cols)))
    else:
        print('%-30s %8s %6s %7s %6s %9s %8s %9s %10s' % ('purpose', 'requests', 'errors', 'checked', 'valid',
                                                         'tokens in', 'out', 'reasoning', 'cost USD'))
        for name, r in sorted(rows.items()) + [('TOTAL', tot)]:
            print('%-30s %8d %6d %7d %6d %9d %8d %9d %10.4f' % ((name,) + tuple(r[c] for c in cols)))
        print('\nmodel time: %.0f s; average cost per request: $%.5f' % (tot['seconds'],
                                                                       tot['cost'] / max(1, tot['requests'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
