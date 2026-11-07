# Part B: AI layer design (schemas, prompts, validation, autonomy)

Group 3. This is the "AI layer design" deliverable. Code: `lab9/part_b/`.
Build history and test evidence: `docs/BUILD_LOG.md` Steps 10-14.

## 1. The one rule everything follows

**The model advises; code decides.** The model reads evidence and answers in
a fixed JSON shape. It never picks a switch, a port, a priority, a cookie or a
REST call. Code builds every rule from the NSOT, the NSOT validator checks it,
a human (or AUTO with three-way agreement) approves it, and it goes through
the same controller REST path as Part A.

```
             +-----------------------------------------------------------+
 operator -> | AI layer (laptop, Python stdlib)                          |
 console  <- |  collector -> [detectors] -> llm_client -> answer check     |
             |       -> code plan (NSOT) -> NSOT validator -> approval    |
             +--------------------------|--------------------------------+
                                        | REST (one controller path)
                         Ryu :8080 (ofctl_rest + lab9 apps) -> OpenFlow 1.3 switches
```

| Part | File | Role |
|---|---|---|
| Collector | `collector.py` | REST-only snapshot: flows (+pps), port rates, port up/down, links, unauthorized rules, TCP sensor |
| Model door | `llm_client.py` | schema shown to the model, JSON + schema + caller checks, one repair try, retries 408/429/5xx, cost log, call cap, kill switch |
| NSOT reader | `nsot_view.py` | attachments, names, standby links, network description for prompts |
| Validator | `nsot_validator.py` | may this rule be installed / deleted? (Section 4) |
| Approval | `approvals.py` + controller `ai_approvals.py` | console Approve/Reject + terminal y/N, first answer wins, timeout = no |
| Feed | `events.py` + controller `ai_events.py` | every step to `logs/ai_events.jsonl` and the console's AI tab |

## 2. Schemas (what the model must return)

All schemas are in the code next to their caller and are shown to the model
in the system prompt. `additionalProperties: false` everywhere.

**B1 report** (`b1_analyst.SCHEMA`): `network_health` healthy | degraded |
critical; `findings[]` (max 10) of `category` (link_failure,
unauthorized_flow, drop_rule, traffic_flood, port_scan, switch_disconnected,
port_errors, other), `severity` (info | warning | critical), `device`,
`port` (int or null), `evidence`, `explanation`, `recommended_action`;
`summary`. Extra check: `device` must be an NSOT switch/host/router (or
`unknown` with category `other`), `port` must exist on that switch,
"healthy" cannot carry warning/critical findings.

**B2 translation** (`b2_intent.SCHEMA`): `status` ok | unclear | refuse;
`policies[]` (max 4) of `action` (block | allow | rate_limit), `src`, `dst`
(NSOT host or "any"), `protocol` (any | icmp | tcp | udp), `dst_port`,
`rate_pps`, `duration_s`; `question`; `reason`; `interpretation` (one sentence
for the human). Extra checks: names exist; ok needs policies, unclear needs a
question, refuse needs a reason; src = dst refused; any/any refused; port
needs tcp/udp; rate_limit needs rate_pps.

**B3 classification** (`b3_responder.SCHEMA`): `threat_type` (traffic_flood |
port_scan | unauthorized_flow | link_failure | none), `confidence` 0-1,
`severity`, `target`, `explanation`, `recommended_action` (must be in the
list allowed for that threat type in `b3_policy.json`), `evidence_used[]`.

## 3. Prompts (files in `part_b/prompts/`)

Every prompt contains `{network}`, filled by `nsot_view.describe_network()`
from the NSOT: no prompt hard-codes a device, port or address, so the same
prompts work on the physical lab once the NSOT is updated.

- **B1**: three candidates compared on identical snapshots (BUILD_LOG Step
  13). Chosen: `b1_v3_checklist.md` (network design + a six-item checklist:
  switches, links incl. the standby link, unauthorized/drop rules, traffic >
  100 pps, scans, errors; evidence must quote numbers; severity rules; "do not
  report normal things"). With reasoning off: 8/8 planted issues found, 0
  false alarms, 0 invalid, 12.9 s average.
- **B2** `b2_intent.md`: translate only; the list of hosts that exist; DNS,
  DHCP and management are protected and must be refused; never guess a host
  ("the printer" is not a host); ask one question when unclear.
- **B3** `b3_classify.md`: "second opinion" framing; the model gets the
  evidence but **not** the detector's guess; definitions of each threat incl.
  "one big legitimate TCP transfer is not a flood"; "prefer none when unsure:
  a wrong block cuts off a real user"; the allowed actions per threat.

Model settings: `deepseek-v4.1-flash` via opencode (all in `.env`),
temperature 0, reasoning off (B1 experiment: same accuracy as low, 2-3x
faster, about half the cost; default reasoning exhausted the token budget).

## 4. Validation (in code, never only in a prompt)

`nsot_validator.validate_rule()` for every install, in order:

1. Switch exists in the NSOT and is connected.
2. Cookie and priority are the AI's own: 0xB0 intent / 0xB1 response,
   priority 20-40 (below the protected rules at 50, above learned rules at 1).
3. Match: only allowed fields; ports exist; MACs/IPs are NSOT devices; never
   the management subnet or TCP 6633/8080/22; never DNS/DHCP UDP ports; never
   "match everything"; IP fields need eth_type, ports need ip_proto.
4. Action drop (or meter only where `/stats/meterfeatures` reports meters:
   none do here). Hard timeout required (responses <= 120 s, intents <= 3600 s).
5. **Protected-packet simulation**: example DNS and DHCP packets in both
   directions for every host, and management packets, are run through the
   rule with every in-port they could arrive on at that switch. Refused unless
   a higher-priority protected rule (DNS/DHCP intercept at 50) catches the
   packet first. This is what refuses "block all traffic to srv1" (it would
   drop the router's DNS/DHCP replies to srv1) while accepting "quarantine
   vm1" (its own DNS/DHCP requests are caught at 50 before the drop).
6. No duplicate or conflicting AI rule already on the switch.

`validate_delete()`: AI may delete its own rules (0xB0/0xB1), learned rules
(0x10, re-learned automatically) and rules with an unknown cookie
(unauthorized). Never table-miss, DNS, DHCP or sensor rules.

Tests: `tests/test_nsot_validator.py` 32/32, each refusal checked for the
right reason.

## 5. Where rules go (code, from the NSOT)

- B2 block: on the **source host's edge switch, at its port**, matching
  `in_port` + `eth_src` (MAC, not IP: a host's DHCP address can differ from
  the NSOT, see failure log #5) + `ipv4_dst` (+ protocol/port). Traffic is
  stopped where it enters the network. With src "any": the destination's edge
  switch. "allow" = delete the matching earlier block (there is no allow rule
  to install). Contradictions inside one request are refused by code.
- B3 response: drop the source at its edge port for 120 s (cookie 0xB1,
  priority 35); a scan may be blocked for TCP only; an unauthorized rule is
  deleted exactly (`delete_strict`); a link failure is a read-only failover
  check plus deletion of learned rules still pointing out of a dead port.
- Rate limits: no switch supports meters, so B2 refuses them and B3 falls
  back to the temporary block (documented in `b3_policy.json`).

## 6. Autonomy decisions

| Situation | Who decides | Why |
|---|---|---|
| B1 analysis | nobody: read-only report | no network change |
| B2 any intent | always a human (console Approve/Reject or terminal y/N; 120 s, no answer = no) | the operator asked for a change; they must see the exact rule first |
| B3 HITL mode | human (console or terminal, 60 s, no answer = no) | default mode |
| B3 AUTO mode | acts only when **code detector + model + validator all agree** | a single opinion is never enough; disagreement = logged, no action |
| B3 symmetric flood (two hosts at the same rate) | alert only, always | flow counters cannot tell attacker from victim (failure log #4) |
| Model error / invalid answer | no action | fail closed |
| Call cap reached, `part_b/STOP` exists, duration over | loop stops | no unbounded loops; max 3600 s per run |

Every AI rule is reversible: cookie-tagged, hard timeout, deletable by cookie
(`b2_intent.py --clear`). Every decision is logged
(`logs/b3_runs/*/responses.jsonl`, `logs/ai_events.jsonl`) and every model
call is in the cost log (`logs/api_calls.jsonl`, `cost_report.py`).

## 7. Detection (B3, code thresholds in `b3_policy.json`)

| Threat | Detector | Evidence given to the model |
|---|---|---|
| traffic_flood | a host's forwarded traffic at its edge switch >= 300 pps (learned + per-connection rules from its port; traffic already dropped by an AI rule is not counted, so a working block clears the incident) | edge port rx/tx pps, busiest rules, its TCP connections, "normal is a few pps" |
| port_scan | TCP sensor: >= 25 distinct ports or >= 6 hosts in 60 s, still active (last <= 20 s) | connection counts, distinct ports/hosts, example ports |
| unauthorized_flow | any rule whose cookie is not in the NSOT `flow_cookies` | the rule (switch, cookie, priority, match, actions, packets, age) and our apps' cookies |
| link_failure | an NSOT link reported down (port state) | the link, why, standby status, all links |

An incident is re-handled if still active after a response (max 3 attempts)
and cleared after 2 quiet cycles.
