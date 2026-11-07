# B5: production readiness: what would have to change before this ran on a real network

Short answer: the safety *structure* is production-shaped (code decides, the
model only advises, every change is validated against a source of truth,
reversible and logged), but almost every *component* is lab-grade. In order
of importance:

## 1. Data privacy

- **Today:** flow tables, host names, IP/MAC addresses and traffic rates are
  sent to a hosted model (opencode -> DeepSeek). The cost log stores no prompt
  text, but the provider sees every prompt.
- **Needed:** a data-processing agreement with the provider, or a
  self-hosted/private model (same OpenAI-compatible API: only
  `LAB9_LLM_BASE_URL`/`LAB9_LLM_MODEL` in `.env` change). Pseudonymise
  addresses before they leave the network (the evidence already uses NSOT
  names; replace them with stable tokens and map back locally). Keep raw
  evidence on-premises; retention limits on logs.

## 2. Hosted vs. private model

- Hosted: cheap (this lab: well under $1), no hardware, but outages, rate
  limits (we retry 429/5xx) and silent model changes. A provider update could
  change behaviour overnight: pin model versions and re-run the B1 experiment
  and B3 false-positive suite as a regression test before accepting a new one.
- Private: data stays inside, predictable versions, but needs GPUs and
  operations. The reasoning-token finding (93% of output tokens were hidden
  reasoning) matters here: a private deployment would size for that.
- Either way the network must keep working with **no** model: today a model
  failure means "no action" (fail closed), and Part A never depends on it.

## 3. Approval workflows

- **Today:** B2 always asks a human (y/N); B3 has HITL (y/N, 60 s timeout =
  no) and AUTO. AUTO acts only when a code detector, the model and the NSOT
  validator agree, only with cookie-tagged rules at priority 20-40 that
  remove themselves after 120 s.
- **Needed:** named approvers with authentication instead of a terminal
  prompt; change tickets (who approved what, why) linked to each rule's
  cookie; two-person approval for anything wider than one host; AUTO limited to
  a short allow-list of actions (temporary block of one source at its edge
  port) and rate-limited (max N automatic actions per hour, then HITL);
  a "freeze" switch for maintenance windows (today: the `part_b/STOP` file).

## 4. Failure modes we know about (from our own logs)

| Failure mode | What we saw | What production needs |
|---|---|---|
| Model invents fields / names | answers refused by schema + NSOT name check | keep strict validation; track refusal rate as a health metric |
| Reasoning model runs out of tokens | empty/cut-off answers (B1 run 1) | explicit reasoning budget, `finish_reason` monitoring |
| Victim blocked instead of attacker | symmetric ping flood: flow counters cannot tell who sends | packet-level telemetry (sFlow/IPFIX, ICMP type counters) before any automatic block; alert-only when attribution is ambiguous |
| Legitimate bulk traffic looks like a flood | large iperf transfer (FP runs) | per-service baselines, not one global pps threshold |
| Detector and model disagree | logged, no action | review queue for humans; use disagreements to tune thresholds |
| Controller REST unreachable | cycle error, loop continues, no action | HA controller pair; AI layer must never retry writes blindly |
| AI rule outlives its reason | every AI rule has a hard timeout | the same, plus reconciliation of rules against the ticket system |
| Stale NSOT (e.g. pc2's DHCP address differed from the NSOT) | flagged by the B1 model as an unknown device | NSOT synced from DHCP/IPAM, drift checks (we have `nsot_drift.py` for switch config only) |

## 5. Security of the control path

- Ryu's REST API on port 8080 has **no authentication** and our `/lab9/ai/events`
  accepts any POST. On a real network: TLS + auth on the northbound API,
  network ACLs so only the AI host and admins can reach it, OpenFlow over TLS
  to the switches.
- The management network is out-of-band and protected in the NSOT and in code
  (no AI rule may match its subnet or ports 6633/8080/22).

## 6. Scale

- The collector reads every switch every ~6 s over REST (32 calls for 6
  switches). For hundreds of switches: streaming telemetry instead of polling,
  and the model only on detector events (as B3 already does), never per cycle.
- Cost scales with incidents, not with time: B3 calls the model only when a
  detector fires (0 calls in a quiet 60 s run).
