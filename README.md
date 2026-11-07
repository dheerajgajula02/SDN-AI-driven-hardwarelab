# Lab 9 — AI-Driven SDN Hardware and Apps (Final Team Lab)

**Course:** CSCI 5280-001 Software-Defined Networking — Fall 2026
**Instructor:** Prof. Levi Perigo
**Team:** Group 3 — Dheeraj Gajula, Walker Narog, Sang Shim
**Points:** 100 (+9 bonus) · **Format:** team lab (3–4 students) · ~3 weeks
**Due:** Mon Nov 30, 2026, 11:59pm (available until Dec 1, 11:59am)
**Canvas:** https://canvas.colorado.edu/courses/142325/assignments/2797628

## Approach

No physical hardware yet. Build and test as much as possible on the two lab VMs
(`mininet-ofm` and `sdn-controllers`), keeping all hardware-specific details in one
place, so the same code can be pointed at the physical devices on lab day.

## Materials

| File | Description |
|---|---|
| `Lab9_AI_SDN_Hardware_and_Apps.docx` | Official Lab 9 guide downloaded from Canvas |
| `Lab9_Guide.md` | Plain-text copy of the guide for quick reference |

> The guide says physical connectivity, device assignments, addressing, and equipment details are *provided separately* — not included in the downloaded document. Need to get those from the instructor/TA.

## Progress dashboard

Open `dashboard.html` in a browser for the visual status: objectives, build
steps, built-vs-planned topology, A1 checklist, open items. Its status data
(top of the `<script>`) is updated at the end of every step.

## Current state

| Item | State |
|---|---|
| Controller | Ryu 4.34 (Python 3.5 venv) on `sdn-controllers` running `part_a/vlan_switch_13.py` + `ofctl_rest`, OpenFlow `6633`, REST `8080` |
| Mininet VM | No topology running (Step 1 test network runs and exits) |
| Build progress | Part A complete in the virtual lab (Steps 0–9, A1–A6; 102 automated checks pass). Steps 0–5: VLAN switching, NSOT apply + drift detection, router r1 (inter-VLAN, NAT, DHCP + IOS config), standby link + failover (0 pings lost), and out-of-band management network isolation. Next: Step 6 (Part A apps A3–A6). See `docs/BUILD_LOG.md` |
| Previous attempt | Archived at `../.archive/lab9_attempt1/` (outside this folder; passwords scrubbed) |

## Deliverables checklist

### Part A — Hardware and SDN Applications (60 pts)

- [ ] **A1 Network build (20)** — Internet via traditional router (DHCP + inter-VLAN routing), isolated management traffic, OVS + OpenFlow on bare-metal servers, OpenFlow on multivendor hybrid switches, controller on management network controlling every switch, survives redundant-link failure.
- [ ] **A2 NSOT-driven OpenFlow config (8)** — Read switch/controller/OpenFlow connection details from NSOT, configure every hardware switch, verify/display OpenFlow connectivity.
- [ ] **A3 DNS blacklist (10)** — Force DNS to controller; external JSON good/bad verdict lookup initiated by controller; demo good + bad site. *Bonus +3: modified DNS reply → "blocked" page.*
- [ ] **A4 DHCP (6)** — Force DHCP requests to Internet router; edge-switch requests must be unicast.
- [ ] **A5 SDN trace (8)** — Source/destination input (CLI or Flask GUI), print switch DPIDs along path. *Bonus +3: ingress/egress ports.*
- [ ] **A6 REST implementation (8)** — All applications exposed through the controller REST API.

### Part B — AI Operations Layer (40 pts)

- [ ] **B1 AI Network Analyst (8)** — Live state from all four hardware devices (flows, port stats/rates, drop rules, link status); LLM reports abnormalities; plant ≥3 issues including redundant-link failure; show found/missed/why.
- [ ] **B2 Intent Controller (9)** — Natural language → structured policy → hardware via controller after human confirmation; validate against NSOT; ≥4 intents incl. one vendor switch + one OVS server; several bad requests correctly refused.
- [ ] **B3 Closed-Loop Responder (10)** — Detect/classify/respond to scan, flood, unauthorized flow, link failure; human-in-the-loop + autonomous modes; actions on OVS and ≥1 vendor switch; false-positive tests; ≥5 min continuous run. *Bonus +3: automated link-failure response.*
- [ ] **B4 Advanced Technique (8)** — One technique beyond Labs 6–8 patterns; propose to instructor/TA early; document why, demo, evaluate vs baseline.
- [ ] **B5 Reliability, Safety, Cost (5)** — False-positive/failure log, API call + cost log, AI-use disclosure, production-readiness analysis.

### Objective 7 — Testing and Deliverables

- [ ] Team demo: designed scenarios + one surprise scenario from instructor/TA
- [ ] Individual interview: explain the AI layer's decisions
- [ ] Team submission: application code (A + B), lab document with hardware configs and app explanations, AI layer design (schemas, prompts, validation, autonomy decisions), B5 logs/analysis
- [ ] Individual submission: contribution statement + grade for each teammate

## Integration rules (from the guide)

- Protected flows (DNS, DHCP, management) must never be disrupted by the AI layer — define in NSOT and enforce in code.
- NSOT is the single source of truth for Objective 2 **and** the AI validator.
- AI actions go through the same controller path as Part A.
- Never trust model output — validate all LLM output in code before touching the network.

## Open questions for the TA

- Is the Cisco switch an OpenFlow switch or the non-OpenFlow management switch?
- What are the "four hardware devices" in B1?
- Which link is the "designated redundant link"?
- Where are the provided device assignments and addressing?
- Which OpenFlow version do the Arista and HP switches support?

## Layout

```
lab9/
├── Lab9_AI_SDN_Hardware_and_Apps.docx
├── Lab9_Guide.md
├── README.md
├── virtual/         # Mininet test networks (Python 3, run on mininet-ofm)
├── part_a/          # Part A: network build + controller apps
├── part_b/          # Part B: AI layer
├── docs/            # build log, design notes, physical-lab porting
└── logs/            # API cost log, false-positive log, evidence
```
