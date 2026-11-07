# B5: AI-use disclosure (how the team used AI tools to build Lab 9)

Group 3: Dheeraj Gajula, Walker Narog, Sang Shim. *Each member should add or
correct their own part before submission.*

## Two different kinds of AI in this lab

| | What | Where it runs | Who controls it |
|---|---|---|---|
| **AI inside the product** | the Part B AI layer: B1 analyst, B2 intent controller, B3 responder | `lab9/part_b/`, calls `deepseek-v4.1-flash` through opencode's OpenAI-compatible API | our code: every answer is checked by schema + NSOT validator before anything touches the network |
| **AI used to build it** | a coding assistant (Claude, in the OpenCode terminal app) | the team's laptop, with SSH access to the two lab VMs | a team member, step by step |

This document is about the second kind.

## How the coding assistant was used

- **Writing code, step by step, reviewed by us.** Part A apps (VLAN switch,
  NSOT apply/drift, DNS blacklist, DHCP unicast, trace, console) and Part B
  (collector, LLM client, validator, B1-B3) were written one function at a
  time with numbered "Step N" comments, explained to the team member at each
  step, and deployed only after that.
- **Testing on the real virtual lab.** The assistant ran the tests over SSH on
  the Mininet and controller VMs, read the results, and fixed problems. Tests
  were required to check real traffic (counters, captures, pings) with a
  control, not only the UI.
- **Debugging.** Several real bugs were found this way (see
  `docs/BUILD_LOG.md`): learned rules without the source MAC flooding traffic
  through the controller; missing `Content-Type` on our REST answers; the
  model not being shown its schema; a reasoning model running out of tokens;
  the flood detector naming the *victim* of a symmetric ping flood.
- **Documentation.** Drafts of the build log, dashboard and these B5 documents,
  edited by the team.
- **Research.** Comparing Part B with our Labs 6-8 (a sub-agent read our own
  earlier code) and vendor/OpenFlow details.

## Rules we kept

- No passwords or API keys in code, documents or logs. Keys only in a
  git-ignored `.env`; tests read passwords from environment variables. A
  check before every commit looks for the key in all files.
- Every change was tested on the lab VMs before being called done; tests that
  could pass by accident were rewritten with controls.
- Every member must be able to explain every line (guide requirement); the
  code comments and `docs/BUILD_LOG.md` are written for that.

## Where the AI tool was wrong (and how we caught it)

Listed with evidence in `docs/B5_FAILURE_LOG.md` and `docs/BUILD_LOG.md`.
Examples: a first version of the LLM client that never showed the model its
schema (caught by the validator on the first live call), a token budget too
small for a reasoning model (caught by the B1 experiment), and a flood
detector that could block the victim (caught by an offline test on a real
snapshot before any live run).
