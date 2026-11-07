CSCI 5280 – Software-Defined Networking and AI-Driven Network Operations

Lab 9 – AI-Driven SDN Hardware and Apps (Final Team Lab)

University of Colorado Boulder

Department of Computer Science

Professor Levi Perigo, Ph.D.

Format: team lab (3–4 students) | Duration: approximately 3 weeks | Total: 100 points + bonus

### Lab Summary

The final lab brings together everything from the course: SDN theory, hardware, controller applications, and AI-driven operations. You will build a real multivendor SDN network on physical hardware, write SDN applications that manipulate traffic through the controller's northbound interface (NBI), and then add an AI operations layer that observes the live hardware, accepts natural-language intent, and detects and responds to problems.

The lab has two parts:

Part A – Hardware and SDN Applications (60 points): Build the network and the four base applications, working on physical equipment.

Part B – AI Operations Layer (40 points): Build an AI layer on top of Part A using the patterns from Labs 6–8, plus one advanced technique chosen by your team.

The AI layer is not a separate project. It runs against the same hardware, controller, and REST path as your Part A applications, and it must not break them.

Physical connectivity, device assignments, addressing, and equipment details are provided. This document describes what you must accomplish, not how to wire it.

Skills used in this lab:

Installing an SDN controller and configuring Open vSwitch on bare-metal servers

Configuring OpenFlow on multivendor hybrid switches

Routing, switching, VLAN, and network design; troubleshooting OpenFlow and the network

Programming SDN applications via REST API and OpenFlow

Using LLM APIs to analyze, translate, and decide

Validating AI output and engineering safe, trustworthy automation

You may use AI tools throughout this lab. You are responsible for every line your team submits, and each member will be asked to explain it individually.

## Part A – Hardware and SDN Applications (60 points)

### Objective 1 – Network Build (20 points)

Build and configure the network so that it meets the following outcomes:

The network has Internet access through the traditional router, which also serves the DHCP needs of your design and any inter-VLAN routing you require.

Your team's management traffic is isolated so that multiple teams can share the same physical infrastructure if needed.

The bare-metal servers run Open vSwitch with OpenFlow enabled on the appropriate ports, and reach the controller over the out-of-band network.

The vendor hybrid switches run OpenFlow on the appropriate ports per vendor documentation, with a separate non-OpenFlow management network.

An SDN controller of your choice is installed on the management network, has Internet connectivity, and controls every OpenFlow switch.

The network continues to operate when the designated redundant link fails.

Document your design decisions, addressing, and configurations in your lab document.

### Objective 2 – NSOT-Driven Automated OpenFlow Configuration (8 points)

Write an application that reads connection details (switch IP, controller IP, OpenFlow port, version, transport protocol, etc.) from an NSOT file and configures every hardware switch accordingly.

The application must verify and display that each switch has established OpenFlow connectivity with the controller.

Your NSOT file is used again in Part B. Design it to describe more than connection details (see Integration Rules).

### Objective 3 – DNS Blacklist Application (10 points)

Force DNS traffic from any device to the controller. Based on the requested domain, traffic to bad sites must be blocked and traffic to good sites must be allowed.

The good/bad decision must come from an external check: your team must find or build a way to send a URL to a site that returns a JSON verdict (good or bad), work out how to query it from the controller, and justify your choice. The lookup must be initiated from the controller, not from the end hosts.

Determine how you will test both outcomes, and demonstrate a good site and a bad site.

Bonus (+3): For a blocked domain, return a modified DNS reply so the browser displays a "blocked" page.

### Objective 4 – DHCP Application (6 points)

Force DHCP requests from hosts to the Internet router (DHCP server). Requests entering the network at the edge switches must be unicast.

### Objective 5 – SDN Trace Application (8 points)

Accept a source and destination from the user (CLI or Flask GUI) and trace the path through the OpenFlow network, printing the DPIDs of the switches along the path.

Bonus (+3): Display ingress and egress ports along the path.

### Objective 6 – REST Implementation (8 points)

Implement all the applications above through the controller's REST API.

## Part B – AI Operations Layer (40 points)

### Ground rules for Part B

Use the LLM API-first approach. No model training is required or expected.

Use economy-tier models during development (see API Budget below).

The AI layer observes and acts through the same controller and REST path as the Part A applications.

You decide how much the AI is allowed to do on its own. Be ready to defend that decision.

### Objective B1 – AI Network Analyst (8 points)

Builds on Lab 6.

Collect live state from all four hardware devices: flow tables, port statistics/rates, drop rules, and link status.

Prepare that data for an LLM and have it report anything abnormal, with an explanation a network engineer could act on.

Plant at least three issues of your own design, including the redundant-link failure. Do not tell the model what the issues are.

Show what the model found, what it missed, and why you think that happened.

### Objective B2 – Intent Controller (9 points)

Builds on Lab 7.

Accept a natural-language policy, translate it into a structured policy, and apply it to the hardware through the controller after human confirmation.

Validate every policy against your NSOT before it is applied: reject unknown hosts or devices, conflicts with existing policy, and any request that would disrupt a protected flow.

Demonstrate at least four intents, including one that lands on a vendor switch and one on an Open vSwitch server, plus several bad requests (ambiguous, impossible, contradictory) that your system correctly refuses or questions.

### Objective B3 – Closed-Loop Responder (10 points)

Builds on Lab 8.

Detect, classify, and respond to threats on the hardware network: at least a scan, a flood, an unauthorized flow, and the link failure. Detection of the link failure is required; an automated response to it earns bonus credit.

Support both a human-in-the-loop mode and an autonomous mode.

Actions must be demonstrated on both Open vSwitch servers and at least one vendor switch. If a vendor switch cannot support an action (for example, meters), document the limit and your fallback.

Test for false positives with repeated normal-traffic runs.

Run the loop continuously for at least five minutes while threats are introduced.

### Objective B4 – Advanced Technique (8 points)

Choose one technique beyond the Labs 6–8 patterns. Propose it to the instructor or a TA early in the project, before building it.

Document why you chose it, demonstrate it working in the network, and evaluate whether it improved results compared with your baseline.

Examples (not a required list): retrieval over vendor documentation or your NSOT; tool calling or a simple agent that can invoke your trace application; a second model that checks the first model's output; comparing a hosted model with a self-hosted model; AI-generated explanations of traced paths.

### Objective B5 – Reliability, Safety, and Cost (5 points)

A false-positive and failure log showing where your AI layer was wrong and what you did about it.

An API call and cost log for the team.

An AI-use disclosure describing how your team used AI tools to build the lab.

A short production-readiness analysis: what would have to change before this ran on a real network (data privacy, hosted vs. private models, approval workflows, failure modes)?

### Integration Rules

Protected flows. The DNS, DHCP, and management flows must never be disrupted by the AI layer. Define them in your NSOT and enforce them in code, not just in the prompt.

One source of truth. The NSOT drives Objective 2 and also serves as the AI validator's reference for what exists and what may be changed.

One controller path. AI actions go through the same controller as Part A.

Never trust model output. Validate all LLM output in code before anything touches the network.

### Objective 7 – Final Testing and Deliverables

Demonstration (team): Demonstrate the hardware network, the four Part A applications, and the AI layer to the TAs and professor. The demo includes:

Scenarios your team designed

One surprise scenario injected by the instructor or a TA

Individual interview: Each student answers questions individually, including questions on how the AI layer reached its decisions.

Team submission:

Application code (Part A and Part B)

Lab document: hardware configurations and explanation of each application

AI layer design: schemas, prompts, validation logic, and autonomy decisions

B5 logs and analysis

Individual submission: What each person (including yourself) contributed, and a grade for each team member (including yourself).

### Hardware and Topology

Each team must select the following equipment for the SDN Final Lab:

2 Arista switches

1 HP switch

1 Cisco router

1 Controller server

2 Open vSwitch (OVS) servers

1 Cisco switch

All available equipment has been labeled in blue tags "SDN FINAL" Please select only devices with this label.

Each team must use servers from at least two different vendors. You may not select all three servers from Dell. At least one server must be from a different vendor.

Some servers may not have Ubuntu installed. Teams are responsible for installing Ubuntu and Open vSwitch as needed.

### API Budget

Use economy-tier models for development and testing. Typical team usage across the lab is roughly 1,000–1,500 calls, which costs a few dollars or less on economy models.

Never leave a monitoring loop running unattended. Include a maximum-iteration limit or a clear stop condition in every loop.

Reasoning-class models can cost many times more per call; avoid them unless your advanced technique requires one.

Keep your API key out of your code repository.

### Grading Summary

| Part | Objective | Points |
|---|---|---|
| A | 1. Network build | 20 |
| A | 2. NSOT-driven OpenFlow configuration | 8 |
| A | 3. DNS blacklist | 10 |
| A | 4. DHCP | 6 |
| A | 5. SDN trace | 8 |
| A | 6. REST implementation | 8 |
| B | B1. AI Network Analyst | 8 |
| B | B2. Intent Controller | 9 |
| B | B3. Closed-Loop Responder | 10 |
| B | B4. Advanced Technique | 8 |
| B | B5. Reliability, Safety, and Cost | 5 |
|  | Total | 100 |

Bonus: DNS modified reply (+3), trace ingress/egress ports (+3), automated response to link failure (+3).
