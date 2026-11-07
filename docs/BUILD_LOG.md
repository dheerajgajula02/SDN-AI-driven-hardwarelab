# Lab 9 Build Log (virtual first, physical later)

Every step records: goal, files, exact commands, expected vs observed result,
evidence, and what changes on the physical lab.

## Environment

| Item | Value |
|---|---|
| Mininet VM | `mininet-ofm`, SSH via Tailscale `100.73.87.23`, LAN `10.224.76.126`. Ubuntu 14.04 (32-bit), **Mininet 2.3.0 on Python 3.4** (see Step 2.1), OVS 2.0.2 |
| Controller VM | `sdn-controllers`, SSH via Tailscale `100.110.3.67`, LAN `10.224.78.132`. Ubuntu 16.04, Python 3.5 |
| Controller | Ryu 4.34 in venv `/home/sdn/ryu-py3`; OpenFlow `6633`, REST `8080` |
| Rule | VM-to-VM traffic (OpenFlow, REST) uses the **LAN** IPs. Tailscale is only for SSH. |

Credentials are not stored in this repo.

---

## Step 0: Controller (Ryu 4.34 on Python 3)

Done before the rebuild; kept as-is.

```bash
# on sdn-controllers
python3 -m venv /home/sdn/ryu-py3
P=/home/sdn/ryu-py3/bin/pip
$P install --upgrade "pip==20.3.4" "setuptools==44.1.1" "wheel==0.37.1"
$P install "packaging==20.9" "pbr==5.6.0"
$P install --no-build-isolation "ryu==4.34"
$P install "eventlet==0.25.2"
sudo ln -sf /home/sdn/ryu-py3/bin/ryu-manager /usr/local/bin/ryu-manager3
```

Why the pins: Python 3.5 is too old for newer pip/packaging/pbr, and Ryu 4.34
needs `eventlet.wsgi.ALREADY_HANDLED`, which newer eventlet removed.

Check: `ryu-manager3 --version` → `ryu-manager 4.34`.

**Physical lab:** same commands on the controller server.

---

## Step 1: Controller-owned VLAN switching, 2 switches + 1 trunk

### Goal

Prove the controller can do VLAN switching with OpenFlow flows on its own
(no VLAN config on the switches), on the old OVS 2.0.2:

- untagged frames from hosts are put in the access port's VLAN
- frames crossing the trunk carry an 802.1Q tag
- frames delivered to hosts are untagged
- different VLANs cannot reach each other

### Files

| File | Runs on | Purpose |
|---|---|---|
| `part_a/vlan_switch_13.py` | controller | the Ryu app (VLAN-aware learning switch) |
| `part_a/start_ryu.sh` | controller | starts Ryu with the app + `ofctl_rest` |
| `part_a/tests/test_vlan_switch.py` | controller | offline test, no network needed |
| `virtual/step1_two_switch.py` | Mininet VM | test network + automatic checks |

### Test network

```
h1 (VLAN 10) - port 1 -+                       +- port 1 - h3 (VLAN 10)
                       s1 - port 3 ==trunk== port 3 - s2
h2 (VLAN 20) - port 2 -+                       +- port 2 - h4 (VLAN 20)
```

- DPIDs: s1 = 1, s2 = 2. These match the `PORTS` keys in the app.
- All hosts are in **one subnet**, `10.0.0.0/24`, so the only thing that can
  block h1 → h2 is VLAN separation, not routing.
- The OVS switches get **no** `tag`/`trunks` settings.

### Commands

```bash
# 1. laptop -> controller: copy the app
scp part_a/vlan_switch_13.py part_a/start_ryu.sh sdn@<controller>:/home/sdn/lab9/part_a/
scp part_a/tests/test_vlan_switch.py sdn@<controller>:/home/sdn/lab9/part_a/tests/

# 2. controller: offline test (expect exit 0, 3 "dropped" cases)
cd /home/sdn/lab9
/home/sdn/ryu-py3/bin/python3 part_a/tests/test_vlan_switch.py

# 3. controller: stop any old Ryu, start the app
kill $(cat ryu.pid)
chmod +x part_a/start_ryu.sh          # scp may drop the execute bit
setsid nohup part_a/start_ryu.sh > ryu.log 2>&1 < /dev/null &
echo $! > ryu.pid
ss -lnt | grep -E ':6633|:8080'       # both LISTEN

# 4. laptop -> Mininet VM: copy the test network
scp virtual/step1_two_switch.py mininet@<mininet>:/home/mininet/lab9/

# 5. Mininet VM: run the checks
cd /home/mininet/lab9
sudo mn -c
sudo python3 step1_two_switch.py --no-cli > evidence/step1_mininet_run.txt 2>&1
# (without --no-cli it opens the Mininet CLI after the checks)
```

### Expected vs observed

| Check | Expected | Observed |
|---|---|---|
| Offline test | 4 forward cases correct, 3 drops | as expected |
| Switches connect | s1, s2 connected | `connected=True` both; Ryu log `switch 1/2 connected, table-miss rule installed` |
| `pingall` | only h1↔h3 and h2↔h4 succeed | `h1 -> X h3 X`, `h2 -> X X h4` … **66% dropped (4/12 received)** |
| Trunk `s1-eth3` | frames tagged | `ethertype 802.1Q (0x8100) … vlan 10` on every frame |
| Access `s1-eth1` | frames untagged | `ethertype IPv4 (0x0800)` / `ARP (0x0806)`, no tag |
| VLAN isolation on the wire | VLAN 20 broadcast never reaches h1 | h4's `vlan 20` ARP seen on the trunk, **not** on `s1-eth1` |
| Flows | push on access→trunk, pop on trunk→access | see below |
| Ryu errors | none | 0 errors/tracebacks |

Flows on s1 (from `ovs-ofctl -O OpenFlow13 dump-flows s1`):

```
priority=1,in_port=1,vlan_tci=0x0000/0x1fff,dl_dst=00:00:00:00:00:03 actions=push_vlan:0x8100,set_field:10->vlan_vid,output:3
priority=1,in_port=3,dl_vlan=10,dl_dst=00:00:00:00:00:01            actions=strip_vlan,output:1
priority=1,in_port=2,vlan_tci=0x0000/0x1fff,dl_dst=00:00:00:00:00:04 actions=push_vlan:0x8100,set_field:20->vlan_vid,output:3
priority=1,in_port=3,dl_vlan=20,dl_dst=00:00:00:00:00:02            actions=strip_vlan,output:2
priority=0                                                           actions=CONTROLLER:65535
```

How OVS prints our actions:

| App sends | OVS shows |
|---|---|
| match `vlan_vid=OFPVID_NONE` (untagged) | `vlan_tci=0x0000/0x1fff` |
| match `vlan_vid=0x1000 \| 10` | `dl_vlan=10` |
| `SetField(vlan_vid=4106)` | `set_field:10->vlan_vid` (OVS hides the 0x1000 bit) |
| `PopVlan` | `strip_vlan` |

### Problems hit

1. **Launcher not executable after `scp`** → `Permission denied`. Fix: `chmod +x part_a/start_ryu.sh`.
2. **Trunk capture empty on first run.** tcpdump buffered its output, and the `vlan`
   filter can miss tags the kernel keeps as metadata. Fix: `tcpdump -U` with no
   filter, and wait for it to finish before reading the file.

### Evidence

`logs/step1/`:
- `step1_offline_test.txt`: offline test output
- `step1_mininet_run.txt`: connection check, pingall, trunk/access captures, flow tables
- `step1_ryu.log`: controller log (connections + every installed flow)

### Physical lab equivalent

**OVS servers.** Same as Mininet does for us, by hand:

```bash
sudo ovs-vsctl add-br br0
sudo ovs-vsctl set bridge br0 protocols=OpenFlow13
sudo ovs-vsctl set bridge br0 other-config:datapath-id=<16 hex digits, = NSOT dpid>
sudo ovs-vsctl set-fail-mode br0 secure        # no controller -> no forwarding (no rogue NORMAL)
sudo ovs-vsctl add-port br0 <data-port>        # one per data-plane NIC, NO tag/trunks
sudo ovs-vsctl set-controller br0 tcp:<controller-mgmt-ip>:6633
sudo ovs-ofctl -O OpenFlow13 show br0          # note the OpenFlow port numbers
sudo ovs-ofctl -O OpenFlow13 dump-flows br0
```

- The management NIC stays **outside** `br0`.
- The port numbers from `ovs-ofctl show` and the DPID go into `PORTS`
  (later the NSOT). Nothing else in the app changes.

**Vendor switches (Arista, HP, Cisco).** Not decided yet. Depends on whether they
support OpenFlow 1.3 `push_vlan`/`pop_vlan` (controller mode) or must keep
their own `switchport` VLANs (switch mode). This becomes a per-device NSOT
setting.

**Controller.** Same `start_ryu.sh`. The controller must be reachable from every
switch's management IP on TCP 6633.

**Note (after Step 2):** `PORTS` now comes from the NSOT. To rerun Step 1, the
controller needs `LAB9_NSOT=part_a/tests/nsot_step1.json`.

---

## Step 2: NSOT + A2 apply app, full 6-switch topology

### Goal

- Move the port map out of the code into one NSOT file (`part_a/nsot.json`).
- Build the full topology from that file.
- Start every switch **bare**, then let `part_a/nsot_apply.py` (A2) configure
  each one over SSH from the NSOT, and verify it from both sides.

### Files

| File | Runs on | Purpose |
|---|---|---|
| `part_a/nsot.json` | both VMs | the NSOT: controller, VLANs, switches (dpid, mgmt, openflow, ports), hosts |
| `part_a/vlan_switch_13.py` | controller | now loads `PORTS` from the NSOT (`load_ports`), refuses a broken NSOT |
| `part_a/nsot_apply.py` | controller | **A2**: apply OpenFlow settings to every switch, then verify |
| `part_a/tests/nsot_step1.json` | controller | Step 1 network as an NSOT, for the offline test |
| `part_a/tests/test_nsot_loader.py` | controller | loader accepts the real NSOT, refuses 6 kinds of broken NSOT |
| `virtual/step2_full_topology.py` | Mininet VM | cabling only from the NSOT, reset switches to bare, wait, run checks |

### Topology

```
                         cisco1 (dpid 1)
                   port 2 /   | port 3   \ port 4
          arista1 (11) ──┘    └── arista2 (12)   hp1 (21)
          p2: pc1 (V10)           p2: pc2 (V10)  p2: srv1 (V20)
          p3: ovs1 (31)           p3: ovs2 (32)
              p2: app1 (V20)          p2: app2 (V20)
```

6 switches, 5 links: a tree, no loops. cisco1 port 1 is reserved for the
router (Step 3). The redundant link comes in Step 4.

### What `nsot_apply.py` does per switch

1. Checks the NSOT values are applicable (known driver, OpenFlow 1.0/1.3, `tcp`).
2. SSHes to `mgmt.ip` as `mgmt.user` with `mgmt.ssh_key` and runs, as **one**
   `ovs-vsctl` transaction:
   ```
   set bridge B protocols=OpenFlow13 other-config:datapath-id=<dpid as 16 hex>
   -- set-fail-mode B secure
   -- set-controller B tcp:<controller ip>:<openflow port>
   ```
3. Verifies:
   - **device side:** reads back protocols, DPID, fail mode and controller target
   - **controller side:** the DPID appears in Ryu's REST `/stats/switches`
     (waits up to 30 s)
4. Exits 0 only if every switch matches the NSOT and is connected.

Modes: `--dry-run` (print commands only), `--verify` (no changes).

### One-time access setup (controller → Mininet VM)

```bash
# controller: a dedicated key for the apply app, and trust the Mininet VM's host key
ssh-keygen -q -t ed25519 -N "" -C "lab9-nsot-apply@sdn-controllers" -f ~/.ssh/lab9_nsot
ssh-keyscan -t ed25519,ecdsa,rsa 10.224.76.126 >> ~/.ssh/known_hosts

# Mininet VM: accept that key, and allow ONLY ovs-vsctl without a password
cat lab9_nsot.pub >> ~/.ssh/authorized_keys
echo 'mininet ALL=(root) NOPASSWD: /usr/bin/ovs-vsctl' > /tmp/lab9-ovs
sudo visudo -cf /tmp/lab9-ovs && sudo install -m 0440 -o root -g root /tmp/lab9-ovs /etc/sudoers.d/lab9-ovs

# check (from the controller): ovs-vsctl works, ovs-ofctl is refused
ssh -i ~/.ssh/lab9_nsot mininet@10.224.76.126 'sudo -n ovs-vsctl --version; sudo -n ovs-ofctl --version'
```

### Commands

```bash
# laptop -> controller
scp part_a/vlan_switch_13.py part_a/nsot.json part_a/nsot_apply.py sdn@<controller>:/home/sdn/lab9/part_a/
scp part_a/tests/* sdn@<controller>:/home/sdn/lab9/part_a/tests/

# controller: offline tests, restart Ryu, dry run
cd /home/sdn/lab9
/home/sdn/ryu-py3/bin/python3 part_a/tests/test_vlan_switch.py
/home/sdn/ryu-py3/bin/python3 part_a/tests/test_nsot_loader.py
kill $(cat ryu.pid); setsid nohup part_a/start_ryu.sh > ryu.log 2>&1 < /dev/null & echo $! > ryu.pid
grep loaded ryu.log                       # "loaded 6 switches from .../nsot.json"
python3 part_a/nsot_apply.py --dry-run

# laptop -> Mininet VM
scp virtual/step2_full_topology.py part_a/nsot.json mininet@<mininet>:/home/mininet/lab9/

# Mininet VM: bare topology, waits for the apply
sudo mn -c
sudo tmux new -d -s lab9 "cd /home/mininet/lab9 && python3 step2_full_topology.py --no-cli 2>&1 | tee evidence/step2_mininet_run.txt"

# controller: before, apply, (the Mininet script then runs its checks)
python3 part_a/nsot_apply.py --verify     # expect exit 1, every switch WRONG
python3 part_a/nsot_apply.py              # expect exit 0, every switch OK
```

### Expected vs observed

| Check | Expected | Observed |
|---|---|---|
| Offline VLAN test (Step 1 NSOT) | same as Step 1 | same (only dict print order differs) |
| Loader, real NSOT | 6 switches loaded | `loaded 6 switches` |
| Loader, 6 broken NSOTs | all refused | all refused, each with the exact problem named |
| Ryu start | loads the NSOT | `loaded 6 switches from /home/sdn/lab9/part_a/nsot.json` |
| Bare switches | nothing set | protocols `[]`, no datapath-id, fail_mode `[]`, no controller |
| `--verify` before apply | all wrong, exit 1 | 6 × `WRONG: controller, dpid, fail_mode, protocols`, exit 1 |
| Apply | 6 applied, exit 0 | 6 × `applied`, 6 × `OK`, exit 0 |
| Controller REST | DPIDs 1, 11, 12, 21, 31, 32 | `[32, 1, 21, 11, 12, 31]` |
| Flows right after connect | table-miss only | 6 × `priority=0 actions=CONTROLLER:65535` |
| `pingall` | only same-VLAN pairs: 8/20 | **60% dropped (8/20 received)**: app1/app2/srv1 reach each other, pc1↔pc2 |
| app1 → app2 (5 switches) | works | 2/2 replies |
| Shutdown | clean | `*** Done`, no bridges left |
| Ryu errors | none | 0 |

Verify output after apply:

```
switch   dpid  protocols    fail_mode  controller                 ctl sees   result
cisco1   1     OpenFlow13   secure     tcp:10.224.78.132:6633     yes        OK
arista1  11    OpenFlow13   secure     tcp:10.224.78.132:6633     yes        OK
arista2  12    OpenFlow13   secure     tcp:10.224.78.132:6633     yes        OK
hp1      21    OpenFlow13   secure     tcp:10.224.78.132:6633     yes        OK
ovs1     31    OpenFlow13   secure     tcp:10.224.78.132:6633     yes        OK
ovs2     32    OpenFlow13   secure     tcp:10.224.78.132:6633     yes        OK
```

### Problems hit

1. **Controller couldn't SSH to the Mininet VM** (no key; `ovs-vsctl` needs sudo
   with a password). Fixed with the one-time access setup above.
2. **Read-back failed on a bare switch**: `get ... other-config:datapath-id`
   errors when the key is missing. Fixed by reading the whole `other-config` map.
3. **Mininet caches the controller record**, which goes stale if the apply
   replaces it. The Mininet script re-reads it on every check.
4. **Shutdown traceback** (`OSError: No such file or directory`). Python 2's
   `json` returns unicode names; Mininet only splits plain `str` commands, so it
   tried to run the whole `ovs-vsctl …` line as one program. First fixed by
   converting the NSOT to `str`; the problem disappeared for good with the move
   to Python 3 (Step 2.1), where all text is `str`.


### Not done yet (from the Step 2 plan)

- 2a: firewall on REST port 8080.
- Broadcast-leak check, tags on a middle trunk, and flows via REST from the
  Mininet VM.
- ~~Drift detection~~: done in Step 2.2.

### Evidence

`logs/step2/`: `step2_offline_test.txt`, `step2_loader_test.txt`,
`step2_apply_before.txt`, `step2_apply.txt`, `step2_mininet_run.txt`, `step2_ryu.log`.

### Physical lab equivalent

- Put the real values in the NSOT: each switch's real DPID, management IP,
  login user, SSH key path, OpenFlow version, and its OpenFlow port numbers.
- **OVS servers:** the `ovs` driver works as-is (one bridge per server, the
  `bridge` field = its name). The automation account needs the same limited
  sudo rule.
- **Arista / HP / Cisco:** need their own drivers next to `ovs` in `DRIVERS`
  (`apply` = vendor CLI or API commands, `read_back` = parse `show openflow`).
  Until then the script reports them as `SKIPPED: no driver` and does not
  touch them.
- The controller must reach every management IP on SSH (22) and every switch
  must reach the controller on 6633.

---

## Step 2.1: Mininet on Python 3 (no more Python 2)

### Goal

Run every script on Python 3. The VM's Mininet 2.2.2 only supports Python 2;
Mininet 2.3.0 supports Python 3. Install it next to the old one, without
removing anything.

### Checks before installing

| Check | Result |
|---|---|
| OS / Python | Ubuntu 14.04, i686, Python 3.4.3, pip 1.5.4, setuptools 3.3 |
| Mininet for Python 3 before | none (`import mininet.net` fails) |
| Mininet 2.3.0 code on Python 3.4 | `python3 -m compileall mininet` → no errors |
| `mnexec` options used by 2.3.0 | same set as the installed 2.2.2 (`-cdnpa:g:r:vh`) |

### Commands (on `mininet-ofm`)

```bash
cd ~
git clone --depth 1 --branch 2.3.0 https://github.com/mininet/mininet mininet-2.3.0
cd mininet-2.3.0

# backups of the Python 2 pieces that get replaced
sudo cp -n /usr/bin/mnexec /usr/bin/mnexec-2.2.2
sudo cp -n /usr/local/bin/mn /usr/local/bin/mn-py2

# mnexec (C helper). Set VERSION explicitly: the Makefile captures it from
# "mn --version", which prints to stderr, so it ends up empty.
cc -Wall -Wextra -DVERSION=\"2.3.0\" mnexec.c -o mnexec
sudo install -m 755 mnexec /usr/bin/mnexec

# Mininet Python package for Python 3
sudo python3 setup.py -q install
```

### Verification (run from a neutral folder, e.g. `/tmp`, not the source folder)

```bash
cd /tmp
mnexec -v                    # 2.3.0
head -1 /usr/local/bin/mn    # #!/usr/bin/python3
python3 -c "from mininet.net import VERSION; print(VERSION)"   # 2.3.0
python2 -c "from mininet.net import VERSION; print(VERSION)"   # 2.2.2 (untouched)
sudo mn --switch ovs,failMode=standalone --controller none --test pingall
```

Observed: all as above; smoke test `0% dropped (2/2 received)`.

Then both lab scripts were rerun on Python 3 with the same results as before:

| Script | Result on Python 3 |
|---|---|
| `step1_two_switch.py` (controller on `tests/nsot_step1.json`) | 2 connected, 4/12 received, trunk frames `vlan 10`, push/pop flows |
| `step2_full_topology.py` + `nsot_apply.py` | verify-before 6 × WRONG, apply 6 × OK, 8/20 received, clean shutdown |

### Rollback (if ever needed)

```bash
sudo cp /usr/bin/mnexec-2.2.2 /usr/bin/mnexec
sudo cp /usr/local/bin/mn-py2 /usr/local/bin/mn
# Python 3 package: remove /usr/local/lib/python3.4/dist-packages/mininet-2.3.0-py3.4.egg
```

### Evidence

`logs/step1/step1_mininet_run_py3.txt`, `logs/step2/step2_mininet_run.txt` (Python 3 run).

### Physical lab equivalent

None. Mininet is only the virtual stand-in for the cabling. On lab day the
lab code (controller app, `nsot_apply.py`, later apps) is all Python 3 already.

---

## Step 2.2: A2 drift detection (`nsot_drift.py`)

### Goal

Find every place where a switch no longer matches the NSOT, say exactly what
differs, and optionally repair it by re-applying the NSOT.

### Files

| File | Change |
|---|---|
| `part_a/nsot_apply.py` | new `expected_settings()` (shared by verify and drift); `ovs` driver gets `read_ports` |
| `part_a/nsot_drift.py` | new: drift report, `--fix` |

### What it checks

| Check | How | Auto-fix with `--fix`? |
|---|---|---|
| protocols, dpid, fail_mode, controller | driver `read_back` vs `expected_settings` | yes (re-apply that switch) |
| ports | driver `read_ports` (`ovs-vsctl list-ifaces` + `ofport`) vs NSOT port numbers | **no**, report only: adding/removing ports can cut a link |
| connection | DPID in Ryu REST `/stats/switches` | yes, if the settings drifted |
| unknown switches | DPIDs at the controller that are not in the NSOT | no |

Exit code: 0 = no drift, 1 = drift remains.

### Test

```bash
# Mininet VM: Step 2 network, kept running (CLI)
sudo tmux new -d -s lab9 "cd /home/mininet/lab9 && python3 step2_full_topology.py 2>&1 | tee evidence/step2_2_mininet_run.txt"

# controller
cd /home/sdn/lab9/part_a
python3 nsot_apply.py
python3 nsot_drift.py                       # 1. clean

# Mininet VM: plant drift by hand
sudo ovs-vsctl set-fail-mode hp1 standalone
sudo ovs-vsctl set bridge ovs2 protocols=OpenFlow10
sudo ovs-vsctl set-controller arista2 tcp:10.224.78.132:6653
sudo ovs-vsctl add-port ovs1 rogue0 -- set interface rogue0 type=internal

# controller
python3 nsot_drift.py                       # 2. report
python3 nsot_drift.py --fix                 # 3. fix settings, port stays reported

# Mininet VM: operator removes the extra port
sudo ovs-vsctl del-port ovs1 rogue0

# controller
python3 nsot_drift.py                       # 4. clean again
# Mininet CLI: pingall                      # 5. still 8/20
```

### Observed

1. Clean network: `no drift`, exit 0.
2. After planting:
   ```
   switch     what           fix?  detail
   arista2    controller     yes   expected tcp:10.224.78.132:6633, found tcp:10.224.78.132:6653
   arista2    connection     yes   controller does not see dpid 12
   hp1        fail_mode      yes   expected secure, found standalone
   ovs1       port 3         no    on device (rogue0) but not in NSOT
   ovs2       protocols      yes   expected OpenFlow13, found OpenFlow10
   ovs2       connection     yes   controller does not see dpid 32
   ```
   All 4 planted changes found, plus the 2 side effects (arista2 and ovs2 lost
   their controller session; the app only speaks OpenFlow 1.3).
3. `--fix`: re-applied arista2, hp1, ovs2 → afterwards only
   `ovs1 port 3 … rogue0` remains, exit 1.
4. After removing `rogue0`: `no drift`, exit 0; `nsot_apply.py --verify` 6 × OK.
5. `pingall`: 60% dropped (8/20 received), same as before the drift.

Guards (dry run on a modified copy of the NSOT): `hp1 SKIPPED: no driver for
'hp_aos'`, `ovs2 SKIPPED: transport 'ssl' not supported yet`, `arista1 SKIPPED:
unsupported OpenFlow version '1.5'`; the other switches continue normally.

### Evidence

`logs/step2/step2_2_*`: `apply`, `drift_0_clean`, `drift_1_planted`,
`drift_2_fix`, `drift_3_final`, `guards`, `mininet_run`.

### Physical lab equivalent

- Same commands. Run `nsot_drift.py` after any manual change and before the demo.
- Vendor drivers need `read_ports` too (e.g. parse `show openflow` port list).
- Port drift on vendor switches may include many unused front-panel ports;
  decide there whether those count as drift (likely only OpenFlow member ports).

---

## Step 2.3: Clearer names + progress dashboard

### Why

`app1`/`app2` sounded like controller (SDN) applications. They are end hosts:
machines/VMs behind the OVS servers. Renamed to `vm1`/`vm2`. Same IPs and MACs.

### Changes

| File | Change |
|---|---|
| `part_a/nsot.json` | hosts `app1`→`vm1`, `app2`→`vm2` (and `ovs1`/`ovs2` port 2 `to`) |
| `virtual/step2_full_topology.py` | path check is now `vm1 -> vm2` |
| `dashboard.html` | new: progress dashboard; tiered network diagram (router = traditional, the 6 switches = SDN domain, port numbers from the NSOT) |

Earlier evidence files still say `app1`/`app2`; that is the old name for the
same hosts.

### Check

Step 2 rerun: apply 6 × OK, no drift, `pingall` 8/20 (`srv1`, `vm1`, `vm2`
reach each other; `pc1` ↔ `pc2`), `vm1 -> vm2` works, clean shutdown.
Evidence: `logs/step2/step2_3_rename_run.txt`.

### What each box is

| Name | Physical lab | Virtual lab |
|---|---|---|
| r1 | Cisco router (traditional) | Linux host routing (Step 3) |
| cisco1 | Cisco switch | OVS bridge, dpid 1 |
| arista1, arista2 | Arista switches | OVS bridges, dpid 11, 12 |
| hp1 | HP switch | OVS bridge, dpid 21 |
| ovs1, ovs2 | bare-metal servers running OVS | OVS bridges, dpid 31, 32 |
| pc1, pc2 | user laptops, VLAN 10 | Mininet hosts |
| srv1 | server, VLAN 20 | Mininet host |
| vm1, vm2 | VMs/machines behind the OVS servers, VLAN 20 | Mininet hosts |

The wiring is our design (the guide says the real connectivity is provided
separately). On lab day the NSOT changes, not the code.

---

## Step 3: Router (inter-VLAN routing, Internet, NAT, DHCP)

### Goal

Add the traditional router the guide requires: inter-VLAN routing, Internet
access, DHCP. The router does **not** speak OpenFlow; the SDN switches must
deliver frames to it exactly like a normal trunk port would.

### Design

```
inet (203.0.113.2) ── WAN ── r1 ── trunk 10,20 ── cisco1 port 1
                              ├─ r1-eth0.10  10.10.10.1  (VLAN 10 gateway)
                              ├─ r1-eth0.20  10.10.20.1  (VLAN 20 gateway)
                              ├─ NAT: inside → 203.0.113.1
                              └─ DHCP: 10.10.10.100-199, 10.10.20.100-199
```

- **r1** is a Linux host acting as the router (virtual stand-in for the Cisco
  router). Router-on-a-stick: one trunk, one VLAN subinterface per VLAN.
- **No controller change.** cisco1 port 1 is a trunk in the NSOT; the VLAN app
  already tags frames to/from trunks, which is all a router-on-a-stick needs.
- **Hosts** get their VLAN's gateway as default route.
- **inet** stands in for the Internet; NAT hides the inside addresses.

### NSOT additions

- `cisco1` port `1`: `{"to": "r1", "mode": "trunk", "vlans": [10, 20]}`
- `routers.r1`: `lan` (switch port, MAC, IOS interface name), `wan` (IP, next
  hop, IOS interface name), `nat`, `dhcp` pools per VLAN
- `external.inet`: IP, MAC, attached to `r1:wan`

Subinterface IPs are not repeated: they are each VLAN's `gateway`; the
router's VLANs are the VLANs on its switch trunk.

### Files

| File | Runs on | Purpose |
|---|---|---|
| `virtual/lab9_net.py` | Mininet VM | builds everything in the NSOT (switches, hosts, router, inet), configures r1, waits for `nsot_apply.py`, runs checks. Replaces `step2_full_topology.py`. |
| `part_a/render_router.py` | anywhere | prints the Cisco IOS config for r1 from the NSOT (`part_a/generated/r1_ios.cfg`) |

### One-time install (Mininet VM)

```bash
sudo apt-get install -y --no-install-recommends dnsmasq-base   # binary only, no service
lsmod | grep 8021q || sudo modprobe 8021q                      # VLAN subinterfaces
```

### What `lab9_net.py` does to r1 (Linux = virtual router)

```bash
ip addr flush dev r1-eth0 ; ip link set r1-eth0 up
ip link add link r1-eth0 name r1-eth0.10 type vlan id 10 ; ip addr add 10.10.10.1/24 dev r1-eth0.10 ; ip link set r1-eth0.10 up
ip link add link r1-eth0 name r1-eth0.20 type vlan id 20 ; ip addr add 10.10.20.1/24 dev r1-eth0.20 ; ip link set r1-eth0.20 up
ip addr add 203.0.113.1/30 dev r1-eth1 ; ip link set r1-eth1 up
ip route replace default via 203.0.113.2 dev r1-eth1
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o r1-eth1 -j MASQUERADE
dnsmasq --conf-file=/dev/null --port=0 --bind-interfaces \
  --interface=r1-eth0.10 --interface=r1-eth0.20 \
  --dhcp-range=10.10.10.100,10.10.10.199,12h --dhcp-range=10.10.20.100,10.10.20.199,12h \
  --dhcp-leasefile=/tmp/r1-dhcp.leases --pid-file=/tmp/r1-dnsmasq.pid --log-dhcp --log-facility=/tmp/r1-dnsmasq.log
```

(`--port=0` turns off dnsmasq's DNS; DNS is the controller's job in A3.)

### Commands

```bash
# laptop -> controller, then restart Ryu (cisco1 now has port 1)
scp part_a/nsot.json part_a/render_router.py sdn@<controller>:/home/sdn/lab9/part_a/
kill $(cat ryu.pid); setsid nohup part_a/start_ryu.sh > ryu.log 2>&1 < /dev/null & echo $! > ryu.pid

# laptop -> Mininet VM
scp virtual/lab9_net.py part_a/nsot.json mininet@<mininet>:/home/mininet/lab9/
sudo mn -c
sudo tmux new -d -s lab9 "cd /home/mininet/lab9 && python3 lab9_net.py 2>&1 | tee evidence/step3_run.txt"

# controller
python3 part_a/nsot_apply.py
python3 part_a/nsot_drift.py
```

### Expected vs observed

| Check | Expected | Observed |
|---|---|---|
| r1 interfaces | `.10` 10.10.10.1, `.20` 10.10.20.1, WAN 203.0.113.1 | as expected; `ip_forward=1`, MASQUERADE on `r1-eth1`, dnsmasq running |
| `pingall` (7 hosts) | 36/42: all except inet → inside | **14% dropped (36/42)**; only `inet -> X X X X X X` |
| pc1 → pc2 | switched, ttl 64 | ttl=64 |
| pc1 → srv1 | routed, ttl 63 | ttl=63 |
| pc1 → inet | routed + NAT, ttl 63 | ttl=63 |
| cisco1 port 1 capture | same packet up on VLAN 10, down on VLAN 20 | `pc1→r1 vlan 10`, `r1→srv1 vlan 20`, reply `vlan 20` then `vlan 10` |
| What inet sees | source 203.0.113.1 | `203.0.113.1 > 203.0.113.2: ICMP echo request` |
| cisco1 flows | rules with `in_port=1` and to r1's MAC on both VLANs | e.g. `in_port=2,dl_vlan=10,dl_dst=…01:01 → output:1`, `in_port=1,dl_vlan=20,dl_dst=srv1 → output:4` |
| DHCP | pc2 gets a 10.10.10.1xx lease + gateway | `Lease of 10.10.10.118 … router=10.10.10.1`; ping srv1 from it OK; lease in `/tmp/r1-dhcp.leases` |
| A2 | still clean | `nsot_apply.py --verify` all OK, `nsot_drift.py` no drift (includes cisco1 port 1) |
| Shutdown | clean | `*** Done`, no bridges, no dnsmasq left |

Note: trunk-to-trunk rules on cisco1 have no push/pop (frames stay tagged);
only access ports untag. The DHCP broadcast here simply floods inside the
VLAN to r1. Forcing it to the router as **unicast** is A4 (later).

### Evidence

`logs/step3/`: `step3_run.txt` (everything above), `step3_apply.txt`,
`step3_drift.txt`, `r1_ios.cfg`.

### Physical lab equivalent

- Check the router's interface names (`show ip interface brief`), put them in
  `routers.r1.lan.ios_interface` / `wan.ios_interface`, then
  `python3 part_a/render_router.py > r1.cfg` and paste it on the router.
- The real WAN address / next hop / whether NAT is needed come from the lab;
  change them in the NSOT only.
- The core switch port facing the router must be a trunk with VLANs 10,20
  (already the NSOT's cisco1 port 1 role).
- Verify on the router: `show ip interface brief`, `show ip route`,
  `show ip dhcp binding`, `show ip nat translations`.

---

## Step 4: Redundant link, loop protection, failover

### Goal

A1: "The network continues to operate when the designated redundant link
fails." Add a standby link `arista1:4 ↔ arista2:4`, which closes a loop
(cisco1–arista1–arista2), without causing a broadcast storm, and fail over
to it automatically when a primary link dies.

### Design (controller-side "STP")

- The controller knows every switch link from the NSOT (`load_links`) and
  every port's up/down state from the switches (OpenFlow PORT_STATUS, plus a
  port-description request when a switch connects).
- `blocked_ports` builds a loop-free tree from the links that are up, normal
  links first, `standby` links last (Kruskal). Links left out are **blocked**:
  the app never floods out of them and ignores packets arriving on them.
- After every port change, `update_tree` rebuilds the tree. If the blocked set
  changed, it clears the controller's MAC tables and deletes every learned flow
  (cookie `LEARNED` = 0x10) on all switches; traffic re-learns over the new tree.
- No BPDUs and no root election: the controller sees the whole network.
- Floods always go through the controller (never installed as flows), so a
  flood can never loop once a port is blocked.

| State | Blocked |
|---|---|
| all links up | `arista1:4`, `arista2:4` |
| cisco1–arista2 or cisco1–arista1 down | none (standby carries traffic) |
| link repaired | `arista1:4`, `arista2:4` again |
| cisco1–hp1 down (no backup) | unchanged; hp1/srv1 cut off |

### Files

| File | Change |
|---|---|
| `part_a/nsot.json` | `arista1` / `arista2` port 4: trunk 10,20 with `"standby": true` |
| `part_a/vlan_switch_13.py` | `load_links`, `blocked_ports`, `LINKS`, `LEARNED`; port-desc / port-status / disconnect handlers; `update_tree`, `usable`; flooding and learning skip blocked/down ports; learned flows carry cookie `LEARNED`; `load_ports` also checks both ends agree on `standby` |
| `virtual/lab9_net.py` | `--failover`: link-failure tests (`ping_while`, `standby_flows`) |

### Commands

```bash
# controller
scp part_a/vlan_switch_13.py part_a/nsot.json sdn@<controller>:/home/sdn/lab9/part_a/
/home/sdn/ryu-py3/bin/python3 part_a/tests/test_vlan_switch.py
/home/sdn/ryu-py3/bin/python3 part_a/tests/test_nsot_loader.py
kill $(cat ryu.pid); setsid nohup part_a/start_ryu.sh > ryu.log 2>&1 < /dev/null & echo $! > ryu.pid
grep blocked ryu.log      # "6 switch links, blocked ports: [(11, 4), (12, 4)]"

# Mininet VM
scp virtual/lab9_net.py part_a/nsot.json mininet@<mininet>:/home/mininet/lab9/
sudo tmux new -d -s lab9 "cd /home/mininet/lab9 && python3 lab9_net.py --failover --no-cli 2>&1 | tee evidence/step4_failover_run.txt"

# controller
python3 part_a/nsot_apply.py
```

In the Mininet CLI a link is cut / restored with `link cisco1 arista2 down` /
`link cisco1 arista2 up` (the script uses `net.configLinkStatus`).

### Expected vs observed

Offline (`blocked_ports`, 7 cases): all correct (standby blocked when all up;
nothing blocked when either primary or the standby itself is down; one end
down is enough; no change for cisco1–hp1).

Live (ping every 0.1 s, link change after 3 s):

| Test | Expected | Observed |
|---|---|---|
| A. baseline with the loop present | 36/42, no storm, no flows on port 4 | 36/42; no port-4 flows |
| B. cut cisco1–arista2 during pc2 → srv1 | short gap at most, then via standby | **80/80 replies, 0 lost, 0 duplicates**; arista1/arista2 flows now use port 4 |
| B. pingall while down | 36/42 | 36/42 |
| C. restore cisco1–arista2 | standby blocked again | 80/80, 0 lost; no port-4 flows |
| C. pingall | 36/42 | 36/42 |
| D. cut / restore cisco1–arista1 during pc1 → srv1 | same as B/C | 80/80 and 80/80, 0 lost |
| E. cut cisco1–hp1 (no backup) | srv1 unreachable | 31/80 (lost from the cut on), as expected |
| E. pingall after restoring | 36/42 | 36/42 |
| Duplicate replies (loop sign) | 0 | 0 in every test |

Controller log (`step4_ryu.log`), e.g.:

```
6 switch links, blocked ports: [(11, 4), (12, 4)]
port 1:3 is DOWN
topology change: blocked ports [(11, 4), (12, 4)] -> none
port 12:1 is up
port 1:3 is up
topology change: blocked ports none -> [(11, 4), (12, 4)]
```

0 lost pings: in Mininet the PORT_STATUS arrives immediately, and re-learning
finished within one 0.1 s ping interval. **Real hardware will be slower**
(link-down detection and debounce in the switch, OpenFlow agent delay); expect
some loss there and measure it on lab day with the same test.

### Limits (for B5 / later)

- Detects failures where a port goes **down**. A link that stays up but stops
  passing traffic is not detected; LLDP probing by the controller would cover
  that (possible improvement).
- Only links in the NSOT are known. An unlisted cable that makes a loop is not
  blocked (drift detection reports the unexpected port).
- `nsot_drift.py` was not rerun in this step (port 4 now exists on both
  Aristas); rerun it with the next network run.

### Evidence

`logs/step4/`: `step4_failover_run.txt`, `step4_ryu.log`, `step4_apply.txt`,
`step4_offline_test.txt`, `step4_loader_test.txt`.

### Physical lab equivalent

- Mark the cable the TA calls the "designated redundant link" with
  `"standby": true` at both ends in the NSOT.
- Each vendor switch must send OpenFlow PORT_STATUS on link changes (standard;
  check per vendor).
- Turn off the vendor's own STP on OpenFlow ports, or STP and the controller
  will both try to block ports.
- Test: continuous ping across the primary link, pull the cable, count lost
  pings, plug it back, count again. Check the controller log for
  `topology change`.

---

## Step 5: Management network isolation (finishes A1 in virtual lab)

### Goal

A1: "The management network is isolated from production/host traffic."
Declare the out-of-band management network in `nsot.json`, enforce in the NSOT
loader and `nsot_apply.py` / `nsot_drift.py` that the management subnet never
overlaps any data VLAN subnet and that all controller/switch management IPs
live inside it, verify live that data VLAN hosts cannot reach the management
subnet, and rerun `nsot_drift.py` with Step 4's standby port 4 in place.

### Design

- **Virtual lab (out-of-band via root namespace LAN):**
  - Management plane: `10.224.0.0/16` (`sdn-controllers` `10.224.78.132`,
    `mininet-ofm` `10.224.76.126`). OVS bridges run in the root namespace of
    `mininet-ofm` and connect to `10.224.78.132:6633` over `eth0`.
  - Data plane: Mininet hosts (`pc1`, `pc2`, `srv1`, `vm1`, `vm2`, `r1`) run in
    isolated network namespaces attached only to OpenFlow ports on VLAN 10
    (`10.10.10.0/24`) and VLAN 20 (`10.10.20.0/24`). `r1` routes only between
    VLAN 10, VLAN 20, and `inet` (`203.0.113.0/30`).
- **Config guardrails (`vlan_switch_13.py` `load_ports` + `nsot_apply.py` `check_switch`):**
  - Verifies `management.subnet` does not overlap any `vlans.<id>.subnet`.
  - Verifies `controller.ip` and every `switches.<name>.mgmt.ip` belong to
    `management.subnet`.

### Files

| File | Change |
|---|---|
| `part_a/nsot.json` | Added `"management"` block (`mode: "out-of-band"`, `subnet: "10.224.0.0/16"`, `isolated_from_vlans: [10, 20]`) |
| `part_a/vlan_switch_13.py` | `load_ports` checks `management.subnet` non-overlap with VLAN subnets and membership of controller + switch `mgmt.ip` |
| `part_a/nsot_apply.py`, `part_a/nsot_drift.py` | `check_switch` validates `mgmt.ip` against `management.subnet` |
| `part_a/tests/test_nsot_loader.py` | Added 2 negative test cases (`mgmt overlaps VLAN`, `switch mgmt on data VLAN`) |
| `virtual/lab9_net.py` | `run_checks` verifies `pc1` (VLAN 10) and `srv1` (VLAN 20) get `no reply` when pinging controller (`10.224.78.132`) and switch management (`10.224.76.126`) |

### Commands

```bash
# controller
/home/sdn/ryu-py3/bin/python3 part_a/tests/test_nsot_loader.py
python3 part_a/nsot_apply.py
python3 part_a/nsot_drift.py

# Mininet VM
sudo python3 lab9_net.py --no-cli
```

### Expected vs observed

| Check | Expected | Observed |
|---|---|---|
| `test_nsot_loader.py` (`mgmt overlaps VLAN`) | REFUSED | `REFUSED: management subnet 10.10.10.0/24 overlaps VLAN 10 (10.10.10.0/24)` |
| `test_nsot_loader.py` (`switch mgmt on data VLAN`) | REFUSED | `REFUSED: arista1: mgmt ip 10.10.10.99 is not in management subnet 10.224.0.0/16` |
| `nsot_drift.py` (with port 4 standby link) | exit 0, no drift | `no drift: every switch matches the NSOT` |
| `pc1` (VLAN 10) → controller (`10.224.78.132`) & switch mgmt (`10.224.76.126`) | `no reply` | `no reply` on both |
| `srv1` (VLAN 20) → controller (`10.224.78.132`) & switch mgmt (`10.224.76.126`) | `no reply` | `no reply` on both |
| Data plane `pingall` & DHCP | 36/42, DHCP lease obtained | 36/42, `pc2` leased `10.10.10.165` |

### Evidence

`logs/step5/`: `step5_loader_test.txt`, `step5_apply.txt`, `step5_drift.txt`,
`step5_run.txt`.

### Physical lab equivalent

- Connect the controller NIC, OVS server management NICs, Arista `Management1`,
  and HP management VLAN/OOBM port to the dedicated management switch/VLAN (never
  to an OpenFlow-controlled port).
- Update `management.subnet`, `controller.ip`, and each switch's `mgmt.ip` in
  `nsot.json` to the physical rack's management subnet.
- Run `python3 part_a/nsot_drift.py` to confirm all management IPs pass the
  subnet check and all switches connect out-of-band, and verify from `pc1`/`srv1`
  that `ping <controller-mgmt-ip>` fails.

---

## Step 6: A3 DNS blacklist app (`applications/dns_blacklist.py`)

### Goal

A3: force DNS from every device to the controller; the controller asks an
external JSON service for a good/bad verdict; bad domains get a modified DNS
reply that points to a "blocked" page (the former bonus, now required).

### Design

- Every switch gets a protected rule: priority 50, cookie `0x30`,
  `udp,tp_dst=53 -> CONTROLLER` (beats priority-1 learned flows).
- `DnsBlacklistEngine.handle_packet` parses the query, calls the verdict
  service from the controller, and either lets the query continue to `r1`
  (good) or sends a forged A-record reply pointing at `blocked_page_ip`
  (`10.10.20.21`, srv1) straight back out the ingress port (bad).
- External verdict: `applications/dns_verdict_service.py` (port 8053,
  `GET /check?domain=` -> JSON). It checks the team's own blacklist first, then
  Cloudflare's malware/phishing filter (1.1.1.3, DNS-over-HTTPS JSON API).
- REST + UI on Ryu's port 8080: `/lab9/dns/ui`, `/status`, `/check`,
  `/blacklist`, `/config`.
- Virtual lab: `inet` is now NATed to the VM's real Internet (management
  subnet dropped on `inet`), `r1`'s dnsmasq forwards DNS to 8.8.8.8.

### Observed (pc1, `dns-test <domain>`)

| Domain | Verdict source | Result |
|---|---|---|
| example.com | Cloudflare: clean | real IP, `<title>Example Domain</title>` |
| google.com | Cloudflare: clean | real IP, `<title>Google</title>` |
| phishing.testcategory.com | Cloudflare: censored | `10.10.20.21`, ACCESS BLOCKED page |
| evil.com, bad.lab9.lan | team blacklist | `10.10.20.21`, ACCESS BLOCKED page |

Blocked domains never appear in `r1`'s dnsmasq log (stopped at the edge switch).

### Evidence

`logs/step6_dns/`.

### Physical lab equivalent

Run `dns_verdict_service.py 80` on a data-VLAN server for the blocked page and
set `dns_blacklist.blocked_page_ip` in the NSOT. Demo from a real PC browser
with `http://` URLs (HTTPS shows a certificate warning for the blocked page).

---

## Step 7: A4 DHCP unicast app (`applications/dhcp_unicast.py`)

### Goal

A4: force DHCP requests to the Internet router; requests entering at the edge
switches must be unicast.

### Design

- Every switch gets a protected rule: priority 50, cookie `0x40`,
  `udp,tp_src=68,tp_dst=67 -> CONTROLLER`.
- `find_next_hop_to_router`: BFS over usable (not blocked, not down) links to
  `cisco1:1`, so DHCP follows the standby link during a failover.
- `rewrite_dhcp_to_unicast`: Ethernet destination `ff:ff:ff:ff:ff:ff` -> router
  MAC (from the NSOT); sent out one port only.
- **Found in testing:** rewriting the IP destination to `10.10.10.1` as well
  broke DHCP. The router's kernel drops unicast IP from source `0.0.0.0` as a
  martian (UDP counter on r1 stayed at 0). So the IP destination is rewritten
  to the gateway only when the client already has an IP; a new client's
  request is a unicast **frame** that keeps IP destination `255.255.255.255`.
- REST + UI: `/lab9/dhcp/ui`, `/lab9/dhcp/status`, `/lab9/dhcp/config`.

### Commands

```bash
# Mininet VM
sudo python3 lab9_net.py --dhcp
# controller
python3 part_a/nsot_apply.py
```

### Observed

| Check | Expected | Observed |
|---|---|---|
| rule on arista2 | priority 50, cookie 0x40 | `cookie=0x40 ... priority=50,udp,tp_src=68,tp_dst=67 actions=CONTROLLER` |
| pc2-eth0 (host sends) | broadcast | `00:00:00:00:10:12 > ff:ff:ff:ff:ff:ff`, `0.0.0.0.68 > 255.255.255.255.67` |
| arista2-eth1 (trunk leaving edge) | unicast frame to r1 | `00:00:00:00:10:12 > 00:00:00:00:01:01`, vlan 10 |
| pc1-eth0 (same VLAN) | nothing | 0 packets |
| pc2 lease | from r1 | `10.10.10.118`, router/server `10.10.10.1` |
| controller log | edge rewrite + cisco1 hop | DISCOVER and REQUEST: arista2 2->1, cisco1 3->1 |

Not tested yet: a renewal from a client that already has an IP (the path that
also rewrites the IP destination), and DHCP during a link failover.

### Evidence

`logs/step7_dhcp/`.

### Physical lab equivalent

Check early on lab day that the real Cisco router answers a DHCP request sent
as a unicast frame (router MAC) with IP destination `255.255.255.255`.

---

## Step 7.1: One controller console (`applications/console.html`)

The separate DNS and DHCP pages were replaced by one console at
`http://<controller>:8080/lab9/ui` (tabs: DNS filter, DHCP to router; A5/A6
will be added as tabs). Old URLs `/lab9/dns/ui` and `/lab9/dhcp/ui` serve the
same console on the matching tab.

- `applications/console.py`: serves the page (read from disk on every request,
  so edits need no Ryu restart) and `GET /lab9/nsot/summary` (switch and host
  names from the NSOT, no secrets), so the page shows `pc1`/`arista1` instead of
  IPs and DPIDs. Registered in `vlan_switch_13.py`.
- Design: dark rack-steel background; Ethernet pair colours carry meaning
  (green allowed, orange blocked, blue unicast, dotted grey broadcast); each
  decision drawn as a wire, each DHCP request as its real switch path; top bar
  shows the six switches as a faceplate lit by `/stats/switches`. Font:
  Atkinson Hyperlegible Next (clear 0/O, 1/l for addresses).
- Checked with live traffic (5 DNS lookups, 1 DHCP lease) and screenshots at
  1440 px and 390 px wide.

---

## Step 7.2: Verification of real traffic (A3 + A4) and the console

Two repeatable test scripts (laptop, network + Ryu running):

```bash
cd lab9/applications/tests
SSHPASS=<mininet password> python3 test_dataflow.py      # traffic on the wire
SSHPASS=<mininet password> python3 test_console_ui.py    # console buttons + their network effect
```

`mininet_host.py` (shared): runs commands inside hosts (`mnexec`) and captures
on many interfaces at once (802.1Q-tagged frames included).

### Traffic (`test_dataflow.py`): 20/20

| Check | Proof on the wire |
|---|---|
| intercept rules | cookie 0x30 + 0x40, priority 50, on all 6 switches |
| allowed lookup | example.com query seen on cisco1 port 1 (router) |
| blocked lookup | 0 evil.com packets on cisco1 port 1; pc1 gets reply "from 10.10.10.1", A 10.10.20.21 |
| bypass via 8.8.8.8 | still blocked (forged reply "from 8.8.8.8"); allowed domains still answered from the Internet |
| blocked page | HTTP to evil.com returns ACCESS_BLOCKED page |
| VLAN 20 / OVS server | vm2: Cloudflare-flagged domain blocked |
| router log | only example.com asked; blocked domains never reached r1 |
| DHCP | pc2 sends ff:ff:ff:ff:ff:ff; on arista2 trunk and at r1 every request is to 00:00:00:00:01:01; 0 packets on 6 other VLAN-10 links; lease OK |
| DHCP, client with IP | DHCPINFORM from 10.10.10.118: r1 receives `10.10.10.118.68 > 10.10.10.1.67`, answers DHCPACK |
| link cut cisco1–arista2 | lease via standby (arista2 port 4), still unicast; DNS still filtered |
| link restored | DHCP back on arista2 port 1, 0 packets on standby |

Control (to rule out a false "0 leaks"): with unicast forcing turned off, the
same captures saw the broadcast on 5 of 6 links (standby link 0: blocked by
loop protection). With forcing on: 0 on all.

### Console (`test_console_ui.py`): 23/23

Headless Chrome clicks every control; each is checked on the page and in the
network: block/unblock (vm1 gets blocked page / real site), check a domain,
filtering off/on (evil.com real IP / blocked page), forcing off/on (pc1 sees
the broadcast / sees 0), clear history, empty input message, no JS errors.
Run 1 had one failure (T5): a test timing bug (matched an older "Blocked"
row before the 2 s refresh); fixed to wait for the new top row.

### Not covered (limits)

- DNS over TCP/53 and DNS-over-HTTPS are not intercepted (only UDP/53).
- Real Cisco router acceptance of the unicast-frame DHCP request: lab day.

### Evidence

`logs/step7_1_console/`: `dataflow_run1.txt`, `dataflow_control_forcing_off.txt`,
`ui_test_run1.txt` (22/23), `ui_test_run2.txt` (23/23).

---

## Step 7.3: "How it works" tab: hop-by-hop map

Console tab at `http://<controller>:8080/lab9/ui#how`. Four situations
(allowed lookup, blocked lookup, DHCP request, DHCP with a cable cut), each a
list of steps; the packet is animated along each step's hops, the acting device
is highlighted, the text says what it decides, and the packet's headers are
shown with the fields changed at that step in blue.

- The map and the paths are computed from the NSOT, not drawn by hand:
  `applications/console.py` `nsot_topology()` adds `topology` (switch links with
  ports + standby flag, where each host/router plugs in, router MAC/gateways/
  DHCP pools, Internet node, blocked-page IP) to `GET /lab9/nsot/summary`.
  Paths use the same idea as the controller (shortest path, standby only when a
  cable is cut), so they match lab-day cabling once the NSOT is updated.
- Computed paths match what `test_dataflow.py` captured on the wire, e.g. cable
  cut: arista2 → arista1 (standby) → cisco1 → r1.
- `test_console_ui.py` now also checks the tab (T15–T18: paths of all four
  situations, router not on a blocked lookup's path, cut + open standby drawn,
  Next/Back, Play moves the packet and advances, Pause stops). T19 (no JS
  errors) was made strict: the recorder is injected before page scripts
  (`Page.enable` is required for that) and the check fails if it is missing;
  before, a missing recorder would have passed as "0 errors".

Results: console 33/33 (`ui_test_run4_with_map.txt`), traffic re-run after the
Ryu restart 20/20 (`dataflow_run2_after_map.txt`), in `logs/step7_1_console/`.

---

## Step 7.4: Visualisation of the trace app (before building A5)

Three situations added to "How it works" under "How the trace app works":
trace pc1 → srv1 (starts with what ICMP traceroute shows: only r1 and srv1,
the 4 switch hops invisible), trace after a cable cut (follows the rules as
they are now: arista2 out 4, the standby link), trace with a missing rule
(stops at arista2 and says why). The trace is drawn as a hollow ring (it
reads, no packet is sent); a "Trace output" panel builds the printed result.

How the trace works (design for A5): start where the source plugs in (NSOT);
read that switch's flow table through the controller (`/stats/flow/<dpid>`);
the matching rule names the out port; the NSOT says what is wired there; repeat.
The router (not OpenFlow) is worked out from the NSOT subnets (Layer 3:
destination IP → VLAN, readdressed to the destination MAC). `nsot_topology()`
now also returns each VLAN's subnet.

Checked: the rules the visualisation shows match the real flow tables after
pc1 pings srv1 (`logs/step7_1_console/trace_rules_real_vs_predicted.txt`):
arista1 in 2 → push VLAN 10, out 1; cisco1 in 2 → out 1; cisco1 in 1 (VLAN 20)
→ out 4; hp1 in 1 → strip VLAN, out 2. Console test 36/36
(`ui_test_run5_trace_viz.txt`), including the printed hops of all three traces.
Measured: ICMP traceroute pc1 → srv1 shows 2 hops (10.10.10.1, 10.10.20.21).

---

## Step 8: A5 SDN trace (`applications/sdn_trace.py`)

### Goal

A5: take a source and destination, trace the path through the OpenFlow
network, print every switch's DPID with its ingress and egress port.

### Design

- Reads the **real** flow tables through the controller's REST API
  (`/stats/flow/<dpid>`, ofctl_rest), finds the rule an ordinary IPv4 packet
  would match (in_port, VLAN tag, source and destination MAC; rules needing
  UDP ports, i.e. DNS/DHCP, do not match), follows its out port to the next
  switch via the NSOT wiring. Router hop (not OpenFlow) worked out from the
  NSOT subnets. Stops with a reason: no rule yet, wrong place, loop (max 16
  hops), unreadable switch. Read-only: no packet sent, no rule installed.
- `TraceEngine` in Ryu, `GET /lab9/trace?src=&dst=` (A6),
  `applications/trace_cli.py` (CLI; default controller from the NSOT;
  `--details`, `--json`; exit 0 reached / 1 stopped / 2 error),
  console tab "Path trace" (real path lit on the NSOT map + matched rules).
- Inputs: host name, host IP, `inet`, or an Internet IP. Refused (HTTP 400):
  unknown host, same host, an in-VLAN IP that is no NSOT host.

### Bug found and fixed in the switching app (`vlan_switch_13.py`)

Learned rules matched `in_port + eth_dst + VLAN` only. A rule "to pc1 -> port 2"
also carried pc2's replies, so the controller never saw pc2 at that switch,
never learned it, and flooded **every** pc1 -> pc2 packet through the
controller (pings still worked, so nobody noticed). Measured before the fix:
20 pings -> arista1 table-miss +21 (`logs/step8_trace/bug_before_fix.txt`).
Fix: also match `eth_src` (as Ryu's `simple_switch_13` does). After: +0
(test T6b). Found because T6/T9 passed in one run and failed in the next.

### Tests (`applications/tests/test_trace.py`, 22/22)

| Check | Result |
|---|---|
| bad input refused with a reason | 3/3 |
| no learned rules: stops at arista1, says why | pass |
| 10 traces: no rule added, table-miss unchanged on all 6 switches | pass |
| first pings install rules on arista1, cisco1, hp1 (table-miss rose) | pass |
| trace = `arista1 2>1, cisco1 2>1, r1, cisco1 1>4, hp1 1>2`, every hop equal to `ovs-ofctl dump-flows` | pass |
| **second round of 20 pings: table-miss +0 on the path; learned rules +40/+80/+40** | pass |
| same VLAN, both OVS servers, Internet, cable cut (standby), restore, CLI on the controller | pass |

Counters are read 2 s after traffic: OVS copies fast-path counts onto the
OpenFlow rules about once a second (run 1 read 38 instead of 40).

Runs: `logs/step8_trace/test_trace_run1..4*.txt` (18/21, 20/21, 19/21 = test
fixes and the bug; 22/22 after the fix).

---

## Step 9: Part A regression (everything, fresh network)

Fresh Mininet network from the NSOT (bare switches, configured by A2), current
code. Evidence: `logs/step9_regression/`.

| Area | Check | Result |
|---|---|---|
| A1 | pingall 36/42, TTL 64/63, router-on-a-stick tags, NAT 203.0.113.1, mgmt isolation (4/4 no reply), DHCP lease | pass (`reg_full_run.txt`) |
| A1 | failover: cut/restore both sides 80/80, 0 lost, 0 duplicates; no-backup cut loses as expected; 36/42 after | pass (`reg_failover_run.txt`) |
| A2 | `nsot_apply.py` all 6 OK; `nsot_drift.py` no drift; loader refuses 8/8 broken NSOTs; offline VLAN test | pass |
| A3/A4 | `test_dataflow.py` | 20/20 |
| A5 | `test_trace.py` | 22/22 |
| A6 | `test_rest_api.py` (every endpoint, writes undone) | 22/22 |
| UI | `test_console_ui.py` (all 4 tabs, with network effects, strict JS-error check) | 38/38 |

Found and fixed during the regression: the Lab 9 JSON endpoints sent **no
Content-Type header** (`Response(headers=...)` replaces all headers). Shared
`console.json_response()` now used by all apps; checked per endpoint.

Controller log: 0 errors. Left as found: filter on, forcing on, blocklist
unchanged, links up, network running in tmux `lab9`.

---

## Step 10: Part B step 1, the network-state collector (`part_b/collector.py`)

### Goal

B1 (and later B3) need live state from the devices: flow tables, port
rates, drop rules, link status. No model is involved in this step.

### Design

- **REST only, through the controller** (`/stats/switches`, `/stats/flow`,
  `/stats/port`, `/stats/portdesc`). Labs 6/8 used ssh + `ovs-ofctl`, which only
  works on OVS; REST works for every OpenFlow switch (Arista, HP, Cisco) and
  keeps "one controller path".
- Names, wiring, standby links and rule owners come from the NSOT. New NSOT
  section `flow_cookies`: cookie -> owner (`0` table-miss, `16` learned, `48` DNS,
  `64` DHCP, `176`/`177` reserved for AI intents/responses). Any other cookie =
  **unauthorized**.
- Flows and port counters are read twice (default 2 s apart): packets/s per
  port **and per rule** (the rule names the sender's MAC). Missing port or
  counter reset = "invalid" with a reason, never 0 (Lab 8 rule).
- Link state per NSOT link from both ends (OpenFlow `LINK_DOWN` state or
  `PORT_DOWN` config), plus how many learned rules use each link (a standby
  link carrying traffic = the main path failed).
- Standard library only, no f-strings: runs on the laptop (3.14) and on the
  controller (3.5.2, default address from the NSOT).
- Found: every switch reports **no meter support** (`/stats/meterfeatures`:
  `max_meter 0`) -> B3 rate limiting needs a fallback.

### Usage

```
python3 part_b/collector.py --controller 100.110.3.67:8080          # summary
python3 part_b/collector.py --controller 100.110.3.67:8080 --json   # full snapshot
```

### Tests (`part_b/tests/test_collector.py`, 16/16, first run)

Each check compares with an independent source and has a control.

| Check | Independent source | Result |
|---|---|---|
| 6 switches connected, 4 hardware (cisco1, arista1, arista2, hp1) | NSOT | pass |
| rule count per switch | `ovs-ofctl dump-flows` (5/3/7/5/3/3 both) | pass |
| every rule owned, no drops on a clean network (control) | | pass |
| idle port < 5 pps (control), then a ping flood | ping's own count: 1000 in 12.0 s = 83 pps; collector **83.4 pps** | pass |
| busiest rule on arista1 names the sender | `dl_src` = pc1, 81.3 pps | pass |
| standby link cut / restored | `ip link set arista2-eth4 down` | pass |
| main link cisco1-arista2 cut: down, standby carries 2 rules; restored | | pass |
| planted drop rule (cookie 0x99) on hp1: drop + unauthorized, nowhere else; removed | REST add/delete | pass |

Evidence: `logs/stepB1_collector/test_collector_run1.txt`. Controller log 0
errors; everything restored.

Physical equivalent: same code; only the NSOT (DPIDs, ports) changes. The
rate test needs a host that can ping fast (`ping -i 0.01` needs root).
