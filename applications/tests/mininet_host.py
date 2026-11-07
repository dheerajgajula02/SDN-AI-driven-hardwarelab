"""Helpers for tests that check real traffic in the running Mininet network.

Everything runs on the Mininet VM over SSH, as root:
  - on_root(script)          a command in the VM itself (OVS switch ports live here)
  - on_host(host, command)   a command inside a Mininet host (pc1, r1, ...)
  - capture(points, ...)     tcpdump on many interfaces at once around an action

The password comes from the SSHPASS environment variable, never from a file.
"""

import os
import re
import shlex
import subprocess
import time

MININET = 'mininet@100.73.87.23'


# ===========================================================================
# Function 1: run a shell script on the Mininet VM as root
# ===========================================================================

def on_root(script, timeout=60):
    """Run `script` on the Mininet VM with sudo; return its output."""
    # Step 1: wrap the script so it runs under sudo (password from SSHPASS).
    password = os.environ['SSHPASS']
    remote = 'echo %s | sudo -S -p "" sh -c %s' % (shlex.quote(password), shlex.quote(script))
    # Step 2: run it over SSH (sshpass -e also reads SSHPASS for the login).
    out = subprocess.run(
        ['sshpass', '-e', 'ssh', '-o', 'StrictHostKeyChecking=no',
         '-o', 'PubkeyAuthentication=no', MININET, remote],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=timeout)
    return out.stdout


# ===========================================================================
# Function 2: run a command inside a Mininet host
# ===========================================================================

def in_host(host, command):
    """Shell text that runs `command` inside host `host`'s network namespace.

    Mininet starts each host as a shell named "mininet:<host>"; mnexec -a <pid>
    joins that shell's namespace.
    """
    return 'mnexec -a $(pgrep -f "mininet:%s$") sh -c %s' % (host, shlex.quote(command))


def on_host(host, command, timeout=60):
    return on_root(in_host(host, command), timeout)


def resolve(host, domain, server):
    """nslookup `domain` at DNS server `server` from `host`.
    Returns the answer addresses, e.g. ['10.10.20.21']."""
    out = on_host(host, 'nslookup %s %s' % (domain, server))
    answer = out.split('Name:', 1)[-1] if 'Name:' in out else ''
    return re.findall(r'Address(?: \d+)?:\s*([\d.]+)', answer)


# ===========================================================================
# Function 3: capture packets on several interfaces around an action
# ===========================================================================

def capture(points, port, action, seconds=8):
    """Capture UDP `port` traffic on every interface in `points` while
    `action()` runs.

    points: [(where, interface), ...]
            where = 'root' for an OVS switch port, or a host name ('pc1', 'r1')
    Returns {interface: [packet lines]}. Tagged (802.1Q) frames are included:
    a plain "udp port 53" filter would miss packets on trunks.
    """
    flt = '(udp port %d) or (vlan and udp port %d)' % (port, port)

    # Step 1: start one tcpdump per interface in the background (</dev/null
    #         and & so the SSH call returns at once).
    starts = []
    for where, intf in points:
        cmd = ('timeout %d tcpdump -U -e -nn -i %s %s < /dev/null > /tmp/df-%s.txt 2>&1 &'
               % (seconds, intf, shlex.quote(flt), intf))
        starts.append(cmd if where == 'root' else in_host(where, cmd))
    t0 = time.time()
    on_root('\n'.join(starts))
    time.sleep(1.5)

    # Step 2: do the thing being observed.
    action()

    # Step 3: wait until every capture has stopped, then read them all.
    time.sleep(max(0, t0 + seconds + 1 - time.time()))
    raw = on_root('\n'.join('echo "=== %s"; cat /tmp/df-%s.txt' % (i, i) for _, i in points))

    # Step 4: keep only real packet lines (they contain "ethertype").
    result = {}
    for block in raw.split('=== ')[1:]:
        name, _, body = block.partition('\n')
        result[name.strip()] = [l for l in body.splitlines() if 'ethertype' in l]
    return result
