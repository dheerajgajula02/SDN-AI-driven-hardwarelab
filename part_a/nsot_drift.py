#!/usr/bin/env python3
"""A2 drift detection: compare every switch with the NSOT and report differences.

Drift = a device no longer matches the NSOT (changed by hand, rebooted with an
old config, recabled, ...).

Checked per switch:
  settings     protocols, dpid, fail_mode, controller target
  ports        every NSOT port exists on the device, and no extra ports
  connection   the controller sees the switch's DPID
Also: DPIDs connected to the controller that are not in the NSOT.

Run on the controller VM (next to nsot_apply.py, which holds the drivers):
  python3 nsot_drift.py          report only   (exit 0 = no drift, 1 = drift)
  python3 nsot_drift.py --fix    re-apply the NSOT to switches whose settings
                                 drifted; port drift is only reported, because
                                 adding/removing ports can cut a link
"""

import json
import sys
import time

import nsot_apply as apply


def find_drift(nsot):
    """Return a list of (switch, what, detail, fixable)."""
    controller = nsot['controller']
    seen = apply.controller_dpids(controller)
    drift = []

    mgmt_subnet = nsot.get('management', {}).get('subnet')
    for name, sw in sorted(nsot['switches'].items(), key=lambda kv: kv[1]['dpid']):
        problem = apply.check_switch(name, sw, mgmt_subnet)
        if problem:
            drift.append((name, 'cannot check', problem, False))
            continue
        driver = apply.DRIVERS[sw['mgmt']['driver']]

        # 1. OpenFlow settings: device vs NSOT
        actual = driver['read_back'](sw)
        if 'error' in actual:
            drift.append((name, 'unreachable', actual['error'], False))
            continue
        settings_drifted = False
        for field, want in sorted(apply.expected_settings(sw, controller).items()):
            if actual[field] != want:
                drift.append((name, field, 'expected %s, found %s'
                               % (want, actual[field] or 'nothing'), True))
                settings_drifted = True

        # 2. Ports: device vs NSOT (reported only, never auto-fixed)
        ports, error = driver['read_ports'](sw)
        if error:
            drift.append((name, 'ports', 'could not read: ' + error, False))
        else:
            wanted = set(int(p) for p in sw['ports'])
            for p in sorted(wanted - set(ports)):
                drift.append((name, 'port %d' % p, 'in NSOT (to %s) but missing on device'
                               % sw['ports'][str(p)]['to'], False))
            for p in sorted(set(ports) - wanted):
                drift.append((name, 'port %d' % p, 'on device (%s) but not in NSOT'
                               % ports[p], False))

        # 3. Connection: does the controller see it? Re-applying only helps
        #    if the settings are what is wrong.
        if sw['dpid'] not in seen:
            drift.append((name, 'connection', 'controller does not see dpid %s'
                          % sw['dpid'], settings_drifted))

    # 4. Switches the controller sees that the NSOT does not know about
    known = set(sw['dpid'] for sw in nsot['switches'].values())
    for dpid in sorted(seen - known):
        drift.append(('dpid %s' % dpid, 'unknown switch',
                      'connected to the controller but not in the NSOT', False))
    return drift


def report(drift):
    if not drift:
        print('  no drift: every switch matches the NSOT')
        return
    print('  %-10s %-14s %-5s %s' % ('switch', 'what', 'fix?', 'detail'))
    for name, what, detail, fixable in drift:
        print('  %-10s %-14s %-5s %s' % (name, what, 'yes' if fixable else 'no', detail))


def main():
    with open(apply.NSOT_PATH) as f:
        nsot = json.load(f)
    print('NSOT: %s (%d switches)' % (apply.NSOT_PATH, len(nsot['switches'])))

    print('\n== drift ==')
    drift = find_drift(nsot)
    report(drift)

    if '--fix' in sys.argv:
        to_fix = sorted(set(name for name, _, _, fixable in drift if fixable))
        if to_fix:
            print('\n== fix: re-applying the NSOT to %s ==' % ', '.join(to_fix))
            subset = dict(nsot, switches=dict((n, nsot['switches'][n]) for n in to_fix))
            apply.apply_all(subset, dry_run=False)

            # wait for the fixed switches to reconnect, then check again
            wanted = set(nsot['switches'][n]['dpid'] for n in to_fix)
            deadline = time.time() + apply.CONNECT_WAIT
            while not wanted <= apply.controller_dpids(nsot['controller']) \
                    and time.time() < deadline:
                time.sleep(2)

            print('\n== drift after fix ==')
            drift = find_drift(nsot)
            report(drift)

    return 1 if drift else 0


if __name__ == '__main__':
    sys.exit(main())
