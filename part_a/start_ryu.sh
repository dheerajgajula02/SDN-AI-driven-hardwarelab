#!/bin/sh
# Start Ryu 4.34 with the Lab 9 VLAN switch and the REST API.
#   OpenFlow: 6633   REST: 8080
# Run on the controller VM from /home/sdn/lab9:
#   nohup part_a/start_ryu.sh > ryu.log 2>&1 &  echo $! > ryu.pid
cd /home/sdn/lab9 || exit 1
pkill -f dns_verdict_service.py 2>/dev/null || true
nohup python3 applications/dns_verdict_service.py 8053 > verdict.log 2>&1 < /dev/null &
exec /home/sdn/ryu-py3/bin/ryu-manager \
  --ofp-tcp-listen-port 6633 --wsapi-port 8080 \
  part_a/vlan_switch_13.py ryu.app.ofctl_rest
