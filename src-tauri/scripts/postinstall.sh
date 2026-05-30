#!/bin/sh
# Grant raw-socket capability so ARP/ICMP sweeps work without running as root.
# `|| true` keeps the package install from failing on systems without setcap.
setcap cap_net_raw+ep /usr/bin/super-ip-scanner 2>/dev/null || true
