#!/usr/bin/env bash
# Read-only service and connection checks; not a client login test.
set -uo pipefail
systemctl status frimps-bhttp.service --no-pager --full || true
systemctl show frimps-bhttp.service -p ExecStart --no-pager || true
ss -ltnp | grep -E 'bhttp-server|:22[[:space:]]' || true
ss -tnp | grep bhttp-server || true
journalctl -u frimps-bhttp.service -n 60 --no-pager || true
