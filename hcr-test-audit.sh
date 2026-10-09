#!/usr/bin/env bash
# Read-only HCR trial diagnostics.
set -uo pipefail
printf '%s\n' '=== HCR test service ==='
systemctl status frimps-hcr-test.service --no-pager --full || true
printf '%s\n' '=== HCR launch settings ==='
systemctl show frimps-hcr-test.service -p ExecStart --no-pager || true
printf '%s\n' '=== HCR and SSH listeners / connections ==='
ss -ltnp | grep -E 'hcr-server|:22[[:space:]]' || true
ss -tnp | grep 'hcr-server' || true
printf '%s\n' '=== Recent HCR logs ==='
journalctl -u frimps-hcr-test.service -n 60 --no-pager || true
