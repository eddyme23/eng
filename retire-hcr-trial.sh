#!/usr/bin/env bash
# Retire only the obsolete managed trial unit after production HCR is available.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
trial_unit=/etc/systemd/system/frimps-hcr-test.service
[[ -f $trial_unit ]] || exit 0
grep -q '^ExecStart=/opt/frimps-hcr-test/hcr-server ' "$trial_unit" || { echo 'Unrecognized trial unit; left unchanged.' >&2; exit 1; }
systemctl is-active --quiet frimps-hcr.service || { echo 'Start production HCR before retiring the old trial.' >&2; exit 1; }
systemctl disable --now frimps-hcr-test.service
rm -f -- "$trial_unit"
systemctl daemon-reload
systemctl reset-failed frimps-hcr-test.service 2>/dev/null || true
echo 'Obsolete HCR trial service removed; production HCR remains active.'
