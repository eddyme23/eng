#!/usr/bin/env bash
set -euo pipefail

state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"

[[ "${EUID}" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ -s "$state_dir/STAGED.md" ]] || { echo "v6 has not been staged." >&2; exit 1; }

# -H removes the column heading.  Without it the heading itself is non-empty
# and every clean VPS is incorrectly reported as already owning TCP 443.
owners="$(ss -H -ltnp '( sport = :443 or sport = :80 or sport = :8080 or sport = :8880 or sport = :2082 or sport = :2086 )' 2>/dev/null || true)"
if [[ -n "$owners" ]]; then
  echo "A required public TCP port is currently owned. A reviewed migration plan is required before cutover:" >&2
  echo "$owners" >&2
  exit 2
fi

echo "No required public TCP port owner detected. This only confirms cutover eligibility; it does not start services."
