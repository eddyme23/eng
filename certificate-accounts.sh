#!/usr/bin/env bash
# Generate operator-imported credentials; no enrollment HTTP service.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
action="${1:-}"; account="${2:-}"; days="${3:-}"
[[ $account =~ ^[a-z0-9_][a-z0-9_-]{0,31}$ && $days =~ ^[1-9][0-9]{0,3}$ ]] && ((days <= 3650)) || { echo 'Specify account name and validity 1-3650 days.' >&2; exit 1; }
case "$action" in
  create|import)
    bash "$script_dir/ssh-accounts.sh" create-certificate "$account" "$days"
    command=bundle-create; [[ $action != import ]] || command=bundle-import
    if ! bash "$script_dir/app-ssh-auth.sh" "$command" "$account" --days "$days"; then
      echo "Certificate setup failed. No bundle issued. Remove the incomplete account using Remove account in the certificate menu before retrying." >&2
      exit 1
    fi
    ;;
  renew)
    bash "$script_dir/app-ssh-auth.sh" bundle-check "$account"
    bash "$script_dir/ssh-accounts.sh" renew-certificate "$account" "$days"
    bash "$script_dir/app-ssh-auth.sh" bundle-renew "$account" --days "$days"
    ;;
  *) echo 'Usage: certificate-accounts.sh create|import|renew ACCOUNT DAYS' >&2; exit 1 ;;
esac
bash "$script_dir/certificate-details.sh" "$account"
echo 'Import the private bundle into Gen. Keep it secret. Certificate authentication requires the app/Gen bundle importer.'
