#!/usr/bin/env bash
set -uo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
state_dir="${V6_STATE_DIR:-/etc/frimps-v6}"
pick() {
  local choice i
  mapfile -t names < <(python3 "$script_dir/xray-manager.py" list "$protocol" | cut -f1)
  ((${#names[@]})) || { echo 'No accounts found.'; return 1; }
  for i in "${!names[@]}"; do printf '  [%02d] %s\n' "$((i+1))" "${names[$i]}"; done
  echo '  [00] Back'
  read -r -p 'Select account: ' choice || return 1
  [[ $choice =~ ^[0-9]{1,3}$ ]] || return 1
  choice=$((10#$choice))
  ((choice>0 && choice<=${#names[@]})) || return 1
  account="${names[$((choice-1))]}"
}
while true; do
  printf '\nXRAY ACCOUNT MANAGEMENT\n  [01] VLESS (recommended)\n  [02] VMess\n  [03] Trojan\n  [04] Shadowsocks 2022\n  [05] Status\n  [06] Restart Xray\n  [00] Back\n'
  read -r -p 'Option: ' option || exit 0
  case "$option" in
    0|00) exit 0;;
    1|01) protocol=vless;; 2|02) protocol=vmess;; 3|03) protocol=trojan;;
    4|04) protocol=shadowsocks;;
    5|05) systemctl status frimps-xray --no-pager; read -r -p 'Press Enter...' _; continue;;
    6|06) systemctl restart frimps-xray; read -r -p 'Press Enter...' _; continue;;
    *) echo 'Invalid option.'; continue;;
  esac
  if [[ ! -s "$state_dir/xray-settings.json" ]]; then
    echo 'Install Xray with: bash /root/eng/xray-install.sh'; continue
  fi
  while true; do
    printf '\n%s ACCOUNTS\n  [01] Create\n  [02] Renew\n  [03] Delete\n  [04] List\n  [05] Show connection links\n  [00] Back\n' "$protocol"
    read -r -p 'Option: ' action || exit 0
    case "$action" in
      0|00) break;;
      1|01)
        read -r -p 'Account name: ' account || exit 0
        read -r -p 'Validity (days): ' days || exit 0
        if bash "$script_dir/xray-accounts.sh" create "$protocol" "$account" "$days"; then
          bash "$script_dir/xray-accounts.sh" links "$protocol" "$account"
        fi;;
      2|02) if pick; then read -r -p 'Validity (days): ' days || exit 0; bash "$script_dir/xray-accounts.sh" renew "$protocol" "$account" "$days"; fi;;
      3|03) if pick; then read -r -p "Delete $account? [y/N] " confirm || exit 0; [[ $confirm =~ ^[Yy]$ ]] && bash "$script_dir/xray-accounts.sh" delete "$protocol" "$account"; fi;;
      4|04) bash "$script_dir/xray-accounts.sh" list "$protocol";;
      5|05) if pick; then bash "$script_dir/xray-accounts.sh" links "$protocol" "$account"; fi;;
      *) echo 'Invalid option.'; continue;;
    esac
    read -r -p 'Press Enter to continue...' _ || exit 0
  done
done
