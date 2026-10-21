#!/usr/bin/env bash
# A port may be reused only when every reported owner is our managed BHTTP stack.
bhttp_port_available() {
  local port="$1" sockets pids pid owner allowed=' '
  sockets=$(ss -H -ltnp "( sport = :$port )") || return 1
  [[ -n $sockets ]] || return 0
  for owner in frimps-bhttp.service frimps-bhttp-alt.service; do
    pid=$(systemctl show "$owner" -p MainPID --value 2>/dev/null || true)
    [[ $pid =~ ^[1-9][0-9]*$ ]] && allowed+="$pid "
  done
  if [[ $port == 8180 ]] && systemctl is-active --quiet frimps-bhttp-alt.socket; then
    if systemctl show frimps-bhttp-alt.socket -p Listen --value | grep -Eq '(^|[[:space:]])(0\.0\.0\.0:|\[::\]:|\*:)?8180([[:space:]]|$)'; then
      allowed+='1 '
    fi
  fi
  pids=$(grep -oE 'pid=[0-9]+' <<<"$sockets" | cut -d= -f2 | sort -u || true)
  [[ -n $pids ]] || return 1
  while read -r pid; do [[ $allowed == *" $pid "* ]] || return 1; done <<<"$pids"
  # A row with no visible owner cannot be safely claimed.
  while IFS= read -r owner; do [[ $owner == *'pid='* ]] || return 1; done <<<"$sockets"
}

bhttp_select_ports() {
  local port
  BHTTP_SELECTED_PORTS=()
  for port in 90 8180 8081; do
    if bhttp_port_available "$port"; then BHTTP_SELECTED_PORTS+=("$port")
    else echo "Skipping TCP $port: occupied by an unrelated or unidentified listener." >&2; fi
  done
  ((${#BHTTP_SELECTED_PORTS[@]} > 0)) || { echo 'No requested BHTTP port is available.' >&2; return 1; }
}
