#!/usr/bin/env bash
# Shared GF-compatible terminal presentation.  Suppress escapes for pipes,
# files and non-interactive calls so generated configs/links stay clean.
if [[ -t 1 && "${TERM:-dumb}" != dumb ]]; then
  UI_RED=$'\033[1;31m'; UI_GREEN=$'\033[1;32m'; UI_YELLOW=$'\033[1;33m'; UI_CYAN=$'\033[1;36m'; UI_WHITE=$'\033[1;37m'; UI_BOLD=$'\033[1m'; UI_NC=$'\033[0m'
else
  UI_RED= UI_GREEN= UI_YELLOW= UI_CYAN= UI_WHITE= UI_BOLD= UI_NC=
fi
ui_line() { printf '%b══════════════════════════════════════════════════════════════%b\n' "$UI_CYAN" "$UI_NC"; }
ui_success_title() { printf '\n%b══════════════════════════════════════════════════════════════%b\n' "$UI_GREEN" "$UI_NC"; printf '                   %b%s%b\n' "$UI_BOLD" "$1" "$UI_NC"; printf '%b══════════════════════════════════════════════════════════════%b\n' "$UI_GREEN" "$UI_NC"; }
ui_kv() { printf '  %b%-14s%b %b%s%b\n' "$UI_WHITE" "$1:" "$UI_NC" "$UI_YELLOW" "$2" "$UI_NC"; }
ui_rule() { printf '%b--------------------------------------------------------------%b\n' "$UI_CYAN" "$UI_NC"; }
# Format tab-separated rows without the optional util-linux column package.
# Buffer rows so long usernames/addresses align; show headers for an empty store.
ui_table() {
  awk -F '\t' -v headers="$1" '
    BEGIN {
      columns=split(headers, labels, ",")
      for (i=1; i<=columns; i++) { cells[0,i]=labels[i]; width[i]=length(labels[i]) }
    }
    {
      for (i=1; i<=columns; i++) {
        cells[NR,i]=$i
        if (length($i)>width[i]) width[i]=length($i)
      }
    }
    END {
      for (row=0; row<=NR; row++) {
        for (i=1; i<=columns; i++) {
          if (i<columns) printf "%-*s  ", width[i], cells[row,i]
          else printf "%s\n", cells[row,i]
        }
      }
    }'
}
