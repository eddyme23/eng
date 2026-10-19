#!/usr/bin/env bash
# HEX-compatible RAM tiers, with bounded service memory.
bhttp_policy() {
  local memory_mb="$1"
  [[ $memory_mb =~ ^[0-9]+$ ]] && ((memory_mb > 0)) || return 1
  if ((memory_mb < 768)); then BHTTP_POLICY_SESSIONS=512
  elif ((memory_mb < 1536)); then BHTTP_POLICY_SESSIONS=1024
  elif ((memory_mb < 3072)); then BHTTP_POLICY_SESSIONS=2048
  elif ((memory_mb < 6144)); then BHTTP_POLICY_SESSIONS=4096
  else BHTTP_POLICY_SESSIONS=8192; fi
  BHTTP_POLICY_MEMORY_MB=$((memory_mb / 2))
  ((BHTTP_POLICY_MEMORY_MB <= 4096)) || BHTTP_POLICY_MEMORY_MB=4096
}
