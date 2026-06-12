#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail
PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin"

RCLOGFILE="/var/www/htdocs/tn/data/logs/bootlog/rc.local.log"
PF_TABLE_DIR="/etc/pf"
PF_TABLES="blocklist bogons"

log() {
  local service="$1"
  local level="$2"
  local message="$3"
  printf "[$(date '+%Y-%m-%d %H:%M:%S')] %s: [%s] %s\n" "$service" "$level" "$message" | tee -a "$RCLOGFILE"
}

log "PFTABLES" "INFO" "Loading PF blocklist tables"

for table in $PF_TABLES; do
  file="${PF_TABLE_DIR}/${table}"

  if [ ! -s "$file" ]; then
    log "PFTABLES" "WARN" "Table file missing or empty: $file -- skipping $table"
    continue
  fi

  pfctl -t "$table" -T flush 2> /dev/null || true

  if pfctl -t "$table" -T replace -f "$file" 2> /dev/null; then
    count=$(pfctl -t "$table" -T show 2> /dev/null | wc -l | tr -d ' ')
    log "PFTABLES" "INFO" "Table $table loaded ($count entries)"
  else
    log "PFTABLES" "ERROR" "Failed to load table: $table"
  fi
done

log "PFTABLES" "INFO" "PF table population complete"
