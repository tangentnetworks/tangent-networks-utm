#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_change_detector.sh
#
# Purpose: Monitor user-input directory for changes
# If changes detected:
#   1. Calculate checksum of user inputs
#   2. Compare against last known state
#   3. If different, trigger validation workflow
#   4. Only run processing if actual changes exist
#
# Run via: daemon or cron */1 * * * * (every minute)

set -e

# ============================================
# CONFIGURATION
# ============================================
QUEUE_BASE="/var/www/htdocs/tn/data/services/queue/pf-rules"
USER_INPUT="$QUEUE_BASE/user-input"
TRIGGERS="$QUEUE_BASE/triggers"
STATE_FILE="$QUEUE_BASE/.last_input_state"
LOG_FILE="/var/www/tmp/pf_change_detector.log"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# ============================================
# ENSURE /var/www/tmp EXISTS
# ============================================
if [ ! -d /var/www/tmp ]; then
  mkdir -p /var/www/tmp
  chown www:www /var/www/tmp
  chmod 755 /var/www/tmp
fi

# ============================================
# CALCULATE CHECKSUM OF USER INPUTS
# ============================================
calculate_state() {
  # Combine all user input files and create checksum
  # This detects ANY change in user submissions

  local state=""

  for file in "$USER_INPUT"/*.txt "$USER_INPUT"/*.json; do
    if [ -f "$file" ]; then
      # Get file size + modification time + content hash
      state="${state}$(ls -l "$file" | cksum)"
    fi
  done

  echo "$state" | cksum | awk '{print $1}'
}

# ============================================
# CHECK IF VALIDATION ALREADY REQUESTED
# ============================================
if [ -f "$TRIGGERS/validate-requested" ]; then
  # Don't log on every check - only log once
  if [ ! -f "$TRIGGERS/.validation-logged" ]; then
    log "Validation already in progress, skipping change detection"
    touch "$TRIGGERS/.validation-logged"
  fi
  exit 0
fi

# Remove flag if it exists
rm -f "$TRIGGERS/.validation-logged" 2> /dev/null

# ============================================
# CHECK FOR CHANGES
# ============================================
CURRENT_STATE=$(calculate_state)

if [ -f "$STATE_FILE" ]; then
  LAST_STATE=$(cat "$STATE_FILE")
else
  LAST_STATE=""
fi

# ============================================
# NO CHANGES DETECTED
# ============================================
if [ "$CURRENT_STATE" = "$LAST_STATE" ]; then
  # No changes - exit silently (don't spam logs)
  exit 0
fi

# ============================================
# CHANGES DETECTED!
# ============================================
log "═══════════════════════════════════════════════════"
log "CHANGE DETECTED in user inputs"
log "Previous state: $LAST_STATE"
log "Current state:  $CURRENT_STATE"
log "═══════════════════════════════════════════════════"

# ============================================
# CHECK IF USER INPUTS ARE NON-EMPTY
# ============================================
TOTAL_LINES=0

for file in "$USER_INPUT"/*.txt; do
  if [ -f "$file" ]; then
    LINES=$(grep -v '^[[:space:]]*$' "$file" 2> /dev/null | wc -l | tr -d ' ')
    if [ "$LINES" -gt 0 ]; then
      TOTAL_LINES=$((TOTAL_LINES + LINES))
      log "  • $(basename "$file"): $LINES entries"
    fi
  fi
done

# Check JSON files separately
for file in "$USER_INPUT"/*.json; do
  if [ -f "$file" ] && [ -s "$file" ]; then
    log "  • $(basename "$file"): present"
    TOTAL_LINES=$((TOTAL_LINES + 1))
  fi
done

log "Total non-empty entries: $TOTAL_LINES"

# ============================================
# IF NO ACTUAL CONTENT, SKIP
# ============================================
if [ "$TOTAL_LINES" -eq 0 ]; then
  log "WARNING: Changes detected but no actual content, skipping validation"
  echo "$CURRENT_STATE" > "$STATE_FILE"
  exit 0
fi

# ============================================
# TRIGGER VALIDATION WORKFLOW
# ============================================
log "Triggering validation workflow..."

# Create trigger file (this will be picked up by main daemon)
touch "$TRIGGERS/validate-requested"
chown www:www "$TRIGGERS/validate-requested"

# Update state file
echo "$CURRENT_STATE" > "$STATE_FILE"

log "Validation trigger created successfully"
log "Waiting for pf_monitor.sh to process..."

exit 0
