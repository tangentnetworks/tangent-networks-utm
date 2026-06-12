#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/e2g_queue_processor.sh
# Enhanced: Reads full cron schedule from /etc/crontab

PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin"
export PATH

# Configuration
REQ_DIR="/var/www/htdocs/tn/data/services/queue/e2gfilters/request"
OUT_DIR="/var/www/htdocs/tn/data/services/queue/e2gfilters/outcome"
STATUS_DIR="/var/www/htdocs/tn/data/services/queue/e2gfilters/status"
STATUS_FILE="$STATUS_DIR/active_mode.json"
CRON_FILE="/etc/crontab"
DEBUG_LOG="/tmp/e2g_queue_processor_debug.log"
LOCKFILE="/tmp/e2g_processor.lock"

# Function to log debug info
log_debug() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - [SHELL] $*" >> "$DEBUG_LOG"
}

# ============================================
# FUNCTION: WRITE HONEST STATUS FROM CRONTAB
# Enhanced: Extracts full cron schedule info
# ============================================
write_honest_status() {
  log_debug "Refreshing honest status from crontab..."

  # Initialize variables for a clean slate
  REAL_MODE="none"
  M_NAME="No Filter Active"
  M_DESC="No e2guardian filter is currently scheduled"
  SCRIPT_NAME=""
  CRON_MINUTE=0
  CRON_HOUR=0

  # 1. Check for GENERAL (Adult Mode)
  if CRON_LINE=$(grep "e2g_adult_filter.sh" "$CRON_FILE" | grep -v "^#" | head -1 | sed 's/^[[:space:]]*//') && [ -n "$CRON_LINE" ]; then
    REAL_MODE="general"
    M_NAME="General (Adult Mode)"
    M_DESC="Blocks malware and ads, no porn filtering"
    SCRIPT_NAME="e2g_adult_filter.sh"
    CRON_MINUTE=$(echo "$CRON_LINE" | awk '{print $1}')
    CRON_HOUR=$(echo "$CRON_LINE" | awk '{print $2}')

  # 2. Check for CHILDSAFE (Family Mode)
  elif CRON_LINE=$(grep "e2g_childsafe_filter.sh" "$CRON_FILE" | grep -v "^#" | head -1 | sed 's/^[[:space:]]*//') && [ -n "$CRON_LINE" ]; then
    REAL_MODE="childsafe"
    M_NAME="ChildSafe (Family Mode)"
    M_DESC="Blocks malware, ads, and adult content"
    SCRIPT_NAME="e2g_childsafe_filter.sh"
    CRON_MINUTE=$(echo "$CRON_LINE" | awk '{print $1}')
    CRON_HOUR=$(echo "$CRON_LINE" | awk '{print $2}')

  # 3. Check for CUSTOM (User-Managed)
  elif CRON_LINE=$(grep "e2g_user_filter.sh" "$CRON_FILE" | grep -v "^#" | head -1 | sed 's/^[[:space:]]*//') && [ -n "$CRON_LINE" ]; then
    REAL_MODE="custom"
    M_NAME="Custom (User-Managed)"
    M_DESC="User-defined threat intelligence feeds"
    SCRIPT_NAME="e2g_user_filter.sh"
    CRON_MINUTE=$(echo "$CRON_LINE" | awk '{print $1}')
    CRON_HOUR=$(echo "$CRON_LINE" | awk '{print $2}')
  fi

  log_debug "Final decision - Mode: $REAL_MODE, Hour: $CRON_HOUR, Min: $CRON_MINUTE"

  # 4. Atomic Write to JSON
  # We use ${VAR:-0} as a safety, though our check above ensures they have values.
  cat << EOF > "${STATUS_FILE}.tmp"
{
  "mode": "$REAL_MODE",
  "mode_name": "$M_NAME",
  "description": "$M_DESC",
  "script": "$SCRIPT_NAME",
  "cron_hour": ${CRON_HOUR:-0},
  "cron_minute": ${CRON_MINUTE:-0},
  "updated_human": "$(date '+%Y-%m-%d %H:%M:%S')",
  "updated": $(date +%s)
}
EOF

  mv "${STATUS_FILE}.tmp" "$STATUS_FILE"
  chown www:www "$STATUS_FILE" 2> /dev/null || true
  chmod 644 "$STATUS_FILE" 2> /dev/null || true

  log_debug "Status file updated on disk."
}

# ============================================
# INITIALIZATION
# ============================================
# Remove stale lock
[ -f "$LOCKFILE" ] && rm -f "$LOCKFILE"

# Ensure directories exist
mkdir -p "$REQ_DIR" "$OUT_DIR" "$STATUS_DIR"

log_debug "=== PROCESSOR STARTING ==="

# Force status file creation immediately on startup
write_honest_status

# ============================================
# MAIN LOOP
# ============================================
while true; do
  # Process request files
  for req_file in "$REQ_DIR"/*.txt; do
    if [ ! -e "$req_file" ]; then continue; fi

    job_id=$(basename "$req_file" .txt)
    log_debug "Found job: $job_id"
    # Parse request data
    raw_content=$(cat "$req_file")
    mode=$(echo "$raw_content" | cut -d'|' -f2)
    outcome_name=$(echo "$raw_content" | cut -d'|' -f3)
    outcome_file="$OUT_DIR/$outcome_name"

    # Map mode to script
    case "$mode" in
      general) SCRIPT="/usr/local/sbin/e2g_adult_filter.sh" ;;
      childsafe) SCRIPT="/usr/local/sbin/e2g_childsafe_filter.sh" ;;
      custom) SCRIPT="/usr/local/sbin/e2g_user_filter.sh" ;;
      *)
        log_debug "Invalid mode: $mode"
        rm -f "$req_file"
        continue
        ;;
    esac

    # Execute script
    log_debug "Executing: $SCRIPT"
    START_TIME=$(date +%s)
    LOG_OUTPUT=$($SCRIPT 2>&1) || EXIT_CODE=$?
    EXIT_CODE=${EXIT_CODE:-0}
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    log_debug "Execution finished. Exit code: $EXIT_CODE, Duration: ${DURATION}s"

    # Write outcome
    if [ $EXIT_CODE -eq 0 ]; then
      cat << EOF > "$outcome_file"
{
  "success": true,
  "mode": "$mode",
  "duration": $DURATION,
  "timestamp": $END_TIME
}
EOF
      # CRITICAL: Re-read crontab to get honest state
      # (script may have modified crontab)
      write_honest_status
    else
      cat << EOF > "$outcome_file"
{
  "success": false,
  "mode": "$mode",
  "exit_code": $EXIT_CODE,
  "duration": $DURATION,
  "timestamp": $END_TIME
}
EOF
    fi

    # Set permissions
    chown www:www "$outcome_file" 2> /dev/null || true
    chmod 644 "$outcome_file" 2> /dev/null || true

    # Cleanup request
    rm -f "$req_file"

    log_debug "Job $job_id completed"
  done

  # Sleep between checks
  sleep 2
done
