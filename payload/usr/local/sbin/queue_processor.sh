#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/queue_processor.sh
# FIXED: Handle slow services (snort, clamd) without blocking the queue

REQ_DIR="/var/www/htdocs/tn/data/services/queue/request"
OUT_DIR="/var/www/htdocs/tn/data/services/queue/outcome"
MANAGER="/usr/local/sbin/service_manager.sh"
MONITOR="/usr/local/sbin/monitor.pl"
LOG="/var/log/queue_processor.log"

# Background job tracking directory
BG_DIR="/var/www/htdocs/tn/data/services/queue/background"
mkdir -p "$BG_DIR" 2> /dev/null
chmod 755 "$BG_DIR" 2> /dev/null
chown www:www "$BG_DIR" 2> /dev/null

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG"
}

# Services that take a LONG time to start and should run in background
# These use background watchers and can take 45s-7min+ depending on load
is_slow_service() {
  case "$1" in
    snort | snortinline | clamd | freshclam | pmacct)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

log "Queue processor run started"

mkdir -p "$REQ_DIR" "$OUT_DIR" 2> /dev/null
chmod 755 "$REQ_DIR" "$OUT_DIR" 2> /dev/null
chown www:www "$REQ_DIR" "$OUT_DIR" 2> /dev/null

file_count=0
for req in "$REQ_DIR"/*.txt; do
  [ -e "$req" ] || continue
  file_count=$((file_count + 1))
done

log "Found $file_count request file(s)"

# Check for completed background jobs first
for bg_marker in "$BG_DIR"/*.done; do
  [ -e "$bg_marker" ] || continue

  JOB_ID=$(basename "$bg_marker" .done)
  log "Background job $JOB_ID completed, processing result"

  # Read the result from the marker file
  if [ -f "$bg_marker" ]; then
    . "$bg_marker" # Source the file to get variables

    TIMESTAMP=$(date +%Y-%m-%d-%H-%M-%S)
    OUT_FILE="$OUT_DIR/${JOB_ID}-${TIMESTAMP}.json"

    # Get current service state
    SERVICE_STATUS_FILE="/var/www/htdocs/tn/data/services/status/${BG_SERVICE}/status"
    if [ -f "$SERVICE_STATUS_FILE" ]; then
      SERVICE_STATE=$(cat "$SERVICE_STATUS_FILE")
    else
      SERVICE_STATE='{"status":"unknown"}'
      log "WARNING: No status file for $BG_SERVICE"
    fi

    if [ "$BG_EXIT_CODE" -eq 0 ]; then
      printf '{"success":true,"action":"%s","service":"%s","state":%s,"timestamp":"%s","background":true}' \
        "$BG_ACTION" "$BG_SERVICE" "$SERVICE_STATE" "$TIMESTAMP" > "$OUT_FILE"
      log "SUCCESS: Background job $JOB_ID completed - $OUT_FILE"
    else
      printf '{"success":false,"action":"%s","service":"%s","error":"service manager exited non-zero","state":%s,"timestamp":"%s","background":true}' \
        "$BG_ACTION" "$BG_SERVICE" "$SERVICE_STATE" "$TIMESTAMP" > "$OUT_FILE"
      log "FAILURE: Background job $JOB_ID completed - $OUT_FILE"
    fi

    chmod 644 "$OUT_FILE"
    chown www:www "$OUT_FILE"

    # Clean up marker
    rm -f "$bg_marker"
    log "Cleaned up background marker: $bg_marker"
  fi
done

# Process new requests
for req in "$REQ_DIR"/*.txt; do
  [ -e "$req" ] || continue

  log "Processing: $req"

  read -r ACTION SERVICE < "$req" || {
    log "ERROR: Failed to read $req"
    rm -f "$req"
    continue
  }

  log "Action=$ACTION Service=$SERVICE"

  ID=$(basename "$req" .txt)
  TIMESTAMP=$(date +%Y-%m-%d-%H-%M-%S)

  # Check if this is a slow service doing start/restart
  if is_slow_service "$SERVICE" && { [ "$ACTION" = "start" ] || [ "$ACTION" = "restart" ]; }; then
    log "SLOW SERVICE: Launching $SERVICE $ACTION in background"

    # Remove request immediately so it doesn't get picked up again
    rm -f "$req"
    log "Removed request file: $req (launching in background)"

    # Launch in background with output capture
    (
      $MANAGER "$ACTION" "$SERVICE" > /dev/null 2>&1
      BG_EXIT_CODE=$?

      # Write completion marker -- store only what's needed for the outcome
      # file. BG_OUTPUT is intentionally omitted: multi-line log text with
      # brackets and special chars corrupts the sourced variable assignment.
      # The manager's output is already in syslog via logger(1).
      BG_MARKER="$BG_DIR/${ID}.done"
      printf 'BG_ACTION="%s"\nBG_SERVICE="%s"\nBG_EXIT_CODE=%d\n' \
        "$ACTION" "$SERVICE" "$BG_EXIT_CODE" > "$BG_MARKER"
      chmod 644 "$BG_MARKER"
      chown www:www "$BG_MARKER"

      echo "$(date '+%Y-%m-%d %H:%M:%S') - Background job $ID finished (exit: $BG_EXIT_CODE)" >> "$LOG"
    ) &

    log "Background job launched for $ID (PID: $!)"

    # Trigger monitor to update UI state immediately
    $MONITOR > /dev/null 2>&1 || true

    continue
  fi

  # Normal (fast) service handling
  OUT_FILE="$OUT_DIR/${ID}-${TIMESTAMP}.json"
  log "Output file: $OUT_FILE"

  OUTPUT=$($MANAGER "$ACTION" "$SERVICE" 2>&1)
  EXIT_CODE=$?

  log "Command exit code: $EXIT_CODE"

  # Trigger monitor
  $MONITOR > /dev/null 2>&1 || true

  SERVICE_STATUS_FILE="/var/www/htdocs/tn/data/services/status/${SERVICE}/status"
  if [ -f "$SERVICE_STATUS_FILE" ]; then
    SERVICE_STATE=$(cat "$SERVICE_STATUS_FILE")
  else
    SERVICE_STATE='{"status":"unknown"}'
    log "WARNING: No status file for $SERVICE"
  fi

  # Use perl to properly escape for JSON
  OUTPUT_ESCAPED=$(echo "$OUTPUT" | perl -pe 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g; s/\r/\\r/g; s/\t/\\t/g')

  if [ $EXIT_CODE -eq 0 ]; then
    printf '{"success":true,"action":"%s","service":"%s","manager_output":"%s","state":%s,"timestamp":"%s"}' \
      "$ACTION" "$SERVICE" "$OUTPUT_ESCAPED" "$SERVICE_STATE" "$TIMESTAMP" > "$OUT_FILE"
    log "SUCCESS: Created $OUT_FILE"
  else
    printf '{"success":false,"action":"%s","service":"%s","error":"%s","state":%s,"timestamp":"%s"}' \
      "$ACTION" "$SERVICE" "$OUTPUT_ESCAPED" "$SERVICE_STATE" "$TIMESTAMP" > "$OUT_FILE"
    log "FAILURE: Created $OUT_FILE"
  fi

  chmod 644 "$OUT_FILE"
  chown www:www "$OUT_FILE"

  rm -f "$req"
  log "Removed request file: $req"
done

# Clean up old outcome files (older than 5 minutes)
# Outcome files must outlive the longest possible job -- 20 min is safe ceiling
find "$OUT_DIR" -name "*.json" -type f -mmin +20 -delete 2> /dev/null

# Clean up old background markers (shouldn't happen, but just in case)
find "$BG_DIR" -name "*.done" -type f -mmin +10 -delete 2> /dev/null

log "Queue processor run completed"
exit 0
