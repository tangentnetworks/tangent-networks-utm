#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/integrity_check.sh
# Monitors integrity check queue and processes verification requests

REQ_DIR="/var/www/htdocs/tn/data/queue/integrity/request"
OUT_DIR="/var/www/htdocs/tn/data/queue/integrity/outcome"
STATUS_DIR="/var/www/htdocs/tn/data/services/status/integrity"
TAUDIT="/usr/local/sbin/TNAudit.pl"
LOG="/var/www/tmp/integrity_runner.log"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG"
}

log "Integrity runner started"

# Ensure directories exist
mkdir -p "$REQ_DIR" "$OUT_DIR" "$STATUS_DIR" 2> /dev/null
chmod 755 "$REQ_DIR" "$OUT_DIR" "$STATUS_DIR" 2> /dev/null
chown www:www "$REQ_DIR" "$OUT_DIR" "$STATUS_DIR" 2> /dev/null

# Process queue
file_count=0
for req in "$REQ_DIR"/request-*; do
  [ -e "$req" ] || continue
  file_count=$((file_count + 1))
done

if [ $file_count -eq 0 ]; then
  # No requests - exit silently
  exit 0
fi

log "Found $file_count request file(s)"

for req in "$REQ_DIR"/request-*; do
  [ -e "$req" ] || continue

  log "Processing: $req"

  # Read action and check type from file
  read -r ACTION CHECK < "$req" || {
    log "ERROR: Failed to read $req"
    rm -f "$req"
    continue
  }

  log "Action=$ACTION Check=$CHECK"

  # Extract request timestamp from filename
  REQUEST_TIME=$(basename "$req" | sed 's/^request-//')
  OUT_FILE="$OUT_DIR/out-${REQUEST_TIME}"

  log "Output file: $OUT_FILE"

  # Execute verification via TNAudit.pl
  START_TIME=$(date +%s)

  # Call TNAudit.pl with proper arguments
  if [ "$ACTION" = "verify" ]; then
    JSON_OUTPUT=$($TAUDIT --verify --check "$CHECK" --json 2>&1)
  elif [ "$ACTION" = "baseline" ]; then
    JSON_OUTPUT=$($TAUDIT --create-baseline --check "$CHECK" --json 2>&1)
  elif [ "$ACTION" = "update" ]; then
    JSON_OUTPUT=$($TAUDIT --update-baseline --check "$CHECK" --json 2>&1)
  else
    log "ERROR: Unknown action: $ACTION"
    rm -f "$req"
    continue
  fi

  EXIT_CODE=$?
  END_TIME=$(date +%s)
  DURATION=$((END_TIME - START_TIME))

  log "TNAudit.pl exit code: $EXIT_CODE (${DURATION}s)"

  # Check if JSON_OUTPUT is valid JSON
  if echo "$JSON_OUTPUT" | grep -q '"success"'; then
    # Parse JSON using grep (simple extraction)
    FILES=$(echo "$JSON_OUTPUT" | grep -o '"files":[0-9]*' | cut -d: -f2)
    CHANGES=$(echo "$JSON_OUTPUT" | grep -o '"changes":[0-9]*' | cut -d: -f2)
    STATUS=$(echo "$JSON_OUTPUT" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    SUCCESS=$(echo "$JSON_OUTPUT" | grep -o '"success":[a-z]*' | cut -d: -f2)

    # Ensure we have values
    FILES=${FILES:-0}
    CHANGES=${CHANGES:-0}
    STATUS=${STATUS:-unknown}

    log "Parsed: FILES=$FILES CHANGES=$CHANGES STATUS=$STATUS SUCCESS=$SUCCESS"

    # Write outcome (just pass through the JSON from TNAudit.pl)
    echo "$JSON_OUTPUT" > "$OUT_FILE"

    log "SUCCESS: Created $OUT_FILE"

    # Update cached status
    if [ "$SUCCESS" = "true" ]; then
      cat > "$STATUS_DIR/$CHECK" << EOF
{
  "status": "$STATUS",
  "files": $FILES,
  "changes": $CHANGES,
  "last_check": $(date +%s),
  "duration": "${DURATION}s"
}
EOF
    else
      cat > "$STATUS_DIR/$CHECK" << EOF
{
  "status": "failed",
  "last_check": $(date +%s),
  "error": "Verification failed"
}
EOF
    fi

  else
    # JSON parsing failed or error output
    log "ERROR: Invalid JSON output or command failed"

    # Escape output for JSON
    OUTPUT_ESCAPED=$(echo "$JSON_OUTPUT" | perl -pe 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g; s/\r/\\r/g; s/\t/\\t/g')

    cat > "$OUT_FILE" << EOF
{
  "success": false,
  "check": "$CHECK",
  "action": "$ACTION",
  "status": "failed",
  "error": "$OUTPUT_ESCAPED",
  "duration": "${DURATION}s",
  "timestamp": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
    log "FAILURE: Created $OUT_FILE"

    # Update cached status
    cat > "$STATUS_DIR/$CHECK" << EOF
{
  "status": "failed",
  "last_check": $(date +%s),
  "error": "Verification failed"
}
EOF
  fi

  # Fix permissions
  chmod 644 "$OUT_FILE"
  chown www:www "$OUT_FILE"
  chmod 644 "$STATUS_DIR/$CHECK"
  chown www:www "$STATUS_DIR/$CHECK"

  # Remove request file
  rm -f "$req"
  log "Removed request file: $req"
done

# Cleanup old outcomes (>5 minutes)
find "$OUT_DIR" -name "out-*" -type f -mmin +5 -delete 2> /dev/null

log "Integrity runner completed"
exit 0
