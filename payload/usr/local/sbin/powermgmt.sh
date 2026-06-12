#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/powermgmt.sh
# Reads power state requests from queue and executes them
# Follows standard Tangent Networks detector/action script pattern

QUEUE_REQ_DIR="/var/www/htdocs/tn/data/queue/powerstate/request"
QUEUE_OUT_DIR="/var/www/htdocs/tn/data/queue/powerstate/outcome"
LOG_DATE=$(date '+%Y-%m-%d')
LOGFILE="/tmp/power-${LOG_DATE}.log"

# Ensure directories exist
mkdir -p "$QUEUE_REQ_DIR" 2> /dev/null || true
mkdir -p "$QUEUE_OUT_DIR" 2> /dev/null || true

# =============================================
# Check for any request files
# =============================================

# Find oldest request file (process one per cycle)
REQ_FILE=""
for f in "$QUEUE_REQ_DIR"/*.txt; do
  # Check glob did not expand to literal (no files)
  [ -f "$f" ] || exit 0
  REQ_FILE="$f"
  break
done

# No request files found - nothing to do
[ -z "$REQ_FILE" ] && exit 0

# =============================================
# Read the request
# =============================================

COMMAND=$(cat "$REQ_FILE" 2> /dev/null | tr -d '\n\r')

# Validate command is not empty
if [ -z "$COMMAND" ]; then
  echo "[$(date)] ERROR: Empty request file: $REQ_FILE" >> "$LOGFILE"
  rm -f "$REQ_FILE"
  exit 0
fi

# Strict whitelist - only allow known safe commands
case "$COMMAND" in
  "shutdown -r now" | "shutdown -hp now")
    # Valid command - proceed
    ;;
  *)
    echo "[$(date)] ERROR: Rejected unknown command: $COMMAND" >> "$LOGFILE"
    rm -f "$REQ_FILE"
    exit 0
    ;;
esac

# =============================================
# Extract job ID from filename for outcome
# =============================================

FILENAME=$(basename "$REQ_FILE" .txt)
OUTCOME_FILE="${QUEUE_OUT_DIR}/${FILENAME}-outcome.json"

echo "[$(date)] INFO: Processing request: $FILENAME" >> "$LOGFILE"
echo "[$(date)] INFO: Command: $COMMAND" >> "$LOGFILE"

# =============================================
# Delete request file BEFORE executing
# so runner does not re-process on next cycle
# =============================================

rm -f "$REQ_FILE"

# =============================================
# Write outcome file BEFORE executing shutdown
# because system may halt before we can write it
# =============================================

cat > "$OUTCOME_FILE" << EOF
{"success":true,"message":"Command accepted and executing: ${COMMAND}","command":"${COMMAND}"}
EOF

echo "[$(date)] INFO: Outcome written: $OUTCOME_FILE" >> "$LOGFILE"
echo "[$(date)] INFO: Executing: $COMMAND" >> "$LOGFILE"

# Small delay so Perl polling can read the outcome
# before the system goes down
sleep 1

# =============================================
# Execute the command
# =============================================

$COMMAND >> "$LOGFILE" 2>&1

# If we get here (restart case), log it
echo "[$(date)] INFO: Command returned (system may be restarting)" >> "$LOGFILE"

exit 0
