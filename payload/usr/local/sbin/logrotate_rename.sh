#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# Post-rotation hook for newsyslog
# Renames .0 files to _YYYY-MM-DD.log format immediately after rotation
# Usage: logrotate_rename.sh <logfile_path>
#

set -e

LOGFILE="$1"
ROTATION_LOG="/var/www/htdocs/tn/data/logs/rotation/newsyslog_rename.log"

# Validate input
if [ -z "$LOGFILE" ]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: No logfile path provided" >> "$ROTATION_LOG"
  exit 1
fi

# Ensure rotation log directory exists
mkdir -p "$(dirname "$ROTATION_LOG")"

# Calculate yesterday's date (the date of the rotated log)
YESTERDAY=$(perl -e '@t=localtime(time - 86400); printf("%04d-%02d-%02d", $t[5]+1900, $t[4]+1, $t[3]);')

# Construct paths
ROTATED_FILE="${LOGFILE}.0"
BASENAME=$(basename "$LOGFILE")
DIRNAME=$(dirname "$LOGFILE")

# Handle different naming patterns
case "$BASENAME" in
  messages | daemon | authlog | maillog | secure)
    # System logs in /var/log
    NEW_NAME="${BASENAME}_${YESTERDAY}.log"
    ;;
  *.log)
    # Application logs (e.g., doas.log -> doas_YYYY-MM-DD.log)
    BASE="${BASENAME%.log}"
    NEW_NAME="${BASE}_${YESTERDAY}.log"
    ;;
  *)
    # Fallback: use basename as-is
    NEW_NAME="${BASENAME}_${YESTERDAY}.log"
    ;;
esac

NEW_PATH="${DIRNAME}/${NEW_NAME}"

# Perform rename if .0 file exists
if [ -f "$ROTATED_FILE" ]; then
  if mv "$ROTATED_FILE" "$NEW_PATH"; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: Renamed $(basename "$ROTATED_FILE") -> $NEW_NAME" >> "$ROTATION_LOG"

    # Optional: Set permissions to match original (already handled by newsyslog)
    # chmod 644 "$NEW_PATH"

    exit 0
  else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Failed to rename $ROTATED_FILE" >> "$ROTATION_LOG"
    exit 1
  fi
else
  # Not an error - newsyslog might not have created .0 if log was empty
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] SKIP: No .0 file found for $LOGFILE" >> "$ROTATION_LOG"
  exit 0
fi
