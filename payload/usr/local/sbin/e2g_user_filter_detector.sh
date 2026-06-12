#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# Detects changes in userfeeds.txt and triggers e2g_user_filter.sh

# Absolute paths (outside chroot)
USERFEEDS="/var/www/htdocs/tn/data/services/queue/e2gfilters/userlist/userfeeds.txt"
CHECKSUM_FILE="/var/www/htdocs/tn/data/services/queue/e2gfilters/userlist/.userfeeds.checksum"
PROCESSOR="/usr/local/sbin/e2g_user_filter.sh"
LOGFILE="/var/www/htdocs/tn/data/services/queue/e2gfilters/outcome/detector.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOGFILE")" 2> /dev/null || true

# Skip if userfeeds.txt doesn't exist
if [ ! -f "$USERFEEDS" ]; then
  exit 0
fi

# Calculate current checksum
CURRENT_SUM=$(cksum "$USERFEEDS" 2> /dev/null | awk '{print $1}')

# Read previous checksum
PREVIOUS_SUM=""
if [ -f "$CHECKSUM_FILE" ]; then
  PREVIOUS_SUM=$(cat "$CHECKSUM_FILE")
fi

# If changed, run processor
if [ "$CURRENT_SUM" != "$PREVIOUS_SUM" ]; then
  echo "[$(date)] userfeeds.txt changed (checksum: $CURRENT_SUM), triggering processor..." >> "$LOGFILE"

  # Run processor in background (non-blocking)
  "$PROCESSOR" >> "$LOGFILE" 2>&1 &
  PROCESSOR_PID=$!

  # Update checksum
  echo "$CURRENT_SUM" > "$CHECKSUM_FILE"

  echo "[$(date)] Processor launched in background (PID: $PROCESSOR_PID)" >> "$LOGFILE"
fi

exit 0
