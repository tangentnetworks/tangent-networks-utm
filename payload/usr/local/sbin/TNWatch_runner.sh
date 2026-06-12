#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# TNWatch Runner
# /usr/local/sbin/TNWatch_runner.sh
#
# Called by cron every 5 minutes.
# 1. Parse all log sources (incremental)
# 2. Check alert rules -- send immediate emails if triggered
#
# Daily digest (6 AM) is a separate cron entry calling --send-digest directly.

TNWATCH=/usr/local/sbin/TNWatch.pl
LOG=/var/log/TNWatch_runner.log
LOCK=/var/run/TNWatch.lock

# === Lock: prevent overlapping runs ###
if [ -f "$LOCK" ]; then
  pid=$(cat "$LOCK" 2> /dev/null)
  if [ -n "$pid" ] && kill -0 "$pid" 2> /dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') TNWatch_runner already running (pid $pid), skipping" >> "$LOG"
    exit 0
  fi
  # Stale lock
  rm -f "$LOCK"
fi
echo $$ > "$LOCK"

# === Cleanup on exit ###
cleanup() { rm -f "$LOCK"; }
trap cleanup EXIT INT TERM

# === Run ===
TS=$(date '+%Y-%m-%d %H:%M:%S')
echo "$TS Starting TNWatch run" >> "$LOG"

# Parse all sources (incremental -- only reads new log lines)
$TNWATCH --parse-all >> "$LOG" 2>&1
PARSE_RC=$?

if [ $PARSE_RC -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARNING: parse-all exited $PARSE_RC" >> "$LOG"
fi

# Check alert rules -- sends email immediately if any rule fires
$TNWATCH --check-alerts >> "$LOG" 2>&1
ALERT_RC=$?

if [ $ALERT_RC -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARNING: check-alerts exited $ALERT_RC" >> "$LOG"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') TNWatch run complete" >> "$LOG"
exit 0
