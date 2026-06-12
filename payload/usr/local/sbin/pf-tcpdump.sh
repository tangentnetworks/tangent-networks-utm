#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# Daily PFLOG archival to persistent storage
# MFS keeps only last 100 lines for real-time display
# 7-day uncompressed retention for fast Perl search/filter

set -e

# Persistent archive location (NOT in MFS)
ARCHIVE_DIR="/var/www/htdocs/tn/data/archive/logs/system"
LOGDATE=$(date +%Y-%m-%d)
ARCHIVE_FILE="${ARCHIVE_DIR}/pflog_${LOGDATE}.log"

# Real-time processing location (in MFS for WebUI)
MFS_LOGFILE="/var/www/htdocs/tn/data/logs/pf/pflog1.log"
MFS_TMPFILE="/var/www/htdocs/tn/data/logs/pf/pflog1.log.tmp"
TAIL_LINES=500
RETENTION_DAYS=7

TCPDUMP="/usr/sbin/tcpdump"
PFIF="pflog1"
PIDFILE="/var/run/pf-tcpdump.pid"

# Ensure archive directory exists
mkdir -p "$ARCHIVE_DIR"
chown www:wheel "$ARCHIVE_DIR"
chmod 755 "$ARCHIVE_DIR"

# Ensure today's archive file exists
touch "$ARCHIVE_FILE"
chown www:wheel "$ARCHIVE_FILE"
chmod 644 "$ARCHIVE_FILE"

# Ensure MFS logfile exists
mkdir -p "$(dirname "$MFS_LOGFILE")"
touch "$MFS_LOGFILE"
chown www:wheel "$MFS_LOGFILE"
chmod 644 "$MFS_LOGFILE"

# Function to start tcpdump
start_tcpdump() {
  # Kill any existing tcpdump on pflog1
  pkill -f "$TCPDUMP.*-i $PFIF" 2> /dev/null || true
  sleep 1

  # Start tcpdump - discard stderr (only metadata), keep stdout (actual packets)
  # Use subshell to properly background the entire pipeline
  ($TCPDUMP -l -n -e -ttt -i "$PFIF" 2> /dev/null \
    | tee -a "$ARCHIVE_FILE" >> "$MFS_LOGFILE") &

  # Save PID of the subshell
  echo $! > "$PIDFILE"
  echo "Started tcpdump pipeline (PID: $(cat "$PIDFILE"))"
}

# Check if tcpdump is running
if [ -f "$PIDFILE" ]; then
  RUNNING_PID=$(cat "$PIDFILE" 2> /dev/null || echo "")
  if [ -n "$RUNNING_PID" ] && kill -0 "$RUNNING_PID" 2> /dev/null; then
    # Process is running
    # Check if it's a new day (need to rotate to new file)
    # Check today's archive directly first -- avoids false rotation
    # trigger on first boot when archive directory is empty
    if [ -f "$ARCHIVE_FILE" ]; then
      CURRENT_DATE="$LOGDATE"
    else
      CURRENT_DATE=$(ls -t "$ARCHIVE_DIR"/pflog_*.log 2> /dev/null \
        | head -1 \
        | grep -o '[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}' \
        || echo "")
    fi

    if [ "$CURRENT_DATE" != "$LOGDATE" ]; then
      echo "New day detected, rotating to $ARCHIVE_FILE"
      pkill -P "$RUNNING_PID" 2> /dev/null || true
      kill "$RUNNING_PID" 2> /dev/null || true
      pkill -f "$TCPDUMP.*-i $PFIF" 2> /dev/null || true
      rm -f "$PIDFILE"
      sleep 2
      > "$MFS_LOGFILE" # Truncate MFS file for new day
      start_tcpdump
      exit 0
    fi

    # Truncate MFS to last 500 lines (in-memory operation)
    LINE_COUNT=$(wc -l < "$MFS_LOGFILE" 2> /dev/null || echo 0)
    if [ "$LINE_COUNT" -gt "$((TAIL_LINES + 50))" ]; then
      tail -n "$TAIL_LINES" "$MFS_LOGFILE" > "$MFS_TMPFILE"
      mv "$MFS_TMPFILE" "$MFS_LOGFILE"
      chown www:wheel "$MFS_LOGFILE"
      chmod 644 "$MFS_LOGFILE"
    fi
  else
    # PID file exists but process is dead
    echo "Stale PID file, restarting tcpdump"
    rm -f "$PIDFILE"
    pkill -f "$TCPDUMP.*-i $PFIF" 2> /dev/null || true
    start_tcpdump
  fi
else
  # No PID file, start tcpdump
  echo "No tcpdump running, starting..."
  pkill -f "$TCPDUMP.*-i $PFIF" 2> /dev/null || true
  start_tcpdump
fi

# Delete uncompressed logs older than 7 days
find "$ARCHIVE_DIR" -name "pflog_*.log" -mtime +${RETENTION_DAYS} -delete 2> /dev/null || true

exit 0
