#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# Daily cleanup script for date-stamped log archives
# Deletes logs older than retention period (7 days default)
# Run via cron: 0 11 * * * /usr/local/sbin/cleanup_old_logs.sh
#

set -eu

LOG_BASE="/var/www/htdocs/tn/data/logs"
SYSTEM_LOG_DIR="/var/log"
RETENTION_DAYS=7
CLEANUP_LOG="/var/www/htdocs/tn/data/logs/rotation/cleanup.log"

# Ensure log directory exists
mkdir -p "$(dirname "$CLEANUP_LOG")"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: Starting log cleanup (retention: ${RETENTION_DAYS} days)" >> "$CLEANUP_LOG"

# Check disk usage before cleanup
DISK_USAGE=$(df -h /var/www/htdocs/tn/data | awk 'NR==2 {print $5}' | sed 's/%//')
echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: Disk usage before cleanup: ${DISK_USAGE}%" >> "$CLEANUP_LOG"

if [ "$DISK_USAGE" -gt 85 ]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: Disk usage critical at ${DISK_USAGE}%" >> "$CLEANUP_LOG"
fi

# Cleanup application logs
DELETED_COUNT=0
if [ -d "$LOG_BASE" ]; then
  # Find all date-stamped logs older than retention period
  find "$LOG_BASE" -type f -name "*_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].log" -mtime "+${RETENTION_DAYS}" 2> /dev/null | while IFS= read -r OLD_FILE; do
    if rm "$OLD_FILE" 2> /dev/null; then
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: Deleted $(basename "$OLD_FILE")" >> "$CLEANUP_LOG"
      DELETED_COUNT=$((DELETED_COUNT + 1))
    else
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Failed to delete $(basename "$OLD_FILE")" >> "$CLEANUP_LOG"
    fi
  done
fi

# Cleanup system logs in /var/log
if [ -d "$SYSTEM_LOG_DIR" ]; then
  for SYSLOG in authlog daemon messages maillog secure; do
    find "$SYSTEM_LOG_DIR" -type f -name "${SYSLOG}_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].log" -mtime "+${RETENTION_DAYS}" 2> /dev/null | while IFS= read -r OLD_FILE; do
      if rm "$OLD_FILE" 2> /dev/null; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: Deleted system log $(basename "$OLD_FILE")" >> "$CLEANUP_LOG"
        DELETED_COUNT=$((DELETED_COUNT + 1))
      else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Failed to delete $(basename "$OLD_FILE")" >> "$CLEANUP_LOG"
      fi
    done
  done
fi

# Check disk usage after cleanup
DISK_USAGE_AFTER=$(df -h /var/www/htdocs/tn/data | awk 'NR==2 {print $5}' | sed 's/%//')
echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: Disk usage after cleanup: ${DISK_USAGE_AFTER}%" >> "$CLEANUP_LOG"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: Cleanup complete" >> "$CLEANUP_LOG"
echo "" >> "$CLEANUP_LOG"

# Rotate cleanup log itself if it gets too large (>10MB)
if [ -f "$CLEANUP_LOG" ]; then
  LOG_SIZE=$(stat -f %z "$CLEANUP_LOG" 2> /dev/null || echo 0)
  if [ "$LOG_SIZE" -gt 10485760 ]; then
    mv "$CLEANUP_LOG" "${CLEANUP_LOG}.old"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: Rotated cleanup log" >> "$CLEANUP_LOG"
  fi
fi
