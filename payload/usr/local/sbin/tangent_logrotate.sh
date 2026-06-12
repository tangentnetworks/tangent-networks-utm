#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# =====================================================================
#  Tangent Log Rotation Monitor
# =====================================================================
#
#  Deterministic, self-healing log rotation framework for OpenBSD
#  Designed for unattended operation across reboots and sysupgrades
#
#  Features:
#    - Once-per-calendar-day rotation with triple verification
#    - Fixed retention enforcement (default: 7 days)
#    - PID-based concurrency protection
#    - Automatic /etc/rc reintegration after sysupgrade
#    - Safe handling of empty and missing logs
#    - Machine-readable metadata output for dashboards
#
#  Execution Model:
#    - @reboot via /etc/rc (pre-daemon startup)
#    - Every 20 minutes via /etc/crontab
#
#  Script Path:
#    /usr/local/sbin/tangent_logrotate.sh
#
#  Author: David Peter
#  Organization: Tangent Networks
#  Web: https://tangentnet.top
#  Email: tangent.net@zohomail.in
#  Date: Wed Jan 07 09:10:35 PM IST 2026
#
#  License: BSD 3-Clause
#  See ROTATION.md for full documentation and license text.
#
# =====================================================================

set -eu

# Configuration
PID_FILE="/var/www/htdocs/tn/data/run/tangent_logrotate.pid"
STAMP_FILE="/var/www/htdocs/tn/data/logs/bootlog/.rotation_stamp"
LOG_FILE="/var/www/htdocs/tn/data/logs/rotation/monitor.log"
META_FILE="/var/www/htdocs/tn/data/logs/.rotation_meta"
NEWSYSLOG_RENAME="/usr/local/sbin/logrotate_rename.sh"
RC_FILE="/etc/rc"
RC_BACKUP="/usr/local/share/tangent/rc.backup"

# Retention policy
RETENTION_DAYS=7

# Ensure directories exist
mkdir -p "$(dirname "$PID_FILE")" "$(dirname "$STAMP_FILE")" "$(dirname "$LOG_FILE")" "$(dirname "$RC_BACKUP")"

# Logging function
log_msg() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Cleanup function
cleanup() {
  rm -f "$PID_FILE"
}

trap cleanup EXIT INT TERM

# === SELF-HEALING: CHECK /etc/rc INTEGRATION ===
check_rc_integration() {
  local RC_MARKER="# Tangent Log Rotation Hook"
  local RC_SCRIPT_PATH="/usr/local/sbin/tangent_logrotate.sh"

  # Check if both marker AND script call exist (complete integration check)
  if grep -q "$RC_MARKER" "$RC_FILE" 2> /dev/null \
    && grep -q "$RC_SCRIPT_PATH" "$RC_FILE" 2> /dev/null; then
    # Integration is complete, nothing to do
    return 0
  fi

  log_msg "WARN: /etc/rc missing or incomplete Tangent rotation hook - attempting repair"

  # Backup current rc file
  if [ -f "$RC_FILE" ]; then
    cp -p "$RC_FILE" "$RC_BACKUP.$(date +%s)" 2> /dev/null || true
    log_msg "INFO: Backed up /etc/rc to $RC_BACKUP.$(date +%s)"
  fi

  # Remove any existing incomplete/duplicate Tangent blocks first
  local TMPFILE_CLEAN="/tmp/rc.clean.$"
  awk '
        /^# Tangent Log Rotation Hook/ {
            # Start of Tangent block - skip until we find the closing fi
            in_tangent_block = 1
            next
        }
        in_tangent_block {
            # Skip lines until we find the closing fi
            if ($0 ~ /^fi$/) {
                in_tangent_block = 0
            }
            next
        }
        # Print all non-Tangent lines
        { print }
    ' "$RC_FILE" > "$TMPFILE_CLEAN"

  # Now inject the clean block at the right location.
  # Anchor to 'reorder_libs 2>&1 |&' -- this line is invariant across sysupgrades.
  # Injecting after reorder_libs ensures the dynamic linker cache is fully rebuilt
  # before logrotate runs. start_daemon ordering may change; reorder_libs will not.
  if grep -q "reorder_libs 2>&1 |&" "$TMPFILE_CLEAN" 2> /dev/null; then
    local TMPFILE="/tmp/rc.tmp.$"
    awk '/reorder_libs 2>&1 \|&/ && !inserted {
            print
            print ""
            print "# Tangent Log Rotation Hook"
            print "# Rotate logs before daemons start (Tangent custom)"
            print "if [ -x /usr/local/sbin/tangent_logrotate.sh ]; then"
            print "        echo -n '\''rotating logs'\''"
            print "        /usr/local/sbin/tangent_logrotate.sh >/dev/null 2>&1"
            print "        echo '\''.'\''"
            print "fi"
            inserted = 1
            next
        }
        { print }' "$TMPFILE_CLEAN" > "$TMPFILE"

    # Atomic replacement
    if [ -s "$TMPFILE" ]; then
      chmod 644 "$TMPFILE"
      mv -f "$TMPFILE" "$RC_FILE"
      log_msg "SUCCESS: Repaired /etc/rc with rotation hook"
    else
      log_msg "ERROR: Failed to create patched /etc/rc"
      rm -f "$TMPFILE"
    fi
    rm -f "$TMPFILE_CLEAN"
  else
    log_msg "ERROR: Could not find injection point in /etc/rc (missing 'reorder_libs 2>&1 |&' line)"
    rm -f "$TMPFILE_CLEAN"
  fi
}

# Run RC integration check
check_rc_integration

# === LOCK MECHANISM ===
if [ -f "$PID_FILE" ]; then
  OLD_PID=$(cat "$PID_FILE" 2> /dev/null || echo "")
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2> /dev/null; then
    # Process is still running, exit silently
    exit 0
  else
    # Stale PID file, remove it
    rm -f "$PID_FILE"
  fi
fi

# Create new PID file
echo $$ > "$PID_FILE"

# === DATE CALCULATIONS ===
TODAY=$(date '+%Y-%m-%d')
YESTERDAY=$(date -r $(($(date +%s) - 86400)) '+%Y-%m-%d')
PURGE_DATE=$(date -r $(($(date +%s) - (RETENTION_DAYS * 86400))) '+%Y-%m-%d')

log_msg "INFO: Rotation check started (today: $TODAY, purge: <$PURGE_DATE)"

# === PURGE OLD ARCHIVES (>7 DAYS) ===
log_msg "INFO: Purging archives older than $RETENTION_DAYS days (before $PURGE_DATE)"

PURGE_COUNT=0
PURGE_TEMP="/tmp/purge_list.$"

# Build list of files to purge
find /var/www/htdocs/tn/data/logs -type f -name "*_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].log" > "$PURGE_TEMP"

# Process the list (no subshell, so PURGE_COUNT persists)
while IFS= read -r ARCHIVE; do
  [ -z "$ARCHIVE" ] && continue

  # Extract date from filename (format: *_YYYY-MM-DD.log)
  ARCHIVE_DATE=$(basename "$ARCHIVE" | sed -E 's/.*_([0-9]{4}-[0-9]{2}-[0-9]{2})\.log$/\1/')

  # Compare dates (string comparison works for YYYY-MM-DD format)
  if [ "$ARCHIVE_DATE" \< "$PURGE_DATE" ]; then
    log_msg "PURGE: Deleting $ARCHIVE (date: $ARCHIVE_DATE)"
    rm -f "$ARCHIVE"
    PURGE_COUNT=$((PURGE_COUNT + 1))
  fi
done < "$PURGE_TEMP"

rm -f "$PURGE_TEMP"

if [ $PURGE_COUNT -gt 0 ]; then
  log_msg "INFO: Purged $PURGE_COUNT old archive(s)"
fi

# === TRIPLE VERIFICATION ===

# Check 1: Stamp file
if [ -f "$STAMP_FILE" ]; then
  LAST_ROTATION=$(cat "$STAMP_FILE" 2> /dev/null || echo "")
  if [ "$LAST_ROTATION" = "$TODAY" ]; then
    log_msg "INFO: Already rotated today (stamp file check). Exiting."
    exit 0
  fi
  log_msg "INFO: Stamp file shows last rotation: $LAST_ROTATION"
fi

# Check 2: Filesystem verification (look for yesterday's archived logs)
set -A SAMPLE_LOGS \
  "/var/www/htdocs/tn/data/logs/doas/doas_${YESTERDAY}.log" \
  "/var/www/htdocs/tn/data/logs/system/messages_${YESTERDAY}.log" \
  "/var/log/authlog.0"

FOUND_COUNT=0
for SAMPLE in "${SAMPLE_LOGS[@]}"; do
  if [ -f "$SAMPLE" ]; then
    FOUND_COUNT=$((FOUND_COUNT + 1))
  fi
done

if [ $FOUND_COUNT -ge 2 ]; then
  log_msg "INFO: Found existing rotated logs for $YESTERDAY. Updating stamp file."
  echo "$TODAY" > "$STAMP_FILE"
  exit 0
fi

# Check 3: If we reach here, rotation is needed
log_msg "INFO: No rotation detected for today. Proceeding with rotation."

# === LOG FILE DEFINITIONS ===
# All logs that need date-stamped rotation

set -A SYSTEM_LOGS \
  "/var/log/authlog" \
  "/var/log/maillog" \
  "/var/log/secure" \
  "/var/cron/log"

set -A CUSTOM_SYSTEM_LOGS \
  "/var/www/htdocs/tn/data/logs/system/messages" \
  "/var/www/htdocs/tn/data/logs/system/daemon"

set -A APPLICATION_LOGS \
  "/var/www/htdocs/tn/data/logs/doas/doas.log" \
  "/var/www/htdocs/tn/data/logs/dhcpd/dhcpd.log" \
  "/var/www/htdocs/tn/data/logs/unbound/unbound.log" \
  "/var/www/htdocs/tn/data/logs/rad/rad.log" \
  "/var/www/htdocs/tn/data/logs/collectd/collectd.log" \
  "/var/www/htdocs/tn/data/logs/sslproxy/sslproxy.log" \
  "/var/www/htdocs/tn/data/logs/sslproxy/sslproxy_connect.log" \
  "/var/www/htdocs/tn/data/logs/sockd/sockd.log" \
  "/var/www/htdocs/tn/data/logs/p3scan/p3scan.log" \
  "/var/www/htdocs/tn/data/logs/smtp-gated/smtp-gated.log" \
  "/var/www/htdocs/tn/data/logs/spamd/spamd.log" \
  "/var/www/htdocs/tn/data/logs/snort/alert.log" \
  "/var/www/htdocs/tn/data/logs/snort/snort.log" \
  "/var/www/htdocs/tn/data/logs/snort/snortinline.log" \
  "/var/www/htdocs/tn/data/logs/snortsentry/snortsentry.log" \
  "/var/www/htdocs/tn/data/logs/e2guardian/access.log" \
  "/var/www/htdocs/tn/data/logs/e2guardian/e2guardian.log" \
  "/var/www/htdocs/tn/data/logs/httpd/httpd_access.log" \
  "/var/www/htdocs/tn/data/logs/httpd/httpd_error.log" \
  "/var/www/htdocs/tn/data/logs/pmacct/pmacct.log" \
  "/var/www/htdocs/tn/data/logs/imspector/imspector.log" \
  "/var/www/htdocs/tn/data/logs/ftp-proxy/ftp-proxy.log" \
  "/var/www/htdocs/tn/data/logs/waf/access.log" \
  "/var/www/htdocs/tn/data/logs/waf/error.log" \
  "/var/www/htdocs/tn/data/logs/waf/security.log" \
  "/var/www/htdocs/tn/data/logs/csp/security.log"

# Combine all logs
set -A ALL_LOGS "${SYSTEM_LOGS[@]}" "${CUSTOM_SYSTEM_LOGS[@]}" "${APPLICATION_LOGS[@]}"

# === ROTATION LOGIC ===
ROTATION_ERRORS=0
ROTATED_COUNT=0
SKIPPED_EMPTY=""
SKIPPED_MISSING=""

for LOGFILE in "${ALL_LOGS[@]}"; do
  # Skip if log file doesn't exist
  if [ ! -f "$LOGFILE" ]; then
    log_msg "SKIP: $LOGFILE does not exist"
    LOGNAME=$(basename "$LOGFILE" .log)
    if [ -z "$SKIPPED_MISSING" ]; then
      SKIPPED_MISSING="$LOGNAME"
    else
      SKIPPED_MISSING="$SKIPPED_MISSING,$LOGNAME"
    fi
    continue
  fi

  # Check if file is empty (size = 0)
  FILESIZE=$(stat -f %z "$LOGFILE" 2> /dev/null || echo "0")
  if [ "$FILESIZE" -eq 0 ]; then
    log_msg "SKIP: $LOGFILE is empty (0 bytes) - not rotating"
    LOGNAME=$(basename "$LOGFILE" .log)
    if [ -z "$SKIPPED_EMPTY" ]; then
      SKIPPED_EMPTY="$LOGNAME"
    else
      SKIPPED_EMPTY="$SKIPPED_EMPTY,$LOGNAME"
    fi
    continue
  fi

  log_msg "INFO: Rotating $LOGFILE ($FILESIZE bytes)"

  # Copy current log to .0, then truncate
  if cp -p "$LOGFILE" "${LOGFILE}.0" 2>&1 | tee -a "$LOG_FILE"; then
    if : > "$LOGFILE" 2>&1 | tee -a "$LOG_FILE"; then
      # Rename .0 to date-stamped format
      if [ -x "$NEWSYSLOG_RENAME" ]; then
        if "$NEWSYSLOG_RENAME" "$LOGFILE" 2>&1 | tee -a "$LOG_FILE"; then
          ROTATED_COUNT=$((ROTATED_COUNT + 1))
          log_msg "SUCCESS: Rotated and renamed $(basename "$LOGFILE")"
        else
          log_msg "ERROR: Failed to rename ${LOGFILE}.0"
          ROTATION_ERRORS=$((ROTATION_ERRORS + 1))
        fi
      else
        log_msg "ERROR: Rename script not found or not executable: $NEWSYSLOG_RENAME"
        ROTATION_ERRORS=$((ROTATION_ERRORS + 1))
      fi
    else
      log_msg "ERROR: Failed to truncate $LOGFILE"
      ROTATION_ERRORS=$((ROTATION_ERRORS + 1))
    fi
  else
    log_msg "ERROR: Failed to copy $LOGFILE to ${LOGFILE}.0"
    ROTATION_ERRORS=$((ROTATION_ERRORS + 1))
  fi
done

# Special handling for httpd logs (send signal after rotation)
if [ -f "/var/www/htdocs/tn/data/logs/httpd/httpd_access.log" ] || [ -f "/var/www/htdocs/tn/data/logs/httpd/httpd_error.log" ]; then
  log_msg "INFO: Sending USR1 signal to httpd"
  if pkill -USR1 -u root -U root -x httpd 2>&1 | tee -a "$LOG_FILE"; then
    log_msg "SUCCESS: httpd signaled"
  else
    log_msg "WARN: Failed to signal httpd (may not be running)"
  fi
fi

# === GENERATE METADATA FILE ===
TOTAL_SIZE_KB=0
ARCHIVES_COUNT=0

# Calculate total archive size and count
for ARCHIVE in /var/www/htdocs/tn/data/logs/*/*_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].log; do
  if [ -f "$ARCHIVE" ]; then
    ARCHIVES_COUNT=$((ARCHIVES_COUNT + 1))
    ARCHIVE_SIZE=$(stat -f %z "$ARCHIVE" 2> /dev/null || echo "0")
    TOTAL_SIZE_KB=$((TOTAL_SIZE_KB + (ARCHIVE_SIZE / 1024)))
  fi
done

# Write metadata file
cat > "$META_FILE" << EOF
LAST_ROTATION=$TODAY
ARCHIVES_COUNT=$ARCHIVES_COUNT
TOTAL_SIZE_KB=$TOTAL_SIZE_KB
SKIPPED_EMPTY=$SKIPPED_EMPTY
SKIPPED_MISSING=$SKIPPED_MISSING
RETENTION_DAYS=$RETENTION_DAYS
EOF

log_msg "INFO: Metadata updated: $ARCHIVES_COUNT archives, ${TOTAL_SIZE_KB}KB total"

# === ATOMIC SUCCESS MARKING ===
if [ $ROTATION_ERRORS -eq 0 ]; then
  echo "$TODAY" > "$STAMP_FILE"
  log_msg "SUCCESS: Rotation complete. Rotated $ROTATED_COUNT files. Stamp file updated."
  exit 0
else
  log_msg "ERROR: Rotation completed with $ROTATION_ERRORS errors. Stamp file NOT updated. Will retry on next run."
  exit 1
fi
