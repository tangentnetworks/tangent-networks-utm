#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# e2g_status_writer.sh
# Detects which e2guardian filter is active by checking crontab
# Writes status JSON for web UI
# Run via cron every minute

PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin"
export PATH

set -eu

# Configuration
CRONTAB_FILE="/etc/crontab"
STATUS_DIR="/var/www/htdocs/tn/data/services/queue/e2gfilters/status"
STATUS_FILE="$STATUS_DIR/active_mode.json"
LOCKFILE="/tmp/e2g_status_writer.lock"

# Prevent concurrent runs
if [ -f "$LOCKFILE" ]; then
  exit 0
fi
touch "$LOCKFILE"
trap "rm -f $LOCKFILE" EXIT INT TERM

# Create status directory if needed
mkdir -p "$STATUS_DIR" 2> /dev/null || true

# Parse crontab to find active e2guardian filter script
ACTIVE_SCRIPT=$(awk -F'/' '/e2g_.*\.sh/ {print $NF}' "$CRONTAB_FILE" 2> /dev/null || echo "")

# Determine mode from script name
case "$ACTIVE_SCRIPT" in
  e2g_adult_filter.sh)
    MODE="general"
    MODE_NAME="General (Adult Mode)"
    DESCRIPTION="Blocks malware and ads, no porn filtering"
    ;;
  e2g_childsafe_filter.sh)
    MODE="childsafe"
    MODE_NAME="ChildSafe (Family Mode)"
    DESCRIPTION="Blocks malware, ads, and adult content"
    ;;
  e2g_user_filter.sh)
    MODE="custom"
    MODE_NAME="Custom (User-Managed)"
    DESCRIPTION="User-defined threat intelligence feeds"
    ;;
  *)
    MODE="none"
    MODE_NAME="No Filter Active"
    DESCRIPTION="No e2guardian filter is currently scheduled"
    ACTIVE_SCRIPT="none"
    ;;
esac

# Parse cron schedule for the active script directly from crontab.
# Line format: minute hour ... /path/to/e2g_*.sh
# Defaults to 10:00 if script is none or parse fails.
CRON_MINUTE=0
CRON_HOUR=10
if [ "$ACTIVE_SCRIPT" != "none" ]; then
  CRON_LINE=$(grep "$ACTIVE_SCRIPT" "$CRONTAB_FILE" 2> /dev/null | grep -v '^\s*#' | head -1)
  if [ -n "$CRON_LINE" ]; then
    CRON_MINUTE=$(echo "$CRON_LINE" | awk '{print $1}')
    CRON_HOUR=$(echo "$CRON_LINE" | awk '{print $2}')
  fi
fi

# Write status JSON
cat > "$STATUS_FILE" << EOF
{
    "mode": "$MODE",
    "mode_name": "$MODE_NAME",
    "description": "$DESCRIPTION",
    "script": "$ACTIVE_SCRIPT",
    "cron_hour": $CRON_HOUR,
    "cron_minute": $CRON_MINUTE,
    "updated": $(date +%s),
    "updated_human": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF

# Set permissions
chmod 644 "$STATUS_FILE" 2> /dev/null || true

exit 0
