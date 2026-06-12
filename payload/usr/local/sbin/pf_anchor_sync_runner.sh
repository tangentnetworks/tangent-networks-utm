#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_anchor_sync_runner.sh
#
# Poll wrapper for pf_anchor_sync.sh.
# Runs every 30 seconds -- provides startup recovery after reboot
# and keeps active-addons.json fresh as a background safety net.
# pf_monitor.sh also calls pf_anchor_sync.sh directly after every
# apply/reset so the UI updates immediately on those events.

PIDFILE="/var/www/htdocs/tn/data/run/webui/pf_anchor_sync.pid"
SCRIPT="/usr/local/sbin/pf_anchor_sync.sh"

echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
  "$SCRIPT" 2>&1
  sleep 30
done
