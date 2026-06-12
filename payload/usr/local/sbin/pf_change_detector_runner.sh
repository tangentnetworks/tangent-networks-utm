#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# Daemon wrapper for pf_change_detector.sh

PIDFILE="/var/www/htdocs/tn/data/run/webui/pf_change_detector.pid"
SCRIPT="/usr/local/sbin/pf_change_detector.sh"

echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
  "$SCRIPT" 2>&1
  sleep 2
done
