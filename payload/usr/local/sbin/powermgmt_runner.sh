#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/powermgmt_runner.sh
# Daemon wrapper for powermgmt.sh
# Follows standard Tangent Networks runner pattern

PIDFILE="/var/www/htdocs/tn/data/run/webui/powermgmt.pid"
SCRIPT="/usr/local/sbin/powermgmt.sh"

echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
  "$SCRIPT" 2>&1
  sleep 2
done
