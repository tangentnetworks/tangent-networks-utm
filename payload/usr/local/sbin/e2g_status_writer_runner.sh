#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# Daemon wrapper for e2g_status_writer.sh

PIDFILE="/var/www/htdocs/tn/data/run/webui/e2g_status_writer.pid"
SCRIPT="/usr/local/sbin/e2g_status_writer.sh"

echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
  "$SCRIPT" 2>&1
  sleep 2
done
