#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

PIDFILE="/var/www/htdocs/tn/data/run/webui/pflog_maint.pid"

echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
  /usr/local/sbin/pf-tcpdump.sh
  sleep 60
done
