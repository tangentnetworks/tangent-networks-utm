#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

PIDFILE="/var/www/htdocs/tn/data/run/webui/dashboard_stats_runner.pid"

echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
  /usr/local/sbin/collectd_exporter.pl cpu memory df interfaces
  sleep 6
done
