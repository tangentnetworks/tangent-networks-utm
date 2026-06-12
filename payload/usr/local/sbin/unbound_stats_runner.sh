#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

PIDFILE="/var/www/htdocs/tn/data/run/webui/unbound_stats_runner.pid"

echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do

  /usr/local/sbin/unbound_stats_collector.pl
  sleep 5
done
