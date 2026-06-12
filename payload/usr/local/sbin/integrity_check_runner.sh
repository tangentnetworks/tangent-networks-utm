#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/integrity_check_runner.sh

PIDFILE="/var/www/htdocs/tn/data/run/webui/integrity_check.pid"

echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
  /usr/local/sbin/integrity_check.sh
  sleep 1
done
