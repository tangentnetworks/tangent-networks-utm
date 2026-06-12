#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_validator_runner.sh

PIDFILE="/var/www/htdocs/tn/data/run/webui/pf_validator.pid"
TRIGGER_DIR="/var/www/htdocs/tn/data/services/queue/pf-rules/triggers"

echo $$ > "$PIDFILE"

trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
  if ls "$TRIGGER_DIR"/*-requested > /dev/null 2>&1; then
    /usr/local/sbin/pf_validator.pl 2>&1
  fi
  sleep 2
done
