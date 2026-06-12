#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_asn_runner.sh
#
# Poll loop for pf_asn_lookup_runner.sh
# Watches for request files and dispatches the runner.
# Runs as root. Started from rc.local via start_service().
#
# Poll interval: 1 second (fast enough for interactive use —
# the user is waiting for a modal to appear)

PIDFILE="/var/www/htdocs/tn/data/run/webui/pf_asn_lookup.pid"
MAINSCRIPT="/usr/local/sbin/pf_asn.sh"
REQUEST_DIR="/var/www/htdocs/tn/data/services/queue/pf-rules/asn-lookup/request"

echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE" EXIT INT TERM

while true; do
  # Only invoke runner if a request file exists
  if ls "$REQUEST_DIR"/AS* > /dev/null 2>&1; then
    "$MAINSCRIPT" 2>&1
  fi
  sleep 1
done
