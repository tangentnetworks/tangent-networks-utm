#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/unbound_queue_runner.sh

PIDFILE="/var/www/htdocs/tn/data/run/webui/unbound_queue_runner.pid"
SCRIPT="/usr/local/sbin/manage_unbound.sh"
QUEUE_DIR="/var/www/htdocs/tn/data/services/queue/unbound"

# Ensure directories exist
mkdir -p "$(dirname "$PIDFILE")"
if [ ! -d "$QUEUE_DIR" ]; then
  mkdir -p "$QUEUE_DIR"
  chmod 755 "$QUEUE_DIR"
  chown www:www "$QUEUE_DIR"
fi

# Write PID (replaces truncate)
truncate -s0 "$PIDFILE"

# Cleanup on exit
trap "rm -f $PIDFILE" EXIT INT TERM

# Main loop
while true; do
  "$SCRIPT" 2>&1
  sleep 2
done
