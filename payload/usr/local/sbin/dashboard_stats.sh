#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/dashboard_stats.sh
# Optimized metrics exporter

PIDFILE="/var/www/htdocs/tn/data/tmp/dashboard_stats.pid"
INTERVAL=9
MAX_FAILURES=5
failure_count=0

# Function to check if script is already running
check_running() {
  if [ -f "$PIDFILE" ]; then
    old_pid=$(cat "$PIDFILE")
    if kill -0 "$old_pid" 2> /dev/null; then
      logger -t collectd_exporter "Already running (PID $old_pid)"
      exit 1
    else
      rm -f "$PIDFILE"
    fi
  fi
}

# Function to cleanup on exit
cleanup() {
  logger -t collectd_exporter "Daemon stopping (PID $$)"
  rm -f "$PIDFILE"
  exit 0
}

# Trap signals for clean shutdown
trap cleanup INT TERM

# Initial checks
check_running
echo $$ > "$PIDFILE"
logger -t collectd_exporter "Daemon started (PID $$, interval: ${INTERVAL}s)"

# Main loop
while true; do

  error_output=$(/usr/local/sbin/collectd_exporter.pl cpu memory df interfaces swap 2>&1 > /dev/null)

  if [ $? -eq 0 ]; then
    # Success: reset counter and stay silent
    failure_count=0
  else

    failure_count=$((failure_count + 1))
    logger -t collectd_exporter "ERROR: Export failed ($error_output) - Attempt $failure_count/$MAX_FAILURES"

    if [ "$failure_count" -ge "$MAX_FAILURES" ]; then
      logger -t collectd_exporter "CRITICAL: Max failures reached. Exiting."
      cleanup
    fi

    sleep 30
    continue
  fi

  sleep "$INTERVAL"
done
