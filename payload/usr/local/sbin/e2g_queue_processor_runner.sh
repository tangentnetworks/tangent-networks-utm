#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/e2g_queue_processor_runner.sh

PIDFILE="/var/www/htdocs/tn/data/run/webui/e2g_queue_processor.pid"
SCRIPT="/usr/local/sbin/e2g_queue_processor.sh"

# Write the PID of this wrapper script
echo $$ > "$PIDFILE"

# Clean up the PID file on exit or termination
trap "rm -f $PIDFILE" EXIT INT TERM

# Start the target script in the foreground
exec "$SCRIPT"
