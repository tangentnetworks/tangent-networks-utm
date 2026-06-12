#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_log_cleanup.sh
# Nuclear cleanup of /var/www/tmp logs
# Run via cron or manually

LOG_DIR="/var/www/tmp"
MAX_AGE=7

find "$LOG_DIR" -name "*.log" -mtime +$MAX_AGE -delete

echo "[$(date)] Cleaned logs older than $MAX_AGE days"
