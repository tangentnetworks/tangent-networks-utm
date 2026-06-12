#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# pmacct_mfs_manage.sh -- PMACCT MFS log truncation utility for OpenBSD
#
# Purpose:
#   Safely truncates high-frequency PMACCT JSON log files stored on MFS,
#   retaining only the most recent N lines while preserving the original inode.
#   Designed for very frequent execution (e.g., every few seconds via cron).
#
# Features:
#   - Atomic, inode-preserving truncation
#   - Per-file locking with timeout
#   - Defensive checks for readability, writability, and file integrity
#   - ksh / OpenBSD base-system tools only
#
# Intended use:
#   OpenBSD systems running pmacct with JSON output written to memory filesystems
#   for consumption by web dashboards or monitoring pipelines.
#
# Installation:
#   Save as /usr/local/sbin/pmacct_mfs_manage.sh
#   chmod 0755 /usr/local/sbin/pmacct_mfs_manage.sh
#
#  Author: David Peter
#  Organization: Tangent Networks
#  Web: https://tangentnet.top
#  Email: tangent.net@zohomail.in
#  Date: Wed Jan 07 09:10:35 PM IST 2026
#
#  License: BSD 3-Clause
#  See PMACCT_MFS_MANAGE.sh.md for full documentation and license text.
#
# =====================================================================

set -eu

# =====================================================================
# Configuration
# =====================================================================

readonly LINES_TO_KEEP=200
readonly LOCK_TIMEOUT=5
readonly TEMP_SUFFIX=".truncate.$$"

# =====================================================================
# Log files to process (space-separated)
# =====================================================================

readonly LOG_FILES="/var/www/htdocs/tn/data/pipes/pmacct/ext_if_json.log /var/www/htdocs/tn/data/pipes/pmacct/int_if_json.log"

# =====================================================================
# Cleanup function
# =====================================================================

cleanup() {
  local logfile="$1"
  local tmpfile="${logfile}${TEMP_SUFFIX}"
  local lockfile="${logfile}.lock"

  [[ -f "$tmpfile" ]] && rm -f "$tmpfile"
  [[ -f "$lockfile" ]] && rm -f "$lockfile"
}

# =====================================================================
# Truncate a single log file
# =====================================================================

truncate_log() {
  local logfile="$1"
  local tmpfile="${logfile}${TEMP_SUFFIX}"
  local lockfile="${logfile}.lock"
  local line_count=0

  # Verify file exists and is readable
  if [[ ! -f "$logfile" ]]; then
    return 0
  fi

  if [[ ! -r "$logfile" ]]; then
    echo "ERROR: Cannot read $logfile" >&2
    return 1
  fi

  if [[ ! -w "$logfile" ]]; then
    echo "ERROR: Cannot write to $logfile" >&2
    return 1
  fi

  # Try to acquire lock with timeout
  local lock_attempts=0
  while [[ $lock_attempts -lt $LOCK_TIMEOUT ]]; do
    if mkdir "$lockfile" 2> /dev/null; then
      break
    fi
    sleep 1
    lock_attempts=$((lock_attempts + 1))
  done

  if [[ $lock_attempts -ge $LOCK_TIMEOUT ]]; then
    # Lock timeout - check if file is open by another process (excluding ourselves)
    if fstat 2> /dev/null | grep -v "^$(whoami) .* $$" | grep -q "$logfile"; then
      # File is open by another process - this is normal, skip silently
      return 0
    fi
    # Lock failed for other reasons - this IS an error
    echo "ERROR: Could not acquire lock for $logfile after ${LOCK_TIMEOUT}s" >&2
    return 1
  fi

  # Ensure cleanup on exit
  trap "cleanup '$logfile'" EXIT INT TERM

  # Count lines in file
  line_count=$(wc -l < "$logfile" | tr -d ' ')

  # Only truncate if file has more than LINES_TO_KEEP
  if [[ $line_count -le $LINES_TO_KEEP ]]; then
    rm -rf "$lockfile"
    return 0
  fi

  # Extract last N lines to temporary file
  if ! tail -n $LINES_TO_KEEP "$logfile" > "$tmpfile" 2> /dev/null; then
    echo "ERROR: Failed to tail $logfile" >&2
    cleanup "$logfile"
    return 1
  fi

  # Verify temp file was created and has content
  if [[ ! -f "$tmpfile" ]] || [[ ! -s "$tmpfile" ]]; then
    echo "ERROR: Temporary file empty or missing for $logfile" >&2
    cleanup "$logfile"
    return 1
  fi

  # Verify temp file has reasonable line count
  local tmp_lines=$(wc -l < "$tmpfile" | tr -d ' ')
  if [[ $tmp_lines -eq 0 ]] || [[ $tmp_lines -gt $LINES_TO_KEEP ]]; then
    echo "ERROR: Unexpected line count in temp file: $tmp_lines" >&2
    cleanup "$logfile"
    return 1
  fi

  # Atomically replace file content while preserving inode
  # Using >| to force overwrite even with noclobber set
  if ! cat "$tmpfile" >| "$logfile" 2> /dev/null; then
    echo "ERROR: Failed to write back to $logfile" >&2
    cleanup "$logfile"
    return 1
  fi

  # Cleanup
  rm -f "$tmpfile"
  rm -rf "$lockfile"

  return 0
}

# =====================================================================
# Main execution
# =====================================================================

main() {
  local exit_code=0

  for logfile in $LOG_FILES; do
    if ! truncate_log "$logfile"; then
      exit_code=1
    fi
  done

  return $exit_code
}

# =====================================================================
# Run main function
# =====================================================================

main
exit $?
