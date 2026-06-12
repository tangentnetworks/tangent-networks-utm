#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/manage_unbound.sh
# Processes Unbound queue requests and executes unbound-control commands
# Called by unbound_queue_runner.sh

set -e

# Paths (outside chroot)
REQUEST_DIR="/var/www/htdocs/tn/data/services/queue/unbound/request"
OUTCOME_DIR="/var/www/htdocs/tn/data/services/queue/unbound/outcome"
LOG_DIR="/var/www/tmp"

# Log file
LOGFILE="$LOG_DIR/manage_unbound.log"

# Function to log messages
log_message() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOGFILE"
}

# Function to write outcome - ALWAYS use jq for proper JSON encoding
write_outcome() {
  local request_id="$1"
  local success="$2"
  local output="$3"
  local error="$4"

  local outcome_file="$OUTCOME_DIR/${request_id}.json"

  # Use jq to properly build JSON (handles ALL escaping correctly)
  if [ "$success" = "true" ]; then
    jq -n \
      --arg rid "$request_id" \
      --arg out "$output" \
      --argjson ts "$(date +%s)" \
      '{success: true, request_id: $rid, output: $out, timestamp: $ts}' \
      > "$outcome_file"
  else
    jq -n \
      --arg rid "$request_id" \
      --arg err "$error" \
      --arg out "$output" \
      --argjson ts "$(date +%s)" \
      '{success: false, request_id: $rid, error: $err, output: $out, timestamp: $ts}' \
      > "$outcome_file"
  fi

  log_message "Wrote outcome for request $request_id (success=$success)"
}

# Function to execute unbound-control command
execute_unbound_command() {
  local action="$1"
  local domain="$2"
  local output=""
  local exit_code=0

  case "$action" in
    flush_all)
      log_message "Executing: unbound-control flush_zone ."
      output=$(unbound-control flush_zone . 2>&1) || exit_code=$?
      ;;
    flush_domain)
      if [ -z "$domain" ]; then
        echo "Domain parameter required"
        return 1
      fi
      log_message "Executing: unbound-control flush_zone $domain"
      output=$(unbound-control flush_zone "$domain" 2>&1) || exit_code=$?
      ;;
    dump_cache)
      log_message "Executing: unbound-control dump_cache"
      output=$(unbound-control dump_cache 2>&1) || exit_code=$?
      ;;
    reload)
      log_message "Executing: unbound-control reload"
      output=$(unbound-control reload 2>&1) || exit_code=$?
      ;;
    lookup)
      if [ -z "$domain" ]; then
        echo "Domain parameter required"
        return 1
      fi
      log_message "Executing: unbound-control lookup $domain"
      output=$(unbound-control lookup "$domain" 2>&1) || exit_code=$?
      ;;
    *)
      echo "Unknown action: $action"
      return 1
      ;;
  esac

  if [ $exit_code -ne 0 ]; then
    log_message "Command failed with exit code $exit_code"
    echo "$output"
    return $exit_code
  fi

  log_message "Command completed successfully"
  echo "$output"
  return 0
}

# Main processing loop
process_requests() {
  # Check if any request files exist
  local request_count=$(ls -1 "$REQUEST_DIR"/*.json 2> /dev/null | wc -l)

  if [ "$request_count" -eq 0 ]; then
    # No requests - exit immediately (keeps system lean)
    exit 0
  fi

  log_message "Found $request_count request(s) to process"

  # Process each request file
  for request_file in "$REQUEST_DIR"/*.json; do
    if [ ! -f "$request_file" ]; then
      continue
    fi

    local filename=$(basename "$request_file")
    local request_id="${filename%.json}"

    log_message "Processing request: $request_id"

    # Read request JSON (simple extraction)
    local action=$(grep -o '"action"[[:space:]]*:[[:space:]]*"[^"]*"' "$request_file" | cut -d'"' -f4)
    local domain=$(grep -o '"domain"[[:space:]]*:[[:space:]]*"[^"]*"' "$request_file" | cut -d'"' -f4)

    if [ -z "$action" ]; then
      log_message "ERROR: No action found in request $request_id"
      write_outcome "$request_id" "false" "" "No action specified"
      rm -f "$request_file"
      continue
    fi

    log_message "Action: $action, Domain: ${domain:-N/A}"

    # Execute command
    local output=""
    local success="true"
    local error=""

    output=$(execute_unbound_command "$action" "$domain" 2>&1) || {
      success="false"
      error="Command execution failed"
    }

    # Write outcome (jq handles all cases correctly)
    write_outcome "$request_id" "$success" "$output" "$error"

    # Delete request file (cleanup)
    rm -f "$request_file"
    log_message "Deleted request file: $request_file"
  done

  log_message "Request processing complete"
}

# Run main function
process_requests
