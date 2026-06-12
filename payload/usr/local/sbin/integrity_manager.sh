#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

# Configuration
CONFIG_FILE="/var/www/htdocs/tn/data/config/integrity_checks.conf"
MTREE_SPECS="/etc/mtree"
LOG_DIR="/var/www/htdocs/tn/data/logs/bootlog"
MANAGER_LOG="${LOG_DIR}/integrity_$(date '+%Y-%m-%d').log"

# Ensure log directory exists
install -d -o root -g wheel -m 755 "$LOG_DIR"

# Logging function
log() {
  local level="$1"
  local message="$2"
  printf "[$(date '+%Y-%m-%d %H:%M:%S')] INTEGRITY: [%s] %s\n" "$level" "$message" | tee -a "$MANAGER_LOG"
}

# Check if config exists
if [ ! -f "$CONFIG_FILE" ]; then
  log "ERROR" "Config file not found: $CONFIG_FILE"
  echo "ERROR: Configuration file missing"
  exit 1
fi

# Get check info from config
get_check_info() {
  local check_type="$1"

  while IFS='|' read -r type check_name display_name path description excludes; do
    # Skip comments and empty lines
    case "$type" in
      \#* | "") continue ;;
    esac

    if [ "$check_name" = "$check_type" ]; then
      echo "$type|$check_name|$display_name|$path"
      return 0
    fi
  done < "$CONFIG_FILE"

  return 1
}

# Check if mtree spec exists
check_spec_exists() {
  local spec="$1"
  if [ ! -f "$spec" ]; then
    log "ERROR" "mtree spec not found: $spec"
    echo "ERROR: mtree baseline not found"
    echo "Run: /usr/local/sbin/create_integrity_baseline.sh"
    return 1
  fi
  return 0
}

# Verify integrity using mtree
verify_integrity() {
  local check_type="$1"
  local spec_file="$MTREE_SPECS/tn_${check_type}.spec"

  # Get check info from config
  local check_info=$(get_check_info "$check_type")
  if [ -z "$check_info" ]; then
    log "ERROR" "Unknown check type: $check_type"
    echo "ERROR: Check type not found in config: $check_type"
    return 1
  fi

  local type=$(echo "$check_info" | cut -d'|' -f1)
  local display_name=$(echo "$check_info" | cut -d'|' -f3)
  local path=$(echo "$check_info" | cut -d'|' -f4)

  log "INFO" "Verifying: $check_type ($display_name) at $path"

  # Check if spec exists
  check_spec_exists "$spec_file" || return 1

  # Count files in spec (OpenBSD mtree uses relative paths, no leading /)
  # Count non-comment, non-directory, non-parent entries
  local file_count=$(grep -vE '^(#|/set|\.\.|^$)' "$spec_file" 2> /dev/null | grep -v 'type=dir' | grep -vE '^\.' | wc -l | awk '{print $1}')
  echo "Files checked: $file_count"

  # Run mtree verification
  local mtree_output=$(mtree < "$spec_file" 2>&1)
  local exit_code=$?

  if [ $exit_code -eq 0 ]; then
    # No changes detected
    log "INFO" "$check_type: VERIFIED (no changes)"
    echo "Changes detected: 0"
    echo "Status: OK"
    return 0
  else
    # Changes detected
    local change_count=$(echo "$mtree_output" | grep -c "^  " 2> /dev/null || echo 0)

    log "WARN" "$check_type: FAILED ($change_count changes detected)"
    log "WARN" "Changes: $mtree_output"

    echo "Changes detected: $change_count"
    echo "Status: FAILED"
    echo ""
    echo "Modified files:"
    echo "$mtree_output" | grep "^  " || true

    return 1
  fi
}

# Verify all components
verify_all() {
  log "INFO" "Starting full system verification"

  local checks=""
  local total=0
  local passed=0
  local failed=0

  # Read all check names from config
  while IFS='|' read -r type check_name display_name path description excludes; do
    case "$type" in
      \#* | "") continue ;;
    esac
    checks="$checks $check_name"
  done < "$CONFIG_FILE"

  for check in $checks; do
    total=$((total + 1))
    echo ""
    echo "=== Checking: $check ==="

    if verify_integrity "$check"; then
      passed=$((passed + 1))
    else
      failed=$((failed + 1))
    fi
  done

  echo ""
  echo "=== Summary ==="
  echo "Total checks: $total"
  echo "Passed: $passed"
  echo "Failed: $failed"

  log "INFO" "Full verification complete: $passed/$total passed"

  if [ $failed -gt 0 ]; then
    return 1
  fi
  return 0
}

# Main entry point
ACTION="$1"
CHECK="${2:-all}"

log "INFO" "Request: $ACTION $CHECK"

case "$ACTION" in
  verify)
    if [ "$CHECK" = "all" ]; then
      verify_all
    else
      verify_integrity "$CHECK"
    fi
    EXIT_CODE=$?
    ;;

  *)
    log "ERROR" "Unknown action: $ACTION"
    echo "ERROR: Unknown action: $ACTION"
    echo "Usage: $0 {verify} {check_name|all}"
    exit 1
    ;;
esac

exit $EXIT_CODE
