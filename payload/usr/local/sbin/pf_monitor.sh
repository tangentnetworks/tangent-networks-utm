#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_monitor.sh
#
# Root daemon: watches trigger files and orchestrates the
# validate -> load -> apply/reset workflow for anchor "addons".
#
# PRIVILEGE MODEL:
#   - Runs as root (via rc.d or rc.local)
#   - Reads user-input files written by www (pf_write_input.pl)
#   - Writes validation output readable by www (WebUI)
#   - Executes pfctl to load/flush the addons anchor
#
# PIPELINE:
#   trigger: validate-requested
#     -> pf_validator.pl assembles staging/pf-addons.conf
#     -> pfctl -nf tests the staged config
#     -> writes validation-output/verdict.json + full-context.txt
#     -> on pass: arms apply-ready sentinel
#
#   trigger: apply-requested
#     -> copies staging/pf-addons.conf -> /etc/pf/pf-addons.conf
#     -> pfctl -a addons -f /etc/pf/pf-addons.conf (hot-loads anchor)
#
#   trigger: reset-requested
#     -> pfctl -a addons -F all (flush anchor immediately)
#     -> clears /etc/pf/pf-addons.conf
#     -> clears all user-input files
#     -> purges validated/ snapshots (kept in sync with live conf)

set -e

# ============================================
# CONFIGURATION
# ============================================
QUEUE_BASE="/var/www/htdocs/tn/data/services/queue/pf-rules"
USER_INPUT="$QUEUE_BASE/user-input"
STAGING="$QUEUE_BASE/staging"
VALIDATED="$QUEUE_BASE/validated"
TRIGGERS="$QUEUE_BASE/triggers"
VAL_OUT="$QUEUE_BASE/validation-output"

ADDONS_CONF="/etc/pf/pf-addons.conf"
VALIDATOR="/usr/local/sbin/pf_validator.pl"
LOG_FILE="/var/www/tmp/pf_monitor.log"
PIDFILE="/var/www/htdocs/tn/data/run/webui/pf_monitor.pid"
SYNC_SCRIPT="/usr/local/sbin/pf_anchor_sync.sh"
DELETE_SCRIPT="/usr/local/sbin/pf_delete_block.sh"
DELETE_DIR="$QUEUE_BASE/delete-requests"

# ============================================
# LOGGING
# ============================================
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [pf_monitor] $*" | tee -a "$LOG_FILE"
}

# ============================================
# HELPER: Purge timestamped validated snapshots
#
# Called after reset (explicit) and at startup if
# ADDONS_CONF is found empty (e.g. after reboot
# following a reset).
#
# Only removes files matching the pattern
# pf-addons.conf.<unix-timestamp> to avoid
# accidentally deleting anything else in validated/.
# ============================================
purge_validated_snapshots() {
  local count=0
  for f in "$VALIDATED"/pf-addons.conf.*; do
    case "$f" in
      *pf-addons.conf.[0-9]*)
        rm -f "$f" 2> /dev/null && count=$((count + 1))
        ;;
    esac
  done
  log "Purged $count validated snapshot(s) from $VALIDATED"
}

# ============================================
# STARTUP
# ============================================
# Ensure runtime dirs exist
for d in "$STAGING" "$VALIDATED" "$VAL_OUT" "$TRIGGERS"; do
  [ ! -d "$d" ] && mkdir -p "$d"
done

[ ! -d /var/www/tmp ] && mkdir -p /var/www/tmp && chown www:www /var/www/tmp

# Write PID
echo $$ > "$PIDFILE"
trap "rm -f $PIDFILE; log 'Daemon exiting'" EXIT INT TERM

log "========================================"
log "pf_monitor started (PID $$)"
log "========================================"

# ============================================
# STARTUP CONSISTENCY CHECK
#
# If ADDONS_CONF exists but is empty the last
# action was a reset (or a manual wipe). Purge
# validated snapshots so they do not show stale
# rules that are no longer on the firewall.
# ============================================
if [ -f "$ADDONS_CONF" ] && [ ! -s "$ADDONS_CONF" ]; then
  log "ADDONS_CONF is empty at startup -- purging stale validated snapshots"
  purge_validated_snapshots
fi

# ============================================
# HELPER: Write JSON verdict for WebUI polling
# ============================================
write_verdict() {
  local success="$1"
  local stats="$2"
  local warnings="$3"
  local errors="$4"

  cat > "$VAL_OUT/verdict.json" << EOF
{
    "success": $success,
    "timestamp": "$(date '+%Y-%m-%d %H:%M:%S')",
    "stats": $stats,
    "warnings": $warnings,
    "errors": $errors
}
EOF
  chown www:www "$VAL_OUT/verdict.json"
  chmod 0644 "$VAL_OUT/verdict.json"
}

# ============================================
# HELPER: Remove a trigger file safely
# ============================================
clear_trigger() {
  rm -f "$TRIGGERS/$1" 2> /dev/null || true
}

# ============================================
# ACTION: VALIDATE
# ============================================
do_validate() {
  log "--- VALIDATE triggered ---"

  rm -f "$VAL_OUT/verdict.json" 2> /dev/null
  rm -f "$VAL_OUT/full-context.txt" 2> /dev/null
  rm -f "$TRIGGERS/apply-ready" 2> /dev/null

  local validator_out
  local validator_exit=0

  if [ -x "$VALIDATOR" ]; then
    validator_out=$("$VALIDATOR" 2>&1) || validator_exit=$?
  else
    validator_out="ERROR: $VALIDATOR not found or not executable"
    validator_exit=1
  fi

  log "Validator exit: $validator_exit"

  if [ "$validator_exit" -ne 0 ]; then
    log "Validator FAILED"
    echo "$validator_out" > "$VAL_OUT/full-context.txt"
    chown www:www "$VAL_OUT/full-context.txt"
    chmod 0644 "$VAL_OUT/full-context.txt"

    write_verdict "false" \
      '{"ip_added":0,"asn_added":0,"geoip_countries":0,"feeds_added":0,"rejected":0,"duplicates":0}' \
      '[]' \
      "[\"Validator script failed - check $LOG_FILE for details\"]"

    clear_trigger "validate-requested"
    return 1
  fi

  local stats_json
  stats_json=$(echo "$validator_out" | grep '^STATS_JSON:' | sed 's/^STATS_JSON://')
  [ -z "$stats_json" ] && stats_json='{"ip_added":0,"asn_added":0,"geoip_countries":0,"feeds_added":0,"rejected":0,"duplicates":0}'

  local warnings_json
  warnings_json=$(echo "$validator_out" | grep '^WARNINGS_JSON:' | sed 's/^WARNINGS_JSON://')
  [ -z "$warnings_json" ] && warnings_json='[]'

  echo "$validator_out" > "$VAL_OUT/full-context.txt"
  chown www:www "$VAL_OUT/full-context.txt"
  chmod 0644 "$VAL_OUT/full-context.txt"

  local staged="$STAGING/pf-addons.conf"

  if [ ! -f "$staged" ]; then
    log "ERROR: Validator succeeded but $staged not found"
    write_verdict "false" "$stats_json" "$warnings_json" \
      '["Staged config file missing after validation"]'
    clear_trigger "validate-requested"
    return 1
  fi

  log "Running pfctl -nf on staged config..."
  local pfctl_out
  local pfctl_exit=0

  pfctl_out=$(pfctl -a addons -nf "$staged" 2>&1) || pfctl_exit=$?

  {
    echo ""
    echo "=== pfctl -a addons -nf output ==="
    echo "$pfctl_out"
  } >> "$VAL_OUT/full-context.txt"

  if [ "$pfctl_exit" -ne 0 ]; then
    log "pfctl validation FAILED: $pfctl_out"
    write_verdict "false" "$stats_json" "$warnings_json" \
      "[\"pfctl syntax check failed: $(echo "$pfctl_out" | head -3 | tr '\n' ' ' | sed 's/"/\\"/g')\"]"
    clear_trigger "validate-requested"
    return 1
  fi

  log "pfctl validation PASSED"

  touch "$TRIGGERS/apply-ready"
  chown www:www "$TRIGGERS/apply-ready"

  write_verdict "true" "$stats_json" "$warnings_json" '[]'

  log "Verdict written: SUCCESS"
  clear_trigger "validate-requested"
  return 0
}

# ============================================
# ACTION: APPLY
# ============================================
do_apply() {
  log "--- APPLY triggered ---"

  local staged="$STAGING/pf-addons.conf"

  if [ ! -f "$TRIGGERS/apply-ready" ]; then
    log "APPLY rejected: no apply-ready sentinel (run Validate first)"
    clear_trigger "apply-requested"
    return 1
  fi

  if [ ! -f "$staged" ]; then
    log "APPLY failed: staged config missing"
    clear_trigger "apply-requested"
    return 1
  fi

  if [ -f "$ADDONS_CONF" ]; then
    cp "$ADDONS_CONF" "/var/backups/pf-addons.conf.$(date +%s).bak" 2> /dev/null || true
  fi

  [ ! -d /etc/pf ] && mkdir -p /etc/pf

  cp "$staged" "$ADDONS_CONF"
  chown root:wheel "$ADDONS_CONF"
  chmod 0640 "$ADDONS_CONF"

  local pfctl_out
  local pfctl_exit=0
  pfctl_out=$(pfctl -a addons -f "$ADDONS_CONF" 2>&1) || pfctl_exit=$?

  if [ "$pfctl_exit" -ne 0 ]; then
    log "APPLY ERROR: pfctl failed to load anchor: $pfctl_out"
    clear_trigger "apply-requested"
    clear_trigger "apply-ready"
    return 1
  fi

  log "APPLY SUCCESS: anchor 'addons' loaded from $ADDONS_CONF"
  log "pfctl output: $pfctl_out"

  cp "$ADDONS_CONF" "$VALIDATED/pf-addons.conf.$(date +%s)"

  pfctl -sr > "$QUEUE_BASE/current" 2> /dev/null || true
  chown www:www "$QUEUE_BASE/current"
  chmod 0644 "$QUEUE_BASE/current"

  local asn_file="$QUEUE_BASE/user-input/asn-block.txt"
  if [ -f "$asn_file" ] && [ -s "$asn_file" ]; then
    log "ASN entries detected -- triggering pf_asn_resolve.sh in background"
    /usr/local/sbin/pf_asn_resolve.sh >> /var/www/tmp/pf_asn_resolve.log 2>&1 &
  fi

  clear_trigger "apply-requested"
  clear_trigger "apply-ready"

  # Refresh active-addons.json so the UI reflects the new anchor state
  "$SYNC_SCRIPT" >> "$LOG_FILE" 2>&1 || true

  return 0
}

# ============================================
# ACTION: RESET
# Flushes anchor, clears user inputs, purges
# validated snapshots to stay in sync.
# ============================================
do_reset() {
  log "--- RESET triggered ---"

  # Flush the live anchor
  pfctl -a addons -F all 2> /dev/null && log "Anchor 'addons' flushed" || log "WARNING: pfctl flush returned error (anchor may be empty)"

  # Clear the live addons config
  if [ -f "$ADDONS_CONF" ]; then
    cp "$ADDONS_CONF" "/var/backups/pf-addons.conf.$(date +%s).pre-reset" 2> /dev/null || true
    : > "$ADDONS_CONF"
  fi

  # Purge validated snapshots -- they no longer reflect reality
  # now that the live anchor is empty
  purge_validated_snapshots

  # Clear all user input files (but leave the files themselves)
  for f in "$USER_INPUT"/*.txt; do
    [ -f "$f" ] && : > "$f"
  done
  [ -f "$USER_INPUT/geoip-policy.json" ] && : > "$USER_INPUT/geoip-policy.json"

  # Clear staging and stale verdict
  rm -f "$STAGING/pf-addons.conf" 2> /dev/null
  rm -f "$VAL_OUT/verdict.json" 2> /dev/null
  rm -f "$VAL_OUT/full-context.txt" 2> /dev/null
  rm -f "$TRIGGERS/apply-ready" 2> /dev/null

  # Refresh current rules snapshot
  pfctl -sr > "$QUEUE_BASE/current" 2> /dev/null || true
  chown www:www "$QUEUE_BASE/current"
  chmod 0644 "$QUEUE_BASE/current"

  # Reset the change detector state so it re-arms cleanly
  rm -f "$QUEUE_BASE/.last_input_state" 2> /dev/null

  log "RESET complete"
  clear_trigger "reset-requested"

  # Refresh active-addons.json -- anchor is now empty
  "$SYNC_SCRIPT" >> "$LOG_FILE" 2>&1 || true

  return 0
}

# ================================================================
# FUNCTION: do_test_deletion
#
# Triggered by: $TRIGGERS/test-deletion-requested
# Reads:        $STAGING/pf-addons-deletion.conf
# Runs:         pfctl -a addons -nf  (syntax check, no load)
# Writes:       $STAGING/deletion-test-result.json
# Polled by:    JS via /data/services/queue/pf-rules/staging/
#               deletion-test-result.json
# ================================================================
do_test_deletion() {
  log "--- TEST-DELETION triggered ---"

  local deletion_conf="$STAGING/pf-addons-deletion.conf"
  local result_file="$STAGING/deletion-test-result.json"
  local tmp_result="${result_file}.tmp.$$"

  if [ ! -f "$deletion_conf" ] || [ ! -s "$deletion_conf" ]; then
    log "do_test_deletion: ERROR -- staged conf missing or empty"
    printf '{"success":false,"error":"Staged deletion conf not found"}' \
      > "$tmp_result"
    mv "$tmp_result" "$result_file"
    chown www:www "$result_file" 2> /dev/null || true
    chmod 0644 "$result_file" 2> /dev/null || true
    rm -f "$TRIGGERS/test-deletion-requested"
    return 1
  fi

  log "do_test_deletion: running pfctl -a addons -nf on $deletion_conf"

  local pfctl_out
  local pfctl_exit=0
  pfctl_out=$(pfctl -a addons -nf "$deletion_conf" 2>&1) || pfctl_exit=$?

  if [ "$pfctl_exit" -eq 0 ]; then
    log "do_test_deletion: syntax OK"
    printf '{"success":true,"pfctl_exit":0}' > "$tmp_result"
  else
    log "do_test_deletion: pfctl syntax FAILED (exit $pfctl_exit): $pfctl_out"
    # Escape the error string for JSON: backslash, double-quote, newline
    local safe_err
    safe_err=$(printf '%s' "$pfctl_out" \
      | awk '{gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t")}
                 NR > 1 {printf "\\n"}
                 {printf "%s", $0}')
    printf '{"success":false,"pfctl_exit":%d,"error":"%s"}' \
      "$pfctl_exit" "$safe_err" > "$tmp_result"
  fi

  mv "$tmp_result" "$result_file"
  chown www:www "$result_file" 2> /dev/null || true
  chmod 0644 "$result_file" 2> /dev/null || true

  rm -f "$TRIGGERS/test-deletion-requested"
  log "do_test_deletion: complete (exit $pfctl_exit)"
  return "$pfctl_exit"
}

# ================================================================
# FUNCTION: do_apply_deletion
#
# Triggered by: $TRIGGERS/apply-deletion-requested
# Reads:        $STAGING/pf-addons-deletion.conf
# Applies:      pfctl -a addons -f (live load)
# Persists:     cp -> $ADDONS_CONF
# Refreshes:    pf_anchor_sync.sh (rebuilds active-addons.json +
#               parsed-rules.json)
# Writes:       $STAGING/apply-deletion-outcome.json
# ================================================================
do_apply_deletion() {
  log "--- APPLY-DELETION triggered ---"

  local deletion_conf="$STAGING/pf-addons-deletion.conf"
  local outcome_file="$STAGING/apply-deletion-outcome.json"
  local tmp_outcome="${outcome_file}.tmp.$$"

  if [ ! -f "$deletion_conf" ] || [ ! -s "$deletion_conf" ]; then
    log "do_apply_deletion: ERROR -- staged conf missing or empty"
    printf '{"success":false,"error":"Staged deletion conf not found -- re-run preview"}' \
      > "$tmp_outcome"
    mv "$tmp_outcome" "$outcome_file"
    chown www:www "$outcome_file" 2> /dev/null || true
    chmod 0644 "$outcome_file" 2> /dev/null || true
    rm -f "$TRIGGERS/apply-deletion-requested"
    return 1
  fi

  # Pre-flight syntax check before touching the live firewall
  log "do_apply_deletion: pre-flight pfctl -nf"
  local preflight_out
  local preflight_exit=0
  preflight_out=$(pfctl -a addons -nf "$deletion_conf" 2>&1) || preflight_exit=$?

  if [ "$preflight_exit" -ne 0 ]; then
    log "do_apply_deletion: pre-flight FAILED (exit $preflight_exit): $preflight_out"
    local safe_err
    safe_err=$(printf '%s' "$preflight_out" \
      | awk '{gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t")}
                 NR > 1 {printf "\\n"}
                 {printf "%s", $0}')
    printf '{"success":false,"error":"Pre-flight check failed: %s"}' \
      "$safe_err" > "$tmp_outcome"
    mv "$tmp_outcome" "$outcome_file"
    chown www:www "$outcome_file" 2> /dev/null || true
    chmod 0644 "$outcome_file" 2> /dev/null || true
    rm -f "$TRIGGERS/apply-deletion-requested"
    return 1
  fi

  # Load into live anchor
  log "do_apply_deletion: loading into anchor addons"
  local load_out
  local load_exit=0
  load_out=$(pfctl -a addons -f "$deletion_conf" 2>&1) || load_exit=$?

  if [ "$load_exit" -ne 0 ]; then
    log "do_apply_deletion: pfctl load FAILED (exit $load_exit): $load_out"
    local safe_err
    safe_err=$(printf '%s' "$load_out" \
      | awk '{gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t")}
                 NR > 1 {printf "\\n"}
                 {printf "%s", $0}')
    printf '{"success":false,"error":"pfctl load failed: %s"}' \
      "$safe_err" > "$tmp_outcome"
    mv "$tmp_outcome" "$outcome_file"
    chown www:www "$outcome_file" 2> /dev/null || true
    chmod 0644 "$outcome_file" 2> /dev/null || true
    rm -f "$TRIGGERS/apply-deletion-requested"
    return 1
  fi

  log "do_apply_deletion: anchor loaded successfully"

  # Persist to /etc/pf/pf-addons.conf so it survives reboot
  if cp "$deletion_conf" "$ADDONS_CONF"; then
    chown root:wheel "$ADDONS_CONF"
    chmod 0640 "$ADDONS_CONF"
    log "do_apply_deletion: persisted to $ADDONS_CONF"
  else
    log "do_apply_deletion: WARNING -- could not copy to $ADDONS_CONF (anchor is live)"
  fi

  # Clean up staged file
  rm -f "$deletion_conf"

  # Rebuild active-addons.json and parsed-rules.json
  if [ -x "$SYNC_SCRIPT" ]; then
    log "do_apply_deletion: calling $SYNC_SCRIPT"
    "$SYNC_SCRIPT" >> "$LOG_FILE" 2>&1 \
      || log "do_apply_deletion: WARNING -- sync script returned non-zero"
  else
    log "do_apply_deletion: WARNING -- sync script not found: $SYNC_SCRIPT"
  fi

  # Write success outcome -- JS stops polling when this appears
  printf '{"success":true,"message":"Deletion applied -- anchor reloaded"}' \
    > "$tmp_outcome"
  mv "$tmp_outcome" "$outcome_file"
  chown www:www "$outcome_file" 2> /dev/null || true
  chmod 0644 "$outcome_file" 2> /dev/null || true

  rm -f "$TRIGGERS/apply-deletion-requested"
  log "do_apply_deletion: complete"
  return 0
}

# ============================================
# MAIN LOOP
# ============================================
log "Entering main watch loop (poll every 2s)"

while true; do

  # --- VALIDATE (highest priority) ---
  if [ -f "$TRIGGERS/validate-requested" ]; then
    do_validate || log "validate step returned error"
  fi

  # --- APPLY ---
  if [ -f "$TRIGGERS/apply-requested" ]; then
    do_apply || log "apply step returned error"
  fi

  # --- RESET ---
  if [ -f "$TRIGGERS/reset-requested" ]; then
    do_reset || log "reset step returned error"
  fi

  # --- DELETE BLOCK ---
  if ls "$DELETE_DIR"/*.json > /dev/null 2>&1; then
    "$DELETE_SCRIPT" >> "$LOG_FILE" 2>&1 || log "delete block step returned error"
  fi

  # --- TEST DELETION ---
  if [ -f "$TRIGGERS/test-deletion-requested" ]; then
    do_test_deletion || log "test-deletion step returned error"
  fi

  # --- APPLY DELETION ---
  if [ -f "$TRIGGERS/apply-deletion-requested" ]; then
    do_apply_deletion || log "apply-deletion step returned error"
  fi

  sleep 2
done
