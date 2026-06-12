#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_anchor_sync.sh
#
# PURPOSE:
#   1. Check whether the addons anchor is loaded.
#   2. If the anchor is empty and pf-addons.conf is non-empty,
#      test the conf with pfctl -nf, load it if clean.
#   3. Parse the live anchor rules and table memberships.
#   4. Write /var/www/htdocs/tn/data/services/queue/pf-rules/active-addons.json
#      for consumption by pf_active_rules.pl (CGI) and the WebUI.
#
# CALLED BY:
#   - pf_anchor_sync_runner.sh  (poll loop, every 30s)
#   - pf_monitor.sh             (after every apply and reset)
#   - pf_delete_block.sh        (after a deletion, to refresh the UI)
#
# PRIVILEGE: runs as root
# OUTPUT:    active-addons.json  (chowned www:www, mode 0644)

set -e

# ============================================================
# CONFIGURATION
# ============================================================
QUEUE_BASE="/var/www/htdocs/tn/data/services/queue/pf-rules"
ADDONS_CONF="/etc/pf/pf-addons.conf"
OUTPUT_JSON="$QUEUE_BASE/active-addons.json"
LOG_FILE="/var/www/tmp/pf_anchor_sync.log"
ANCHOR="addons"

# ============================================================
# LOGGING
# ============================================================
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [pf_anchor_sync] $*" >> "$LOG_FILE"
}

# ============================================================
# TRAP -- run pf_rule_parser.pl on every exit path so that
# parsed-rules.json always exists regardless of anchor state.
# pf_rule_parser.pl writes an empty structure when pf-addons.conf
# is absent or empty, which is correct and expected.
# || true prevents a parser error from masking the real exit code.
# ============================================================
trap '/usr/local/sbin/pf_rule_parser.pl >> "$LOG_FILE" 2>&1 || true' EXIT

# ============================================================
# JSON HELPERS
# No jq dependency -- pure shell string building.
# ============================================================

# Escape a string for safe embedding in a JSON value.
# Handles backslash, double-quote, and common control characters.
json_str() {
  printf '%s' "$1" \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g' \
    | tr -d '\000-\031'
}

# Write empty state with no error -- normal condition (no conf, post-reset, first run)
write_empty_clean() {
  cat > "$OUTPUT_JSON" << EOF
{
    "generated": $(date +%s),
    "anchor_loaded": false,
    "load_error": "",
    "blocks": []
}
EOF
  chown www:www "$OUTPUT_JSON" 2> /dev/null
  chmod 0644 "$OUTPUT_JSON" 2> /dev/null
  log "Wrote empty state: $1"
}

# Write error state -- only for real pfctl failures
write_empty() {
  local reason
  reason=$(json_str "$1")
  cat > "$OUTPUT_JSON" << EOF
{
    "generated": $(date +%s),
    "anchor_loaded": false,
    "load_error": "$reason",
    "blocks": []
}
EOF
  chown www:www "$OUTPUT_JSON" 2> /dev/null
  chmod 0644 "$OUTPUT_JSON" 2> /dev/null
  log "Wrote error state: $1"
}

# ============================================================
# ENSURE QUEUE SUBDIRS EXIST WITH www OWNERSHIP
# The CGI (www user) writes delete requests here.
# Created by this script (root) so permissions are correct.
# ============================================================
for _d in "$QUEUE_BASE/delete-requests" "$QUEUE_BASE/delete-outcome"; do
  if [ ! -d "$_d" ]; then
    mkdir -p "$_d"
    chown www:www "$_d"
    chmod 0755 "$_d"
    log "Created directory: $_d"
  fi
done

# ============================================================
# STEP 1 -- CHECK ANCHOR STATE
# pfctl -a addons -sr returns the ruleset. Empty stdout means
# the anchor is not loaded or is empty.
# ============================================================
ANCHOR_RULES=$(pfctl -a "$ANCHOR" -sr 2> /dev/null || true)

if [ -z "$ANCHOR_RULES" ]; then
  log "Anchor '$ANCHOR' is empty -- checking conf file"

  # Nothing to load if conf is absent or empty -- this is normal after
  # a reset or on first run. Write empty state with no load_error so
  # the UI shows the informational banner, not the error banner.
  if [ ! -f "$ADDONS_CONF" ] || [ ! -s "$ADDONS_CONF" ]; then
    cat > "$OUTPUT_JSON" << EOF
{
    "generated": $(date +%s),
    "anchor_loaded": false,
    "load_error": "",
    "blocks": []
}
EOF
    chown www:www "$OUTPUT_JSON" 2> /dev/null
    chmod 0644 "$OUTPUT_JSON" 2> /dev/null
    log "Anchor empty, no conf file -- wrote empty state"
    exit 0
  fi

  # --------------------------------------------------------
  # STEP 2 -- TEST THE CONF BEFORE LOADING
  # pfctl -nf writes errors to stderr. Any stdout output
  # (warnings, notices) means something is worth reporting.
  # --------------------------------------------------------
  PFCTL_OUT=$(pfctl -a "$ANCHOR" -nf "$ADDONS_CONF" 2>&1) || {
    log "pfctl -nf FAILED: $PFCTL_OUT"
    write_empty "pfctl syntax check failed: $(echo "$PFCTL_OUT" | head -2 | tr '\n' ' ')"
    exit 0
  }

  if [ -n "$PFCTL_OUT" ]; then
    # Non-empty stdout from -nf means pfctl had something to say.
    # Treat as an error -- surface it to the UI, do not load.
    log "pfctl -nf reported output (not loading): $PFCTL_OUT"
    write_empty "pfctl reported warnings/errors -- fix via console: $(echo "$PFCTL_OUT" | head -2 | tr '\n' ' ')"
    exit 0
  fi

  # Test passed cleanly -- load the anchor
  log "pfctl -nf passed -- loading anchor"
  pfctl -a "$ANCHOR" -f "$ADDONS_CONF" 2> /dev/null || {
    log "pfctl load FAILED"
    write_empty "Failed to load anchor"
    exit 0
  }

  # Re-read rules after load
  ANCHOR_RULES=$(pfctl -a "$ANCHOR" -sr 2> /dev/null || true)
  if [ -z "$ANCHOR_RULES" ]; then
    write_empty_clean "Anchor still empty after load"
    exit 0
  fi

  log "Anchor loaded successfully"
fi

# ============================================================
# STEP 3 -- PARSE THE CONF FILE INTO LOGICAL BLOCKS
#
# We parse pf-addons.conf rather than the live pfctl output
# because the conf carries the provenance information we need
# (section headers, source queue files, country codes, ASNs).
# The conf was generated by pf_validator.pl with known section
# comment markers we can grep for reliably.
# ============================================================
if [ ! -f "$ADDONS_CONF" ] || [ ! -s "$ADDONS_CONF" ]; then
  write_empty_clean "Anchor loaded but conf file absent"
  exit 0
fi

# ============================================================
# HELPER: get live table entries from kernel via pfctl
# Returns newline-separated CIDRs/IPs, one per line.
# ============================================================
get_table_entries() {
  local tbl="$1"
  pfctl -a "$ANCHOR" -t "$tbl" -T show 2> /dev/null || true
}

# ============================================================
# HELPER: build a JSON array from newline-separated strings
# ============================================================
lines_to_json_array() {
  local input="$1"
  local result=""
  local first=1
  echo "$input" | while IFS= read -r line; do
    line=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
    [ -z "$line" ] && continue
    escaped=$(json_str "$line")
    if [ "$first" -eq 1 ]; then
      result="\"$escaped\""
      first=0
    else
      result="$result, \"$escaped\""
    fi
    printf '%s' "$result"
  done
  # lines_to_json_array prints incrementally -- caller wraps in []
}

# ============================================================
# Build blocks JSON array by reading pf-addons.conf sections
# ============================================================
BLOCKS_JSON=""
BLOCK_SEP=""

# Track current section
IN_IP_BLOCK=0
IN_IP_PASS=0
IN_ASN_BLOCK=0
IN_GEOIP=0
IN_FEEDS=0
IN_CUSTOM=0

# Accumulate custom rules
CUSTOM_RULES=""
FEED_ENTRIES=""

# ---- IP BLOCK ----
if grep -q "USER IP BLOCK LIST" "$ADDONS_CONF" 2> /dev/null; then
  ENTRIES=$(get_table_entries "user_block_ips")
  COUNT=$(echo "$ENTRIES" | grep -c '[^[:space:]]' || echo 0)
  if [ "$COUNT" -gt 0 ]; then
    ENTRIES_ARR=$(echo "$ENTRIES" | sed 's/^[[:space:]]*//' | grep '[^[:space:]]' \
      | awk '{printf "%s\"%s\"", (NR>1?", ":""), $0}')
    BLOCKS_JSON="${BLOCKS_JSON}${BLOCK_SEP}{
        \"type\": \"ip_block\",
        \"label\": \"IP Block List\",
        \"table\": \"user_block_ips\",
        \"action\": \"block\",
        \"entry_count\": $COUNT,
        \"table_entries\": [$ENTRIES_ARR],
        \"queue_file\": \"ip-block.txt\"
    }"
    BLOCK_SEP=", "
    log "ip_block: $COUNT entries"
  fi
fi

# ---- IP PASS ----
if grep -q "USER IP PASS LIST" "$ADDONS_CONF" 2> /dev/null; then
  ENTRIES=$(get_table_entries "user_pass_ips")
  COUNT=$(echo "$ENTRIES" | grep -c '[^[:space:]]' || echo 0)
  if [ "$COUNT" -gt 0 ]; then
    ENTRIES_ARR=$(echo "$ENTRIES" | sed 's/^[[:space:]]*//' | grep '[^[:space:]]' \
      | awk '{printf "%s\"%s\"", (NR>1?", ":""), $0}')
    BLOCKS_JSON="${BLOCKS_JSON}${BLOCK_SEP}{
        \"type\": \"ip_pass\",
        \"label\": \"IP Pass List\",
        \"table\": \"user_pass_ips\",
        \"action\": \"pass\",
        \"entry_count\": $COUNT,
        \"table_entries\": [$ENTRIES_ARR],
        \"queue_file\": \"ip-pass.txt\"
    }"
    BLOCK_SEP=", "
    log "ip_pass: $COUNT entries"
  fi
fi

# ---- ASN BLOCK ----
if grep -q "USER ASN BLOCK LIST" "$ADDONS_CONF" 2> /dev/null; then
  # Extract ASN list from comment line: # ASNs: AS4134, AS1234
  ASNS=$(grep "^# ASNs:" "$ADDONS_CONF" | sed 's/^# ASNs: //' | tr -d '\n')
  ENTRIES=$(get_table_entries "user_asn_block")
  COUNT=$(echo "$ENTRIES" | grep -c '[^[:space:]]' || echo 0)
  ASNS_ARR=$(echo "$ASNS" | tr ',' '\n' | sed 's/^[[:space:]]*//' | grep '[^[:space:]]' \
    | awk '{printf "%s\"%s\"", (NR>1?", ":""), $0}')
  ENTRIES_ARR=$(echo "$ENTRIES" | sed 's/^[[:space:]]*//' | grep '[^[:space:]]' \
    | awk '{printf "%s\"%s\"", (NR>1?", ":""), $0}')
  BLOCKS_JSON="${BLOCKS_JSON}${BLOCK_SEP}{
        \"type\": \"asn_block\",
        \"label\": \"ASN Block\",
        \"table\": \"user_asn_block\",
        \"action\": \"block\",
        \"asns\": [$ASNS_ARR],
        \"entry_count\": $COUNT,
        \"table_entries\": [$ENTRIES_ARR],
        \"queue_file\": \"asn-block.txt\"
    }"
  BLOCK_SEP=", "
  log "asn_block: ASNs=$ASNS CIDRs=$COUNT"
fi

# ---- GEOIP -- one block per country ----
# Each country has its own table geoip_XX and comment line:
# # GeoIP: VN (7 CIDRs)
# Use temp file to avoid subshell variable scope loss (ksh pipe | while runs in subshell)
GEOIP_LINES_TMP="/tmp/pf_sync_geoip_$$.tmp"
grep "^# GeoIP:" "$ADDONS_CONF" 2> /dev/null > "$GEOIP_LINES_TMP" || true

while IFS= read -r line; do
  CC=$(echo "$line" | sed 's/^# GeoIP: //' | awk '{print $1}')
  [ -z "$CC" ] && continue
  CC_LOWER=$(echo "$CC" | tr '[:upper:]' '[:lower:]')
  TBL="geoip_${CC_LOWER}"

  ENTRIES=$(get_table_entries "$TBL")
  COUNT=$(echo "$ENTRIES" | grep -c '[^[:space:]]' 2> /dev/null || echo 0)
  ENTRIES_ARR=$(echo "$ENTRIES" | sed 's/^[[:space:]]*//' | grep '[^[:space:]]' \
    | awk '{printf "%s\"%s\"", (NR>1?", ":""), $0}')

  ACTION="block"
  grep -q "^pass.*<${TBL}>" "$ADDONS_CONF" 2> /dev/null && ACTION="pass"

  BLOCKS_JSON="${BLOCKS_JSON}${BLOCK_SEP}{
        \"type\": \"geoip\",
        \"label\": \"GeoIP \u2014 ${CC}\",
        \"country\": \"${CC}\",
        \"table\": \"${TBL}\",
        \"action\": \"${ACTION}\",
        \"entry_count\": $COUNT,
        \"table_entries\": [$ENTRIES_ARR],
        \"queue_file\": \"geoip-policy.json\"
    }"
  BLOCK_SEP=", "
  log "geoip: $CC table=$TBL entries=$COUNT"
done < "$GEOIP_LINES_TMP"
rm -f "$GEOIP_LINES_TMP"

# ---- FEEDS -- one block per feed ----
# Each feed has a comment: # Feed N: https://url (M entries)
FEED_LINES_TMP="/tmp/pf_sync_feed_$$.tmp"
grep "^# Feed [0-9]" "$ADDONS_CONF" 2> /dev/null > "$FEED_LINES_TMP" || true

while IFS= read -r line; do
  IDX=$(echo "$line" | sed 's/^# Feed //' | awk -F: '{print $1}' | tr -d ' ')
  URL=$(echo "$line" | sed 's/^# Feed [0-9]*: //' | sed 's/ (.*//')
  TBL=$(printf "feed_%03d" "$IDX")

  ENTRIES=$(get_table_entries "$TBL")
  COUNT=$(echo "$ENTRIES" | grep -c '[^[:space:]]' 2> /dev/null || echo 0)
  ENTRIES_ARR=$(echo "$ENTRIES" | sed 's/^[[:space:]]*//' | grep '[^[:space:]]' \
    | awk '{printf "%s\"%s\"", (NR>1?", ":""), $0}')

  ACTION="block"
  grep -q "^pass.*<${TBL}>" "$ADDONS_CONF" 2> /dev/null && ACTION="pass"

  URL_ESC=$(json_str "$URL")
  BLOCKS_JSON="${BLOCKS_JSON}${BLOCK_SEP}{
        \"type\": \"feed\",
        \"label\": \"Feed ${IDX}\",
        \"feed_index\": $IDX,
        \"url\": \"${URL_ESC}\",
        \"table\": \"${TBL}\",
        \"action\": \"${ACTION}\",
        \"entry_count\": $COUNT,
        \"table_entries\": [$ENTRIES_ARR],
        \"queue_file\": \"feed-urls.txt\"
    }"
  BLOCK_SEP=", "
  log "feed: idx=$IDX url=$URL entries=$COUNT"
done < "$FEED_LINES_TMP"
rm -f "$FEED_LINES_TMP"

# ---- CUSTOM RULES ----
# Extract lines between CUSTOM PF RULES section header and End marker
# that start with pass/block/match (not comments)
CUSTOM_SECTION=$(awk '/# CUSTOM PF RULES/{found=1; next} found && /^# ---/{exit} found{print}' \
  "$ADDONS_CONF" 2> /dev/null | grep -E '^(pass|block|match)\s' || true)

if [ -n "$CUSTOM_SECTION" ]; then
  RULES_ARR=$(echo "$CUSTOM_SECTION" | grep '[^[:space:]]' \
    | awk '{
            # escape double-quotes in the rule
            gsub(/"/, "\\\"");
            printf "%s\"%s\"", (NR>1?", ":""), $0
        }')
  RULE_COUNT=$(echo "$CUSTOM_SECTION" | grep -c '[^[:space:]]' || echo 0)
  BLOCKS_JSON="${BLOCKS_JSON}${BLOCK_SEP}{
        \"type\": \"custom\",
        \"label\": \"Custom PF Rules\",
        \"entry_count\": $RULE_COUNT,
        \"table_entries\": [],
        \"rules\": [$RULES_ARR],
        \"queue_file\": \"custom-rules.txt\"
    }"
  BLOCK_SEP=", "
  log "custom: $RULE_COUNT rules"
fi

# ============================================================
# STEP 4 -- WRITE active-addons.json
# ============================================================
cat > "$OUTPUT_JSON" << EOF
{
    "generated": $(date +%s),
    "anchor_loaded": true,
    "load_error": "",
    "blocks": [$BLOCKS_JSON]
}
EOF

chown www:www "$OUTPUT_JSON"
chmod 0644 "$OUTPUT_JSON"

log "active-addons.json written ($(wc -c < "$OUTPUT_JSON") bytes)"

exit 0
