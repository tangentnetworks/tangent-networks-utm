#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_asn_resolve.sh
#
# Resolves user-submitted ASNs to announced prefixes (IPv4 + IPv6)
# and loads them into the live PF table <user_asn_block>.
#
# DESIGN DECISIONS:
#   - Uses RIPE stat announced-prefixes endpoint (authoritative, free, no key)
#   - Reads prefixes into a file then pfctl -T replace -f <file>
#     → avoids ARG_MAX entirely regardless of prefix count (AWS = 6000+)
#   - Per-ASN cache files allow partial refresh and diff tracking
#   - Handles both IPv4 and IPv6 in the same table (PF supports mixed AF)
#   - Sleep between ASN fetches to respect RIPE stat soft rate limits
#   - Runs as root outside chroot via cron
#
# CRON (root crontab, every 6 hours):
#   0 */6 * * * /usr/local/sbin/pf_asn_resolve.sh >> /var/www/tmp/pf_asn_resolve.log 2>&1
#
# ALSO called by pf_monitor.sh immediately after a successful apply
# so the table is populated without waiting for the next cron window.

set -e

# ============================================
# CONFIGURATION
# ============================================
QUEUE_BASE="/var/www/htdocs/tn/data/services/queue/pf-rules"
ASN_FILE="$QUEUE_BASE/user-input/asn-block.txt"
CACHE_DIR="/var/db/pf-asn"
MERGED_FILE="$CACHE_DIR/_merged.txt"
PREV_MERGED="$CACHE_DIR/_merged_prev.txt"
TABLE="user_asn_block"
LOG_FILE="/var/www/tmp/pf_asn_resolve.log"

# RIPE stat announced-prefixes -- gives exactly what the ASN announces to BGP.
# More accurate than ris-prefixes for blocking intent.
# Includes both IPv4 and IPv6 natively.
RIPE_URL_BASE="https://stat.ripe.net/data/announced-prefixes/data.json?resource="

# Seconds between ASN fetches -- respect RIPE stat soft rate limits
FETCH_DELAY=3

# ============================================
# LOGGING
# ============================================
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [pf_asn_resolve] $*" | tee -a "$LOG_FILE"
}

# ============================================
# SETUP
# ============================================
mkdir -p "$CACHE_DIR"
chmod 700 "$CACHE_DIR"

# ============================================
# CHECK INPUT
# ============================================
if [ ! -f "$ASN_FILE" ] || [ ! -s "$ASN_FILE" ]; then
  log "No ASNs in queue ($ASN_FILE empty or missing) -- exiting"
  exit 0
fi

# Read and normalise ASNs from queue file
# Accepts: AS15169, as15169, 15169
asns=""
while IFS= read -r line; do
  line=$(echo "$line" | sed 's/#.*//' | tr -d '[:space:]')
  [ -z "$line" ] && continue
  num=$(echo "$line" | sed 's/^[Aa][Ss]//')
  case "$num" in
    *[!0-9]*)
      log "SKIP: '$line' is not a valid ASN"
      continue
      ;;
  esac
  asn="AS${num}"
  asns="${asns} ${asn}"
done < "$ASN_FILE"

if [ -z "$asns" ]; then
  log "No valid ASNs found in queue -- exiting"
  exit 0
fi

log "=== pf_asn_resolve started ==="
log "ASNs to resolve: $asns"

# ============================================
# FETCH ANNOUNCED PREFIXES PER ASN
#
# RIPE stat announced-prefixes JSON (relevant excerpt):
#   {"data":{"prefixes":[{"prefix":"1.2.3.0/24",...},{"prefix":"2001:db8::/32",...}]}}
#
# We extract the value of every "prefix":"<value>" key.
# IPv4 CIDRs: digits/dots/slash
# IPv6 CIDRs: hex/colons/slash
# Both are unambiguous in the JSON -- no parser needed.
# ============================================
fetch_asn() {
  local asn="$1"
  local cache_file="$CACHE_DIR/${asn}.txt"
  local tmpfile="$CACHE_DIR/${asn}.tmp"
  local url="${RIPE_URL_BASE}${asn}"

  log "  Fetching $asn ..."

  if ! ftp -o "$tmpfile" -V -w 45 "$url" 2> /dev/null; then
    log "  WARNING: $asn -- network fetch failed"
    rm -f "$tmpfile"
    return 1
  fi

  if [ ! -s "$tmpfile" ]; then
    log "  WARNING: $asn -- empty response"
    rm -f "$tmpfile"
    return 1
  fi

  # Extract prefix values from JSON response
  # -oE: print only matched part, extended regex
  local prefixes
  prefixes=$(grep -oE '"prefix":"[^"]+"' "$tmpfile" \
    | sed 's/"prefix":"//;s/"//' \
    | sort -u)

  rm -f "$tmpfile"

  if [ -z "$prefixes" ]; then
    log "  WARNING: $asn -- no prefixes in response"
    return 1
  fi

  local v4_count v6_count total
  # IPv4: starts with a digit
  v4_count=$(echo "$prefixes" | grep -cE '^[0-9]' 2> /dev/null || true)
  # IPv6: contains a colon
  v6_count=$(echo "$prefixes" | grep -c ':' 2> /dev/null || true)
  total=$(echo "$prefixes" | wc -l | tr -d ' ')

  log "  $asn: $total prefixes ($v4_count IPv4, $v6_count IPv6)"

  # Atomic write
  echo "$prefixes" > "${cache_file}.new"
  mv "${cache_file}.new" "$cache_file"
  return 0
}

# ============================================
# FETCH LOOP WITH RATE LIMITING
# ============================================
fetch_errors=0
first=1

for asn in $asns; do
  if [ "$first" -eq 0 ]; then
    sleep $FETCH_DELAY
  fi
  first=0

  if ! fetch_asn "$asn"; then
    fetch_errors=$((fetch_errors + 1))
    if [ -f "$CACHE_DIR/${asn}.txt" ]; then
      log "  $asn: live fetch failed -- will use cached data"
    else
      log "  $asn: live fetch failed -- no cache, ASN will be skipped"
    fi
  fi
done

# ============================================
# MERGE ALL CACHE FILES
# ============================================
tmp_merge="$CACHE_DIR/_merge_work.tmp"
: > "$tmp_merge"
loaded_asns=""

for asn in $asns; do
  cache_file="$CACHE_DIR/${asn}.txt"
  if [ -f "$cache_file" ] && [ -s "$cache_file" ]; then
    cat "$cache_file" >> "$tmp_merge"
    loaded_asns="${loaded_asns} $asn"
  else
    log "  $asn: no data available -- skipped in merge"
  fi
done

if [ ! -s "$tmp_merge" ]; then
  log "ERROR: No prefix data available for any ASN -- table unchanged"
  rm -f "$tmp_merge"
  exit 1
fi

# Global sort+dedup across all ASNs
# sort -u handles IPv4 and IPv6 correctly
grep -v '^[[:space:]]*$' "$tmp_merge" | sort -u > "$MERGED_FILE"
rm -f "$tmp_merge"

total_merged=$(wc -l < "$MERGED_FILE" | tr -d ' ')
log "Merged: $total_merged unique prefixes from:$loaded_asns"

# Diff vs previous run for audit trail
if [ -f "$PREV_MERGED" ]; then
  added=$(comm -13 "$PREV_MERGED" "$MERGED_FILE" | wc -l | tr -d ' ')
  removed=$(comm -23 "$PREV_MERGED" "$MERGED_FILE" | wc -l | tr -d ' ')
  log "Delta vs last run: +$added added, -$removed removed"
fi
cp "$MERGED_FILE" "$PREV_MERGED"

# ============================================
# LOAD INTO PF TABLE VIA FILE
#
# pfctl -T replace -f reads line-by-line from file.
# No ARG_MAX issue regardless of prefix count.
# Works for both IPv4 and IPv6 prefixes in the same table.
# PF resolves address family per-entry at load time.
# ============================================
if ! pfctl -a addons -t "$TABLE" -T show > /dev/null 2>&1; then
  log "Table <$TABLE> not yet active in anchor 'addons'"
  log "Prefixes saved to $MERGED_FILE -- will load on next pf_monitor apply"
  exit 0
fi

if pfctl -a addons -t "$TABLE" -T replace -f "$MERGED_FILE" 2> /dev/null; then
  log "Table <$TABLE> replaced: $total_merged prefixes loaded"
else
  log "ERROR: pfctl -T replace failed -- attempting flush + add"
  pfctl -a addons -t "$TABLE" -T flush 2> /dev/null || true
  if pfctl -a addons -t "$TABLE" -T add -f "$MERGED_FILE" 2> /dev/null; then
    log "Table <$TABLE> loaded via flush+add: $total_merged prefixes"
  else
    log "FATAL: could not load prefixes into <$TABLE>"
    exit 1
  fi
fi

log "=== pf_asn_resolve complete (fetch errors: $fetch_errors) ==="
exit 0
