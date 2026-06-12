#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_asn_lookup_runner.sh
#
# Purpose: Root-side ASN impact analysis helper.
#          Called by pf_asn_lookup.pl (www/CGI) via trigger file.
#          Queries PeeringDB + RIPE STAT + PTR record.
#          Writes result JSON to a www-readable location.
#
# Privilege model:
#   - Runs as root (needed for outbound ftp/curl on OpenBSD without chroot)
#   - Input:  /var/www/htdocs/tn/data/services/queue/pf-rules/asn-lookup/request/<ASN>
#   - Output: /var/www/htdocs/tn/data/services/queue/pf-rules/asn-lookup/result/<ASN>.json
#
# Called from: pf_asn_lookup_daemon.sh (poll loop, every 1s)
# Not meant to be called directly.

set -e

QUEUE_BASE="/var/www/htdocs/tn/data/services/queue/pf-rules/asn-lookup"
REQUEST_DIR="$QUEUE_BASE/request"
RESULT_DIR="$QUEUE_BASE/result"
LOG_FILE="/var/www/tmp/pf_asn_lookup.log"
TIMEOUT=10 # seconds for each HTTP request

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [asn-lookup] $*" | tee -a "$LOG_FILE"
}

# ============================================
# JSON escape helper (no jq dependency)
# ============================================
json_escape() {
  local s="$1"
  # Escape backslash, double-quote, control chars
  printf '%s' "$s" \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g' \
    | tr -d '\000-\037'
}

# ============================================
# ENSURE DIRS
# ============================================
[ ! -d "$REQUEST_DIR" ] && mkdir -p "$REQUEST_DIR"
[ ! -d "$RESULT_DIR" ] && mkdir -p "$RESULT_DIR"
[ ! -d /var/www/tmp ] && mkdir -p /var/www/tmp

# ============================================
# FIND PENDING REQUEST
# ============================================
REQUEST_FILE=$(ls -t "$REQUEST_DIR"/AS* 2> /dev/null | head -1)

if [ -z "$REQUEST_FILE" ]; then
  exit 0 # Nothing to do
fi

ASN=$(basename "$REQUEST_FILE") # e.g. AS15169
ASN_NUM=$(echo "$ASN" | sed 's/^AS//i')

log "Processing lookup for $ASN"

# Remove request file immediately to prevent double-processing
rm -f "$REQUEST_FILE"

RESULT_FILE="$RESULT_DIR/${ASN}.json"

# ============================================
# HELPER: HTTP GET with timeout
# Uses ftp(1) on OpenBSD as the HTTP client
# ftp -o - URL writes to stdout
# ============================================
http_get() {
  local url="$1"
  ftp -V -o - "$url" 2> /dev/null
}

# ============================================
# 1. PEERINGDB QUERY
# https://www.peeringdb.com/api/net?asn=<NUM>
# Fields we use:
#   name       - Organisation name
#   info_type  - Content / NSP / ISP / Cable/DSL/ISP /
#                Educational/Research / Non-Profit / Other
#   info_prefixes4  - IPv4 prefix count
#   info_prefixes6  - IPv6 prefix count
#   policy_general  - Open / Selective / Restrictive / No
#   notes      - Operator notes (often identifies services)
# ============================================
log "Querying PeeringDB for $ASN..."

PDB_RAW=$(http_get "https://www.peeringdb.com/api/net?asn=$ASN_NUM" 2> /dev/null || true)

# Extract fields with sed - PeeringDB returns {"data":[{...}]}
# We parse conservatively -- missing fields become empty strings
ORG_NAME=$(echo "$PDB_RAW" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p' | head -1)
NET_TYPE=$(echo "$PDB_RAW" | sed -n 's/.*"info_type":"\([^"]*\)".*/\1/p' | head -1)
PFX4=$(echo "$PDB_RAW" | sed -n 's/.*"info_prefixes4":\([0-9]*\).*/\1/p' | head -1)
PFX6=$(echo "$PDB_RAW" | sed -n 's/.*"info_prefixes6":\([0-9]*\).*/\1/p' | head -1)
POLICY=$(echo "$PDB_RAW" | sed -n 's/.*"policy_general":"\([^"]*\)".*/\1/p' | head -1)
PDB_NOTES=$(echo "$PDB_RAW" | sed -n 's/.*"notes":"\([^"]*\)".*/\1/p' | head -1 | cut -c1-200)

# Fallback org name if PeeringDB has no entry
[ -z "$ORG_NAME" ] && ORG_NAME="Unknown (not in PeeringDB)"
[ -z "$NET_TYPE" ] && NET_TYPE="Unknown"
[ -z "$PFX4" ] && PFX4="0"
[ -z "$PFX6" ] && PFX6="0"

log "PeeringDB: org=$ORG_NAME type=$NET_TYPE prefixes4=$PFX4 prefixes6=$PFX6"

# ============================================
# 2. RIPE STAT -- announced prefixes + prefix count
# https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<NUM>
# ============================================
log "Querying RIPE STAT for announced prefixes..."

RIPE_RAW=$(http_get "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS$ASN_NUM" 2> /dev/null || true)

# Count total prefixes
PREFIX_COUNT=$(echo "$RIPE_RAW" | grep -o '"prefix"' | wc -l | tr -d ' ')
[ -z "$PREFIX_COUNT" ] && PREFIX_COUNT="0"

# Grab first IPv4 prefix for PTR sampling
SAMPLE_PREFIX=$(echo "$RIPE_RAW" \
  | grep -o '"prefix":"[0-9][^"]*"' \
  | head -1 \
  | sed 's/"prefix":"//;s/"//')

SAMPLE_IP=""
if [ -n "$SAMPLE_PREFIX" ]; then
  SAMPLE_IP=$(echo "$SAMPLE_PREFIX" | cut -d'/' -f1)
fi

log "RIPE STAT: $PREFIX_COUNT prefixes announced, sample IP: $SAMPLE_IP"

# ============================================
# 3. PTR RECORD -- operational hint
# host(1) is available on OpenBSD base
# ============================================
PTR_RECORD=""
if [ -n "$SAMPLE_IP" ]; then
  log "Resolving PTR for $SAMPLE_IP..."
  PTR_RAW=$(host "$SAMPLE_IP" 2> /dev/null || true)
  # host output: "1.113.0.203.in-addr.arpa domain name pointer foo.example.com."
  PTR_RECORD=$(echo "$PTR_RAW" | awk '/pointer/ {print $NF}' | sed 's/\.$//' | head -1)
  [ -z "$PTR_RECORD" ] && PTR_RECORD=""
  log "PTR: $PTR_RECORD"
fi

# ============================================
# 4. CLASSIFY IMPACT LEVEL
#
# Levels: CRITICAL / HIGH / MEDIUM / INFO
#
# CRITICAL -- transit providers, large CDNs.
#   Blocking these breaks large parts of the internet
#   for everyone behind this firewall.
#
# HIGH -- major content/cloud platforms.
#   Blocking these breaks specific widely-used services.
#
# MEDIUM -- regional ISPs, smaller content networks.
#   Impact is real but contained.
#
# INFO -- educational, non-profit, small corporate.
#   Low collateral damage expected.
# ============================================

IMPACT_LEVEL="INFO"
IMPACT_REASON=""

case "$NET_TYPE" in
  "NSP")
    IMPACT_LEVEL="CRITICAL"
    IMPACT_REASON="Network Service Provider -- carries transit for many other networks"
    ;;
  "Content")
    if [ "$PREFIX_COUNT" -gt 100 ] 2> /dev/null; then
      IMPACT_LEVEL="CRITICAL"
      IMPACT_REASON="Large content network with $PREFIX_COUNT announced prefixes"
    else
      IMPACT_LEVEL="HIGH"
      IMPACT_REASON="Content delivery network"
    fi
    ;;
  "Cable/DSL/ISP" | "ISP")
    IMPACT_LEVEL="HIGH"
    IMPACT_REASON="Internet Service Provider -- blocking affects all customers of this ISP"
    ;;
  "Educational/Research")
    IMPACT_LEVEL="MEDIUM"
    IMPACT_REASON="Educational or research network"
    ;;
  "Non-Profit")
    IMPACT_LEVEL="MEDIUM"
    IMPACT_REASON="Non-profit organisation network"
    ;;
  *)
    if [ "$PREFIX_COUNT" -gt 200 ] 2> /dev/null; then
      IMPACT_LEVEL="HIGH"
      IMPACT_REASON="Large network with $PREFIX_COUNT announced prefixes"
    elif [ "$PREFIX_COUNT" -gt 50 ] 2> /dev/null; then
      IMPACT_LEVEL="MEDIUM"
      IMPACT_REASON="Mid-sized network with $PREFIX_COUNT announced prefixes"
    else
      IMPACT_LEVEL="INFO"
      IMPACT_REASON="Small or standard corporate network"
    fi
    ;;
esac

# ============================================
# 5. HUMAN-READABLE WARNING TEXT
#    Written for a school IT coordinator,
#    not a network engineer.
# ============================================

case "$IMPACT_LEVEL" in
  "CRITICAL")
    WARNING_TEXT="This is a major internet infrastructure provider. Blocking it could break access to many websites and services for everyone on your network, not just traffic from ${ORG_NAME}. Proceed only if you have a specific, verified reason."
    ;;
  "HIGH")
    WARNING_TEXT="This network serves a large number of users or hosts widely-used services. Blocking it will likely have visible impact on your users. Review carefully before applying."
    ;;
  "MEDIUM")
    WARNING_TEXT="This is a mid-sized network. Blocking it may affect some services your users rely on. Verify the impact before applying."
    ;;
  "INFO")
    WARNING_TEXT="This appears to be a small or standard organisational network. Impact of blocking should be limited, but verify if you are unsure."
    ;;
esac

# ============================================
# 6. WRITE RESULT JSON
# ============================================

ORG_NAME_ESC=$(json_escape "$ORG_NAME")
NET_TYPE_ESC=$(json_escape "$NET_TYPE")
PTR_ESC=$(json_escape "$PTR_RECORD")
WARNING_ESC=$(json_escape "$WARNING_TEXT")
IMPACT_ESC=$(json_escape "$IMPACT_REASON")
NOTES_ESC=$(json_escape "$PDB_NOTES")

cat > "$RESULT_FILE" << EOF
{
    "asn": "$ASN",
    "org_name": "$ORG_NAME_ESC",
    "net_type": "$NET_TYPE_ESC",
    "prefix_count": $PREFIX_COUNT,
    "ipv4_prefixes": $PFX4,
    "ipv6_prefixes": $PFX6,
    "sample_ptr": "$PTR_ESC",
    "impact_level": "$IMPACT_LEVEL",
    "impact_reason": "$IMPACT_ESC",
    "warning_text": "$WARNING_ESC",
    "peeringdb_notes": "$NOTES_ESC",
    "timestamp": $(date +%s),
    "ready": true
}
EOF

chown www:www "$RESULT_FILE"
chmod 0644 "$RESULT_FILE"

log "Result written to $RESULT_FILE (impact: $IMPACT_LEVEL)"
exit 0
