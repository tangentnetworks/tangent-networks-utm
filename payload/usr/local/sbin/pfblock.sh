#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# pfblock.sh - OpenBSD PF blocklist automation (linear style)
set -eu

# ============================================================================
# Configuration
# ============================================================================
PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin"
export PATH
INTEL_CONFIG="/etc/pf/intel.txt"
LOGDIR="/var/www/htdocs/tn/data/logs/cron/"
PFCONF="/etc/pf.conf"
PF_TABLES="blocklist bogons snort_block"
FEEDDIR="/etc/pf/feeds"
IPLIST="/etc/pf/blocklist"
BOGON_FILE="/etc/pf/bogonranges"
IPTMP="/etc/pf/blocklist.tmp"
CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
CRONTAB_FILE="/etc/crontab"
CRON_JOB="0 11 * * * root /usr/local/sbin/pfblock.sh"
CRON_COMMENT="# Auto-generated cron job for pfblock.sh at 11 AM daily"
ORIGINAL_ULIMIT=""

# ============================================================================
# ulimit Management
# ============================================================================
check_and_adjust_ulimit() {
  ORIGINAL_ULIMIT=$(ulimit -n)
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Current ulimit -n: $ORIGINAL_ULIMIT" | tee -a "$LOGFILE"

  if [ "$ORIGINAL_ULIMIT" -lt 2048 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ulimit is below 2048, increasing to 2048..." | tee -a "$LOGFILE"
    ulimit -n 2048
    if [ $? -eq 0 ]; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] ulimit increased to 2048" | tee -a "$LOGFILE"
    else
      echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to increase ulimit" | tee -a "$LOGFILE"
    fi
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ulimit is sufficient (>= 2048)" | tee -a "$LOGFILE"
  fi
}

restore_ulimit() {
  if [ -n "$ORIGINAL_ULIMIT" ] && [ "$ORIGINAL_ULIMIT" -lt 2048 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Restoring original ulimit to $ORIGINAL_ULIMIT..." | tee -a "$LOGFILE"
    ulimit -n "$ORIGINAL_ULIMIT"
  fi
}

# Set trap to restore ulimit on exit
trap restore_ulimit EXIT INT TERM

# ============================================================================
# Logging Setup
# ============================================================================
LOGFILE="$LOGDIR/pf_update-$(date +%Y-%m-%d_%H-%M-%S).log"
mkdir -p "$LOGDIR" "$FEEDDIR"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Starting PF blocklist update" | tee -a "$LOGFILE"

# Check ulimit
check_and_adjust_ulimit

# Verify intel configuration file exists
if [ ! -f "$INTEL_CONFIG" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Intel configuration file not found: $INTEL_CONFIG" | tee -a "$LOGFILE"
  exit 1
fi

# ============================================================================
# Parse Intel Configuration
# ============================================================================
parse_intel_config() {
  local category=$1
  grep "^${category}:" "$INTEL_CONFIG" | sed "s/^${category}: *//" | grep -v "^#" | grep -v "^$"
}

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Reading intel feeds from $INTEL_CONFIG..." | tee -a "$LOGFILE"

IP_FEEDS=$(parse_intel_config "IP")
BOGON_FEED=$(parse_intel_config "BOGONS" | head -1)
CSVLIST=$(parse_intel_config "CSV" | head -1)

# ============================================================================
# Download Function with Error Reporting
# ============================================================================
download_feed() {
  local url=$1
  local fpath=$2
  local feed_type=$3

  fname=$(basename "$url")
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Checking $feed_type feed: $fname" | tee -a "$LOGFILE"

  # Create a temporary file for curl output
  curl_output=$(mktemp)

  if [ -f "$fpath" ]; then
    curl -sf -z "$fpath" -A "$CURL_UA" -o "$fpath" -w "HTTP_CODE:%{http_code}\n" "$url" > "$curl_output" 2>&1
    curl_exit=$?
  else
    curl -sf -A "$CURL_UA" -o "$fpath" -w "HTTP_CODE:%{http_code}\n" "$url" > "$curl_output" 2>&1
    curl_exit=$?
  fi

  # Extract HTTP code from curl output
  http_code=$(grep "HTTP_CODE:" "$curl_output" | tail -1 | cut -d: -f2)

  if [ $curl_exit -eq 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Updated or verified: $fname (HTTP $http_code)" | tee -a "$LOGFILE"
    rm -f "$curl_output"
    return 0
  else
    # Determine specific error reason
    error_reason="Unknown error"
    case $curl_exit in
      6) error_reason="Could not resolve host" ;;
      7) error_reason="Failed to connect to host" ;;
      22) error_reason="HTTP error (code: ${http_code:-N/A})" ;;
      28) error_reason="Operation timeout" ;;
      35) error_reason="SSL connection error" ;;
      52) error_reason="Empty reply from server" ;;
      56) error_reason="Failure in receiving network data" ;;
      *) error_reason="curl exit code $curl_exit" ;;
    esac

    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to download $fname from $url" | tee -a "$LOGFILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Reason: $error_reason" | tee -a "$LOGFILE"

    # Log curl output for debugging
    if [ -s "$curl_output" ]; then
      cat "$curl_output" >> "$LOGFILE"
    fi

    rm -f "$curl_output"
    return 1
  fi
}

# ============================================================================
# Download IP Feeds
# ============================================================================
if [ -n "$IP_FEEDS" ]; then
  echo "$IP_FEEDS" | while read -r url; do
    [ -z "$url" ] && continue
    fname=$(basename "$url")
    fpath="$FEEDDIR/$fname"
    download_feed "$url" "$fpath" "IP"
  done
fi

# ============================================================================
# Download Bogons
# ============================================================================
if [ -n "$BOGON_FEED" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Downloading bogon ranges" | tee -a "$LOGFILE"

  curl_output=$(mktemp)
  curl -sf -A "$CURL_UA" -w "HTTP_CODE:%{http_code}\n" "$BOGON_FEED" > "$curl_output" 2>&1
  curl_exit=$?

  http_code=$(grep "HTTP_CODE:" "$curl_output" | tail -1 | cut -d: -f2)

  if [ $curl_exit -eq 0 ]; then
    # Filter out private IP ranges
    grep -v "HTTP_CODE:" "$curl_output" | sed -E '/192\.168\.0\.0\/16|172\.16\.0\.0\/12|10\.0\.0\.0\/8|127\.0\.0\.0\/8|0\.0\.0\.0\/8|169\.254\.0\.0\/16/d' > "$BOGON_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Downloaded bogon ranges (HTTP $http_code)" | tee -a "$LOGFILE"
  else
    error_reason="Unknown error"
    case $curl_exit in
      6) error_reason="Could not resolve host" ;;
      7) error_reason="Failed to connect to host" ;;
      22) error_reason="HTTP error (code: ${http_code:-N/A})" ;;
      28) error_reason="Operation timeout" ;;
      35) error_reason="SSL connection error" ;;
      52) error_reason="Empty reply from server" ;;
      56) error_reason="Failure in receiving network data" ;;
      *) error_reason="curl exit code $curl_exit" ;;
    esac

    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to download bogon ranges from $BOGON_FEED" | tee -a "$LOGFILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Reason: $error_reason" | tee -a "$LOGFILE"
  fi

  rm -f "$curl_output"
fi

# ============================================================================
# Download CSV
# ============================================================================
if [ -n "$CSVLIST" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Downloading CSV feed" | tee -a "$LOGFILE"

  curl_output=$(mktemp)
  curl -sf -L -A "$CURL_UA" -o "$FEEDDIR/data.csv" -w "HTTP_CODE:%{http_code}\n" "$CSVLIST" > "$curl_output" 2>&1
  curl_exit=$?

  http_code=$(grep "HTTP_CODE:" "$curl_output" | tail -1 | cut -d: -f2)

  if [ $curl_exit -eq 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Downloaded CSV feed (HTTP $http_code)" | tee -a "$LOGFILE"
  else
    error_reason="Unknown error"
    case $curl_exit in
      6) error_reason="Could not resolve host" ;;
      7) error_reason="Failed to connect to host" ;;
      22) error_reason="HTTP error (code: ${http_code:-N/A})" ;;
      28) error_reason="Operation timeout" ;;
      35) error_reason="SSL connection error" ;;
      52) error_reason="Empty reply from server" ;;
      56) error_reason="Failure in receiving network data" ;;
      *) error_reason="curl exit code $curl_exit" ;;
    esac

    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to download CSV feed from $CSVLIST" | tee -a "$LOGFILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Reason: $error_reason" | tee -a "$LOGFILE"
  fi

  rm -f "$curl_output"
fi

# ============================================================================
# Extract IPs
# ============================================================================
: > "$IPTMP"
for feed in "$FEEDDIR"/*; do
  [ -f "$feed" ] && grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$feed" \
    | awk -F'[/.]' '($1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255) { print $1"."$2"."$3"."$4 (NF > 4 ? "/"$5 : "") }' >> "$IPTMP"
done

# Extract IPs from CSV
csv="$FEEDDIR/data.csv"
[ -f "$csv" ] && awk -F, '{ for (i = 1; i <= NF; i++) if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$/) print $i }' "$csv" >> "$IPTMP" 2> /dev/null || true

# Sort and deduplicate
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Sorting and deduplicating IP list" | tee -a "$LOGFILE"
sort -u "$IPTMP" -o "$IPLIST" 2> /dev/null || cat "$IPTMP" > "$IPLIST"
rm -f "$IPTMP"

ip_count=$(wc -l < "$IPLIST" 2> /dev/null || echo "0")
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Total unique IPs/CIDRs extracted: $ip_count" | tee -a "$LOGFILE"

# ============================================================================
# PF Configuration
# ============================================================================
if ! grep -q '^table <blocklist>' "$PFCONF" 2> /dev/null; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Appending persist table definitions to pf.conf" | tee -a "$LOGFILE"
  cat >> "$PFCONF" << 'EOF'
# Auto-generated by pfblock.sh - persist tables (no file backing)
table <blocklist> persist
block in quick from <blocklist>
table <bogons> persist
block in quick from <bogons>
EOF
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] PF configuration already contains table definitions" | tee -a "$LOGFILE"
fi

# Ensure tables exist
for table in $PF_TABLES; do
  if pfctl -s Tables 2> /dev/null | grep -qx "$table"; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Table <$table> exists in PF memory" | tee -a "$LOGFILE"
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Creating table <$table> in PF memory" | tee -a "$LOGFILE"
    pfctl -t "$table" -T replace -f /dev/null 2> /dev/null || true
  fi
done

# Load tables
[ -f "$IPLIST" ] || touch "$IPLIST"
[ -f "$BOGON_FILE" ] || touch "$BOGON_FILE"

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Atomically replacing table: blocklist" | tee -a "$LOGFILE"
if pfctl -t blocklist -T replace -f "$IPLIST" >> "$LOGFILE" 2>&1; then
  blocklist_count=$(pfctl -t blocklist -T show 2> /dev/null | wc -l)
  echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Blocklist table updated ($blocklist_count entries)" | tee -a "$LOGFILE"
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to replace blocklist table" | tee -a "$LOGFILE" >&2
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Atomically replacing table: bogons" | tee -a "$LOGFILE"
if pfctl -t bogons -T replace -f "$BOGON_FILE" >> "$LOGFILE" 2>&1; then
  bogons_count=$(pfctl -t bogons -T show 2> /dev/null | wc -l)
  echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Bogons table updated ($bogons_count entries)" | tee -a "$LOGFILE"
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to replace bogons table" | tee -a "$LOGFILE" >&2
fi

# Reload PF if enabled
if pfctl -s info 2> /dev/null | grep -q 'Status: Enabled'; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] PF is enabled - reloading configuration" | tee -a "$LOGFILE"

  for table in $PF_TABLES; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Flushing table: $table" | tee -a "$LOGFILE"
    pfctl -t "$table" -T flush 2> /dev/null || true
  done
  if pfctl -f "$PFCONF" >> "$LOGFILE" 2>&1; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] PF configuration reloaded successfully" | tee -a "$LOGFILE"
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to reload pf.conf" | tee -a "$LOGFILE" >&2
  fi
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] PF is not enabled - skipping configuration reload" | tee -a "$LOGFILE"
fi

# ============================================================================
# Cron Job Management
# ============================================================================
if grep -qF "$CRON_JOB" "$CRONTAB_FILE"; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Cron job already exists in $CRONTAB_FILE" | tee -a "$LOGFILE"
else
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Adding cron job to $CRONTAB_FILE" | tee -a "$LOGFILE"
  cp "$CRONTAB_FILE" "$CRONTAB_FILE.bak" || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to backup $CRONTAB_FILE" | tee -a "$LOGFILE" >&2
    exit 1
  }
  TMP_FILE="$CRONTAB_FILE.tmp"
  cp "$CRONTAB_FILE" "$TMP_FILE" || {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to copy $CRONTAB_FILE to $TMP_FILE" | tee -a "$LOGFILE" >&2
    exit 1
  }
  echo "$CRON_COMMENT" >> "$TMP_FILE"
  echo "$CRON_JOB" >> "$TMP_FILE"
  if ! grep -qF "$CRON_JOB" "$TMP_FILE"; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Cron job not appended to $TMP_FILE" | tee -a "$LOGFILE" >&2
    rm -f "$TMP_FILE"
    exit 1
  fi
  mv "$TMP_FILE" "$CRONTAB_FILE" && chmod 644 "$CRONTAB_FILE"
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Successfully updated $CRONTAB_FILE" | tee -a "$LOGFILE"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] PF blocklist update completed successfully" | tee -a "$LOGFILE"
