#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# =============================================================================
# e2g_get_intel.sh -- E2Guardian Adult Filter Intel Gatherer
# =============================================================================
#
# PURPOSE:
#   Downloads and processes all feed sources defined in feeds/general.txt,
#   builds the adult domain/URL blocklists under /etc/e2guardian/lists/,
#   and deploys the filter configuration template.
#
#   This script performs LIST GENERATION ONLY. It does NOT start, stop,
#   or reload e2guardian, and does NOT touch /etc/crontab.
#
#   It is called by TN_PKG_INSTALL.sh (Phase 7, Step 14b) during initial
#   appliance installation, before the Phase 9 smoke tests bring e2guardian
#   up for the first time.
#
#   The cron-triggered daily script (e2g_adult_filter.sh) handles
#   start/reload after list regeneration on a running system.
#
# USAGE:
#   /usr/local/sbin/e2g_get_intel.sh
#   (called automatically by TN_PKG_INSTALL.sh -- not normally run directly)
#
# OUTPUT:
#   /etc/e2guardian/lists/blacklists/adult/domains
#   /etc/e2guardian/lists/blacklists/adult/urls
#   /etc/e2guardian/lists/localexceptionsitelist  (Capitole whitelist entries)
#   /etc/feeds/adult/blockdomains
#   /etc/e2guardian/e2guardianf1.conf             (copied from .a template)
#
# AUTHOR:  Tangent Networks
# VERSION: 1.0.0
# =============================================================================

PATH="/sbin:/usr/sbin:/bin:/usr/bin:/usr/X11R6/bin:/usr/local/sbin:/usr/local/bin"
export PATH

set -eu

SCRIPT_NAME=$(basename "$0")
FILTER_TYPE="adult"
FILTER_TYPE_UPPER="ADULT"
LOGFILE="/tmp/e2guardian-feed.log"
FEEDS_CONFIG="/etc/e2guardian/feeds/general.txt"

# Work directories - ISOLATED per filter type
WORKDIR="/etc/feeds/${FILTER_TYPE}"
HOSTFILESDIR="${WORKDIR}/hostfiles"
DOMAINSDIR="${WORKDIR}/domains"
ADVDIR="${WORKDIR}/ads"
MIXDIR="${WORKDIR}/mix"
PORNDIR="${WORKDIR}/porn"
NEW_FEEDS_DIR="${WORKDIR}/new_feeds"
RAWDOMAINSLIST="${WORKDIR}/domains.new"
DOMAINLIST="${WORKDIR}/blockdomains"

# Output directories - ISOLATED per filter type
E2GLISTSDIR="/etc/e2guardian/lists/blacklists/adult"
E2GURLS="$E2GLISTSDIR/urls"
E2GDOMAINS="$E2GLISTSDIR/domains"

# Config files
FILTERFILE="/etc/e2guardian/e2guardianf1.conf"
FILTERFILETEMPLATE="/etc/e2guardian/e2guardianf1.conf.a"
CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
ORIGINAL_ULIMIT=""

# =============================================================================
# ULIMIT
# =============================================================================
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

trap restore_ulimit EXIT INT TERM

check_and_adjust_ulimit

# =============================================================================
# DIRECTORIES
# =============================================================================
mkdir -p "$HOSTFILESDIR" "$DOMAINSDIR" "$ADVDIR" "$MIXDIR" "$PORNDIR" "$NEW_FEEDS_DIR" "$E2GLISTSDIR"

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ========================================" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] E2Guardian ${FILTER_TYPE_UPPER} Intel Gatherer" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Work directory: $WORKDIR" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Output directory: $E2GLISTSDIR" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ========================================" | tee -a "$LOGFILE"

# =============================================================================
# FEEDS CONFIG
# =============================================================================
if [ ! -f "$FEEDS_CONFIG" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Feeds configuration file not found: $FEEDS_CONFIG" | tee -a "$LOGFILE"
  exit 1
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Cleaning up old files in work directory..." | tee -a "$LOGFILE"
rm -f "${WORKDIR}"/*.new 2> /dev/null || true
rm -f "${WORKDIR}"/feeds-*.log 2> /dev/null || true

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Cleaning up new_feeds directory..." | tee -a "$LOGFILE"
rm -rf "$NEW_FEEDS_DIR"/* 2> /dev/null || true

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Reading feeds from $FEEDS_CONFIG..." | tee -a "$LOGFILE"

HOSTFILES=$(grep "^HOSTFILE:" "$FEEDS_CONFIG" 2> /dev/null | sed "s/^HOSTFILE: *//" | grep -v "^#" | grep -v "^$" || true)
PORNDOMAINS=$(grep "^PORN:" "$FEEDS_CONFIG" 2> /dev/null | sed "s/^PORN: *//" | grep -v "^#" | grep -v "^$" || true)
DOMAINSLIST=$(grep "^DOMAIN:" "$FEEDS_CONFIG" 2> /dev/null | sed "s/^DOMAIN: *//" | grep -v "^#" | grep -v "^$" || true)
MIXLIST=$(grep "^MIXED:" "$FEEDS_CONFIG" 2> /dev/null | sed "s/^MIXED: *//" | grep -v "^#" | grep -v "^$" || true)
ADVERTISERS=$(grep "^ADVERTISER:" "$FEEDS_CONFIG" 2> /dev/null | sed "s/^ADVERTISER: *//" | grep -v "^#" | grep -v "^$" || true)
CAPITOLEARCHIVE=$(grep "^CAPITOLE:" "$FEEDS_CONFIG" 2> /dev/null | sed "s/^CAPITOLE: *//" | grep -v "^#" | grep -v "^$" | head -1 || true)

[ -n "$HOSTFILES" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Found HOSTFILE entries" | tee -a "$LOGFILE"
[ -n "$PORNDOMAINS" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Found PORN entries" | tee -a "$LOGFILE"
[ -n "$DOMAINSLIST" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Found DOMAIN entries" | tee -a "$LOGFILE"
[ -n "$MIXLIST" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Found MIXED entries" | tee -a "$LOGFILE"
[ -n "$ADVERTISERS" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Found ADVERTISER entries" | tee -a "$LOGFILE"
[ -n "$CAPITOLEARCHIVE" ] && echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Found CAPITOLE entry" | tee -a "$LOGFILE"

# =============================================================================
# DOWNLOAD
# =============================================================================
download_feeds() {
  feed_list=$1
  target_dir=$2
  category_name=$3

  echo "$feed_list" | while read -r url; do
    [ -z "$url" ] && continue
    fname=$(basename "$url")
    fpath="$target_dir/$fname"

    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Checking $fname..." | tee -a "$LOGFILE"

    curl_output=$(mktemp)

    if [ -f "$fpath" ]; then
      if curl -sf --connect-timeout 15 --max-time 60 -z "$fpath" -o "$fpath" -A "$CURL_UA" -w "HTTP_CODE:%{http_code}\n" "$url" > "$curl_output" 2>&1; then
        curl_exit=0
      else
        curl_exit=$?
      fi
    else
      if curl -sf --connect-timeout 15 --max-time 60 -o "$fpath" -A "$CURL_UA" -w "HTTP_CODE:%{http_code}\n" "$url" > "$curl_output" 2>&1; then
        curl_exit=0
      else
        curl_exit=$?
      fi
    fi

    http_code=$(grep "HTTP_CODE:" "$curl_output" | tail -1 | cut -d: -f2)

    if [ $curl_exit -eq 0 ]; then
      if [ -s "$fpath" ] && grep -q "<html" "$fpath" 2> /dev/null; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Bad content from $fname (HTML response) - removing" | tee -a "$LOGFILE"
        rm -f "$fpath"
      else
        echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Updated or verified: $fname (HTTP $http_code)" | tee -a "$LOGFILE"
      fi
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

      echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to download $fname from $url" | tee -a "$LOGFILE"
      echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Reason: $error_reason" | tee -a "$LOGFILE"
      if [ -f "$fpath" ] && [ ! -s "$fpath" ]; then
        rm -f "$fpath"
        echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Removed zero-byte $fname - no cached version available" | tee -a "$LOGFILE"
      elif [ -f "$fpath" ] && [ -s "$fpath" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] Failed to download $fname - using cached version" | tee -a "$LOGFILE"
      fi
      if [ -s "$curl_output" ]; then
        cat "$curl_output" >> "$LOGFILE"
      fi
    fi

    rm -f "$curl_output"
  done
}

[ -n "$HOSTFILES" ] && {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Downloading hostfiles..." | tee -a "$LOGFILE"
  download_feeds "$HOSTFILES" "$HOSTFILESDIR" "HOSTFILE"
}
[ -n "$PORNDOMAINS" ] && {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Downloading porn domains..." | tee -a "$LOGFILE"
  download_feeds "$PORNDOMAINS" "$PORNDIR" "PORN"
}
[ -n "$DOMAINSLIST" ] && {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Downloading domains..." | tee -a "$LOGFILE"
  download_feeds "$DOMAINSLIST" "$DOMAINSDIR" "DOMAIN"
}
[ -n "$MIXLIST" ] && {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Downloading mixed lists..." | tee -a "$LOGFILE"
  download_feeds "$MIXLIST" "$MIXDIR" "MIXED"
}
[ -n "$ADVERTISERS" ] && {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Downloading advertisers..." | tee -a "$LOGFILE"
  download_feeds "$ADVERTISERS" "$ADVDIR" "ADVERTISER"
}

# =============================================================================
# CAPITOLE ARCHIVE
# =============================================================================
if [ -n "$CAPITOLEARCHIVE" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Downloading Capitole archive..." | tee -a "$LOGFILE"
  cap_fname=$(basename "$CAPITOLEARCHIVE")
  cap_fpath="${WORKDIR}/$cap_fname"

  curl_output=$(mktemp)

  if [ -f "$cap_fpath" ]; then
    if curl -sf --connect-timeout 30 --max-time 600 -z "$cap_fpath" -o "$cap_fpath" -A "$CURL_UA" -w "HTTP_CODE:%{http_code}\n" "$CAPITOLEARCHIVE" > "$curl_output" 2>&1; then
      curl_exit=0
    else
      curl_exit=$?
    fi
  else
    if curl -sf --connect-timeout 30 --max-time 600 -o "$cap_fpath" -A "$CURL_UA" -w "HTTP_CODE:%{http_code}\n" "$CAPITOLEARCHIVE" > "$curl_output" 2>&1; then
      curl_exit=0
    else
      curl_exit=$?
    fi
  fi

  http_code=$(grep "HTTP_CODE:" "$curl_output" | tail -1 | cut -d: -f2)

  if [ $curl_exit -eq 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Updated or verified: $cap_fname (HTTP $http_code)" | tee -a "$LOGFILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Extracting Capitole archive..." | tee -a "$LOGFILE"
    if tar -xzf "$cap_fpath" -C "${WORKDIR}/" 2>&1 | tee -a "$LOGFILE"; then
      echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Capitole archive extracted successfully." | tee -a "$LOGFILE"
    else
      echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to extract Capitole archive." | tee -a "$LOGFILE"
    fi
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Failed to download Capitole archive." | tee -a "$LOGFILE"
  fi

  rm -f "$curl_output"

  if [ -d "${WORKDIR}/blacklists" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Processing Capitole categories..." | tee -a "$LOGFILE"

    cap_blackdirs=$(find "${WORKDIR}/blacklists" -type f -name "usage" -exec grep -li "^black" {} + 2> /dev/null | sed 's|/usage$||')
    cap_whitedirs=$(find "${WORKDIR}/blacklists" -type f -name "usage" -exec grep -li "^white" {} + 2> /dev/null | sed 's|/usage$||')

    > "$E2GDOMAINS" 2> /dev/null || true
    > "$E2GURLS" 2> /dev/null || true

    echo "$cap_blackdirs" | while read -r cap_dir; do
      [ -z "$cap_dir" ] && continue
      cap_cat=$(basename "$cap_dir")
      if [ -f "${cap_dir}/domains" ]; then
        cat "${cap_dir}/domains" >> "$E2GDOMAINS" 2> /dev/null || true
        echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Capitole blacklist domains: $cap_cat" | tee -a "$LOGFILE"
      fi
      if [ -f "${cap_dir}/urls" ]; then
        cat "${cap_dir}/urls" >> "$E2GURLS" 2> /dev/null || true
        echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Capitole blacklist urls: $cap_cat" | tee -a "$LOGFILE"
      fi
    done

    sort -u "$E2GDOMAINS" -o "$E2GDOMAINS" 2> /dev/null || true
    sort -u "$E2GURLS" -o "$E2GURLS" 2> /dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Capitole blacklist merged." | tee -a "$LOGFILE"

    CAP_WL_TMP="${WORKDIR}/capitole_wl.tmp"
    > "$CAP_WL_TMP" 2> /dev/null || true
    echo "$cap_whitedirs" | while read -r cap_dir; do
      [ -z "$cap_dir" ] && continue
      cap_cat=$(basename "$cap_dir")
      if [ -f "${cap_dir}/domains" ]; then
        cat "${cap_dir}/domains" >> "$CAP_WL_TMP" 2> /dev/null || true
        echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Capitole whitelist domains: $cap_cat" | tee -a "$LOGFILE"
      fi
      if [ -f "${cap_dir}/urls" ]; then
        cat "${cap_dir}/urls" >> "$CAP_WL_TMP" 2> /dev/null || true
        echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Capitole whitelist urls: $cap_cat" | tee -a "$LOGFILE"
      fi
    done

    if [ -s "$CAP_WL_TMP" ]; then
      E2G_EXCEPTION="/etc/e2guardian/lists/localexceptionsitelist"
      sort -u "$CAP_WL_TMP" -o "$CAP_WL_TMP" 2> /dev/null || true
      cat "$CAP_WL_TMP" >> "$E2G_EXCEPTION" 2> /dev/null || true
      sort -u "$E2G_EXCEPTION" -o "$E2G_EXCEPTION" 2> /dev/null || true
      echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Capitole whitelist merged into exception list ($(wc -l < "$CAP_WL_TMP" 2> /dev/null || echo 0) entries)." | tee -a "$LOGFILE"
      rm -f "$CAP_WL_TMP"
    else
      echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] No Capitole whitelist entries found." | tee -a "$LOGFILE"
    fi

    echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] Capitole URLs and domains merged." | tee -a "$LOGFILE"
  fi
fi

# =============================================================================
# DOMAIN EXTRACTION
# =============================================================================
> "$RAWDOMAINSLIST" 2> /dev/null || true

extract_domains_from_hostfile() {
  local file=$1
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Extracting domains from hostfile $file..." | tee -a "$LOGFILE"
  grep -v "^#" "$file" 2> /dev/null | grep . | awk '{print $NF}' | sort -u >> "$RAWDOMAINSLIST" 2> /dev/null || true
}

extract_domains_from_urls() {
  local file=$1
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Extracting domains from URLs in $file..." | tee -a "$LOGFILE"
  sed -E 's|^.*://([^/]+).*|\1|' "$file" 2> /dev/null | sort -u >> "$RAWDOMAINSLIST" 2> /dev/null || true
}

extract_domains_from_mixed() {
  local file=$1
  echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Extracting domains from mixed list $file..." | tee -a "$LOGFILE"
  grep -v -E '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' "$file" 2> /dev/null | sort -u >> "$RAWDOMAINSLIST" 2> /dev/null || true
}

for hostfile in "$HOSTFILESDIR"/*; do [ -f "$hostfile" ] && extract_domains_from_hostfile "$hostfile"; done
for domainfile in "$DOMAINSDIR"/*; do [ -f "$domainfile" ] && extract_domains_from_urls "$domainfile"; done
for mixedfile in "$MIXDIR"/*; do [ -f "$mixedfile" ] && extract_domains_from_mixed "$mixedfile"; done
for porndomainfile in "$PORNDIR"/*; do [ -f "$porndomainfile" ] && extract_domains_from_urls "$porndomainfile"; done
for advfile in "$ADVDIR"/*; do [ -f "$advfile" ] && extract_domains_from_hostfile "$advfile"; done

sort -u "$RAWDOMAINSLIST" -o "$RAWDOMAINSLIST" 2> /dev/null || true
cp "$RAWDOMAINSLIST" "$NEW_FEEDS_DIR/" 2> /dev/null || true

# =============================================================================
# MERGE INTO E2GDOMAINS
# =============================================================================
if [ -f "$RAWDOMAINSLIST" ] && [ -s "$RAWDOMAINSLIST" ]; then
  if [ -f "$E2GDOMAINS" ]; then
    cat "$RAWDOMAINSLIST" >> "$E2GDOMAINS" 2> /dev/null || true
    sort -u "$E2GDOMAINS" -o "$E2GDOMAINS" 2> /dev/null || true
  else
    cp "$RAWDOMAINSLIST" "$E2GDOMAINS" 2> /dev/null || true
  fi
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ========================================" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Extraction Summary:" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Domains extracted: $(wc -l < "$RAWDOMAINSLIST" 2> /dev/null || echo 0)" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Total URLs: $(wc -l < "$E2GURLS" 2> /dev/null || echo 0)" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Total Domains: $(wc -l < "$E2GDOMAINS" 2> /dev/null || echo 0)" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ========================================" | tee -a "$LOGFILE"

cp "$E2GDOMAINS" "$DOMAINLIST" 2> /dev/null || true

# =============================================================================
# DEPLOY FILTER CONFIG TEMPLATE
# =============================================================================
cp "$FILTERFILETEMPLATE" "$FILTERFILE" 2> /dev/null || true
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Activated ${FILTER_TYPE} filter configuration." | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Configuration files updated. Ready for e2guardian start." | tee -a "$LOGFILE"

# =============================================================================
# DONE
# =============================================================================
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ========================================" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ${FILTER_TYPE_UPPER} Filter Assets:" | tee -a "$LOGFILE"
echo "  - Work directory: $WORKDIR" | tee -a "$LOGFILE"
echo "  - Domains: $E2GDOMAINS ($(wc -l < "$E2GDOMAINS" 2> /dev/null || echo 0) entries)" | tee -a "$LOGFILE"
echo "  - URLs: $E2GURLS ($(wc -l < "$E2GURLS" 2> /dev/null || echo 0) entries)" | tee -a "$LOGFILE"
echo "  - Filter config: $FILTERFILE" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] ========================================" | tee -a "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Script completed successfully." | tee -a "$LOGFILE"
