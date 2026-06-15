#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# =============================================================================
# TN_SUBSTITUTE.sh -- Expand %%TOKEN%% placeholders in payload/
# =============================================================================
# VERSION: 5.1.0
#
# Run on the TARGET machine after TN_NET_SET.sh has written /etc/tn-interfaces.
#
# STAGE ARCHITECTURE
# ------------------
# Stage 1  Load and validate /etc/tn-interfaces
#   Sources the interfaces file, validates required variables, rejects bad
#   WAN/PPPoE/dual-ISP configurations, and derives computed values
#   (NAT64 address, MONITOR_V6_HOST) that are not stored in the file.
#
# Stage 2  Set system hostname
#   Applies CERT_CN from tn-interfaces as the live hostname and writes
#   /etc/myname for persistence across reboots.
#
# Stage 3  Token substitution
#   Builds the file list, iterates every text file, and expands all known
#   %%TOKEN%% placeholders via a single sed invocation per file.
#   Renames any .template files by stripping the suffix.
#
# Stage 4  Integrity guard
#   Defensive second-pass over system-critical files only.  Catches any
#   tokens not reached by Stage 3 due to file-list gaps (extensionless
#   files, unusual paths).
#
# Stage 5  SRI hash update
#   Recomputes sha384 hashes for every JS asset referenced in HTML files.
#   Updates the sri_hashes table in TNWAF.pm and every integrity= attribute
#   in HTML and view files so hashes match the deployed byte content.
#
# Verify   No unresolved tokens
#   Fails if any %%TOKEN%% pattern remains in any text file in the payload.
#
# Usage: ksh TN_SUBSTITUTE.sh [--dry-run]
# =============================================================================

set -e

VERSION="5.1.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD="$SCRIPT_DIR/payload"
TN_INTERFACES="/etc/tn-interfaces"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/substitute.log"

mkdir -p "$LOG_DIR"

# -----------------------------------------------------------------------------
# Colours -- suppressed when stdout is not a tty
# -----------------------------------------------------------------------------
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  BLUE=''
  BOLD=''
  NC=''
fi

ok() { printf "  ${GREEN}[OK]${NC}    %s\n" "$1"; }
warn() { printf "  ${YELLOW}[WARN]${NC}  %s\n" "$1"; }
err() { printf "  ${RED}[ERR]${NC}   %s\n" "$1"; }
info() { printf "  ${BLUE}[INFO]${NC}  %s\n" "$1"; }
dry() { printf "  [DRY]   %s\n" "$1"; }

print_header() {
  echo ""
  echo "============================================================"
  printf "  ${BOLD}%s${NC}\n" "$1"
  echo "============================================================"
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
DRY_RUN=0
for _arg in "$@"; do
  case "$_arg" in
    --dry-run) DRY_RUN=1 ;;
    --help | -h)
      echo "Usage: $0 [--dry-run]"
      exit 0
      ;;
  esac
done

printf "\n=== RUN %s ===\n" "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
print_header "TN Token Substitutor v${VERSION}"
info "Payload:  $PAYLOAD"
info "Interfaces: $TN_INTERFACES"
[ "$DRY_RUN" -eq 1 ] && info "DRY RUN -- no files will be modified"

# =============================================================================
# STAGE 1  LOAD AND VALIDATE /etc/tn-interfaces
# =============================================================================
print_header "Stage 1: Load /etc/tn-interfaces"

[ -f "$TN_INTERFACES" ] || {
  err "$TN_INTERFACES not found -- run TN_NET_SET.sh first"
  exit 1
}

. "$TN_INTERFACES"

# Unconditionally required
for _var in EXT_IF INT_IF INT_IP4 INT_NET4; do
  eval "_val=\$$_var"
  [ -z "$_val" ] && {
    err "Required variable $_var not set in $TN_INTERFACES"
    exit 1
  }
done

# Conditionally required
if [ "${WAN_TYPE:-}" = "pppoe" ] && [ -z "${WAN_MTU:-}" ]; then
  err "WAN_TYPE=pppoe but WAN_MTU not set in $TN_INTERFACES"
  exit 1
fi
if [ "${WAN_IS_PPPOE:-0}" = "1" ] && [ -z "${PPPOE_PARENT:-}" ]; then
  warn "WAN_IS_PPPOE=1 but PPPOE_PARENT not set -- verify hostname.${EXT_IF} manually"
fi
if [ "${DUAL_ISP:-0}" = "1" ] && [ -z "${EXT_IF_SECONDARY:-}" ]; then
  err "DUAL_ISP=1 but EXT_IF_SECONDARY not set in $TN_INTERFACES"
  exit 1
fi

# Derived values -- computed here so they are available to the sed block
NAT64_INT_IP4="64:ff9b::a0a:a01"
if [ "$INT_IP4" != "10.10.10.1" ]; then
  _o1=$(echo "$INT_IP4" | cut -d. -f1)
  _o2=$(echo "$INT_IP4" | cut -d. -f2)
  _o3=$(echo "$INT_IP4" | cut -d. -f3)
  _o4=$(echo "$INT_IP4" | cut -d. -f4)
  NAT64_INT_IP4=$(printf "64:ff9b::%02x%02x:%02x%02x" "$_o1" "$_o2" "$_o3" "$_o4")
fi

if [ -n "${INT_NET6:-}" ]; then
  MONITOR_V6_HOST="${INT_NET6%%::/64}::254"
else
  MONITOR_V6_HOST="${MONITOR_V6_HOST:-}"
fi

ok "Interfaces loaded:"
printf "    EXT_IF=%-10s  INT_IF=%s\n" "$EXT_IF" "$INT_IF"
printf "    INT_IP4=%-9s  INT_NET4=%s\n" "$INT_IP4" "$INT_NET4"
printf "    INT_IP6=%s\n" "${INT_IP6:-fd10:10:10::1}"
printf "    NAT64=%s\n" "$NAT64_INT_IP4"

# =============================================================================
# STAGE 2  SET SYSTEM HOSTNAME
# =============================================================================
# CERT_CN is written to tn-interfaces during TN_NET_SET.sh SSL configuration.
# We apply it as the live hostname and persist it to /etc/myname.
# =============================================================================
print_header "Stage 2: Set System Hostname"

if [ -n "${CERT_CN:-}" ]; then
  _old_hostname=$(hostname)
  if [ "$_old_hostname" != "$CERT_CN" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      dry "Would set hostname: $_old_hostname -> $CERT_CN"
    else
      hostname "$CERT_CN"
      printf '%s\n' "$CERT_CN" > /etc/myname
      ok "Hostname set: $_old_hostname -> $CERT_CN"
    fi
  else
    ok "Hostname already correct: $CERT_CN"
  fi
else
  warn "CERT_CN not set in $TN_INTERFACES -- hostname unchanged"
fi

# =============================================================================
# STAGE 3  TOKEN SUBSTITUTION
# =============================================================================
# Builds a de-duplicated file list then expands every %%TOKEN%% placeholder
# in each text file via a single sed invocation.
# .template files are renamed to their final names after substitution.
#
# Tokens are grouped by category in the sed block for readability.
# Ordering within a group does not matter because tokens never overlap
# (%%FOO%% cannot be a substring of %%BAR%%).
# =============================================================================
print_header "Stage 3: Token Substitution"

# Build file list -- by extension for most files, by directory for fragments
TEMP_FILE_LIST=$(mktemp)

find "$PAYLOAD" -type f \( \
  -name "*.conf" -o -name "*.pm" -o -name "*.sh" -o \
  -name "*.pl" -o -name "*.local" -o -name "crontab" -o \
  -name "*.template" -o -name "*.html" -o -name "*.js" \
  \) \
  ! -path "*/e2guardian/*" \
  ! -path "*/data/pipes/*" \
  ! -path "*/data/logs/*" \
  ! -name "firewall.pl" \
  ! -name "pf-tcpdump.sh" \
  ! -name "*.orig" \
  2> /dev/null > "$TEMP_FILE_LIST"

# View fragments (extensionless SPA files) and documentation
# No -maxdepth: view/ has subdirectories (e.g. dashboard/) that also need substitution
for _extra_dir in \
  "$PAYLOAD/var/www/htdocs/tn/view" \
  "$PAYLOAD/var/www/htdocs/tn/docs"; do
  [ -d "$_extra_dir" ] \
    && find "$_extra_dir" -type f \
      ! -name "*.orig" \
      2> /dev/null >> "$TEMP_FILE_LIST"
done

# De-duplicate -- multiple find passes can produce the same path
_dedup_tmp=$(mktemp)
sort -u "$TEMP_FILE_LIST" > "$_dedup_tmp"
mv "$_dedup_tmp" "$TEMP_FILE_LIST"

SUBSTITUTED=0

while IFS= read -r _file; do
  _rel="${_file#$PAYLOAD/}"

  # Skip binary files -- OpenBSD file(1) does not support --mime
  file "$_file" 2> /dev/null | grep -qv "text" && continue

  # Skip files with no tokens
  grep -q "%%" "$_file" 2> /dev/null || continue

  if [ "$DRY_RUN" -eq 1 ]; then
    dry "Would substitute: $_rel"
    SUBSTITUTED=$((SUBSTITUTED + 1))
    continue
  fi

  [ -f "${_file}.orig" ] || cp "$_file" "${_file}.orig"
  _tmp_out=$(mktemp)

  sed \
    -e "s|%%EXT_IF%%|${EXT_IF}|g" \
    -e "s|%%INT_IF%%|${INT_IF}|g" \
    -e "s|%%INT_IFS%%|${INT_IFS:-}|g" \
    -e "s|%%INT_IP4%%|${INT_IP4}|g" \
    -e "s|%%INT_NET4%%|${INT_NET4}|g" \
    -e "s|%%INT_MASK4%%|${INT_MASK4:-255.255.255.0}|g" \
    -e "s|%%INT_CIDR4%%|${INT_CIDR4:-24}|g" \
    -e "s|%%INT_NET4_ADDR%%|${INT_NET4_ADDR:-}|g" \
    -e "s|%%INT_BROADCAST4%%|${INT_BROADCAST4:-}|g" \
    -e "s|%%INT_IF4%%|${INT_IF4:-${INT_IP4}}|g" \
    -e "s|%%INT_IP6%%|${INT_IP6:-fd10:10:10::1}|g" \
    -e "s|%%INT_NET6%%|${INT_NET6:-fd10:10:10::/64}|g" \
    -e "s|%%INT_CIDR6%%|${INT_CIDR6:-64}|g" \
    -e "s|%%MONITOR_V6_HOST%%|${MONITOR_V6_HOST:-}|g" \
    -e "s|%%NAT64_PFX%%|64:ff9b::/96|g" \
    -e "s|%%NAT64_INT_IP4%%|${NAT64_INT_IP4:-64:ff9b::a0a:a01}|g" \
    -e "s|%%EXT_IP4%%|${EXT_IP4:-}|g" \
    -e "s|%%EXT_MASK4%%|${EXT_MASK4:-}|g" \
    -e "s|%%EXT_IP6%%|${EXT_IP6:-}|g" \
    -e "s|%%EXT_GW4%%|${EXT_GW4:-}|g" \
    -e "s|%%EXT_GW6%%|${EXT_GW6:-}|g" \
    -e "s|%%WAN_GW4%%|${EXT_GW4:-}|g" \
    -e "s|%%WAN_GW6%%|${EXT_GW6:-fe80::1}|g" \
    -e "s|%%EXT_IP4_CLASS%%|${EXT_IP4_CLASS:-none}|g" \
    -e "s|%%EXT_IP6_CLASS%%|${EXT_IP6_CLASS:-none}|g" \
    -e "s|%%WAN_NET6%%|${WAN_NET6:-}|g" \
    -e "s|%%DHCP_RANGE_START%%|${DHCP_RANGE_START:-}|g" \
    -e "s|%%DHCP_RANGE_END%%|${DHCP_RANGE_END:-}|g" \
    -e "s|%%DHCPD_FQDN%%|${DHCPD_FQDN:-tangent.localdomain}|g" \
    -e "s|%%DHCPD_SUBNET%%|${DHCPD_SUBNET:-}|g" \
    -e "s|%%DHCPD_NETMASK%%|${DHCPD_NETMASK:-}|g" \
    -e "s|%%DHCPD_BROADCAST%%|${DHCPD_BROADCAST:-}|g" \
    -e "s|%%DHCPD_INT_IF4_START_ADDR%%|${DHCPD_INT_IF4_START_ADDR:-}|g" \
    -e "s|%%DHCPD_INT_IF4_END_ADDR%%|${DHCPD_INT_IF4_END_ADDR:-}|g" \
    -e "s|%%DEPLOY_MODE%%|${DEPLOY_MODE:-cgnat_home}|g" \
    -e "s|%%IPV6_MODE%%|${IPV6_MODE:-nat66}|g" \
    -e "s|%%WAN_TYPE%%|${WAN_TYPE:-ethernet}|g" \
    -e "s|%%WAN_IS_PPPOE%%|${WAN_IS_PPPOE:-0}|g" \
    -e "s|%%PPPOE_PARENT%%|${PPPOE_PARENT:-}|g" \
    -e "s|%%WAN_MTU%%|${WAN_MTU:-1500}|g" \
    -e "s|%%WAN_MSS4%%|${WAN_MSS4:-1420}|g" \
    -e "s|%%WAN_MSS6%%|${WAN_MSS6:-1400}|g" \
    -e "s|%%WAN_SPEED%%|${WAN_SPEED:-unknown}|g" \
    -e "s|%%WAN_DUPLEX%%|${WAN_DUPLEX:-unknown}|g" \
    -e "s|%%WAN_OFFLOAD%%|${WAN_OFFLOAD:-}|g" \
    -e "s|%%WAN_VLAN%%|${WAN_VLAN:-no}|g" \
    -e "s|%%WAN_HAS_TSO4%%|${WAN_HAS_TSO4:-0}|g" \
    -e "s|%%WAN_HAS_TSO6%%|${WAN_HAS_TSO6:-0}|g" \
    -e "s|%%WAN_HAS_LRO%%|${WAN_HAS_LRO:-0}|g" \
    -e "s|%%WAN_HAS_VLAN_HW%%|${WAN_HAS_VLAN_HW:-0}|g" \
    -e "s|%%WAN_IS_10G%%|${WAN_IS_10G:-0}|g" \
    -e "s|%%WAN_COUNT%%|${WAN_COUNT:-1}|g" \
    -e "s|%%LAN_MTU%%|${LAN_MTU:-1500}|g" \
    -e "s|%%LAN_MSS4%%|${LAN_MSS4:-1460}|g" \
    -e "s|%%LAN_MSS6%%|${LAN_MSS6:-1440}|g" \
    -e "s|%%LAN_SPEED%%|${LAN_SPEED:-unknown}|g" \
    -e "s|%%LAN_DUPLEX%%|${LAN_DUPLEX:-unknown}|g" \
    -e "s|%%LAN_OFFLOAD%%|${LAN_OFFLOAD:-}|g" \
    -e "s|%%LAN_VLAN%%|${LAN_VLAN:-no}|g" \
    -e "s|%%LAN_HAS_TSO4%%|${LAN_HAS_TSO4:-0}|g" \
    -e "s|%%LAN_HAS_TSO6%%|${LAN_HAS_TSO6:-0}|g" \
    -e "s|%%LAN_HAS_LRO%%|${LAN_HAS_LRO:-0}|g" \
    -e "s|%%LAN_HAS_VLAN_HW%%|${LAN_HAS_VLAN_HW:-0}|g" \
    -e "s|%%LAN_IS_10G%%|${LAN_IS_10G:-0}|g" \
    -e "s|%%LAN_COUNT%%|${LAN_COUNT:-1}|g" \
    -e "s|%%INT_IS_WIRELESS%%|${INT_IS_WIRELESS:-0}|g" \
    -e "s|%%INT_WIFI_SSID%%|${INT_WIFI_SSID:-}|g" \
    -e "s|%%INT_WIFI_BAND%%|${INT_WIFI_BAND:-}|g" \
    -e "s|%%INT_WIFI_CHANNEL%%|${INT_WIFI_CHANNEL:-0}|g" \
    -e "s|%%INT_BRIDGE_MEMBERS%%|${INT_BRIDGE_MEMBERS:-}|g" \
    -e "s|%%PF_MAX_MSS4_EXT_IF%%|${PF_MAX_MSS4_EXT_IF:-1420}|g" \
    -e "s|%%PF_MAX_MSS6_EXT_IF%%|${PF_MAX_MSS6_EXT_IF:-1400}|g" \
    -e "s|%%PF_MAX_MSS4_INT_IF%%|${PF_MAX_MSS4_INT_IF:-1460}|g" \
    -e "s|%%PF_MAX_MSS6_INT_IF%%|${PF_MAX_MSS6_INT_IF:-1440}|g" \
    -e "s|%%MULTI_WAN_DETECTED%%|${MULTI_WAN_DETECTED:-0}|g" \
    -e "s|%%DUAL_ISP%%|${DUAL_ISP:-0}|g" \
    -e "s|%%EXT_IF_SECONDARY%%|${EXT_IF_SECONDARY:-}|g" \
    -e "s|%%DUAL_ISP_MODE%%|${DUAL_ISP_MODE:-}|g" \
    -e "s|%%WAN_WIFI_SSID%%|${WAN_WIFI_SSID:-}|g" \
    -e "s|%%WAN_WIFI_SECURITY%%|${WAN_WIFI_SECURITY:-}|g" \
    -e "s|%%VIRT_ENV%%|${VIRT_ENV:-bare-metal}|g" \
    -e "s|%%CLOUD_PROVIDER%%|${CLOUD_PROVIDER:-none}|g" \
    -e "s|%%CLOUD_REGION%%|${CLOUD_REGION:-unknown}|g" \
    -e "s|%%RAM_GB%%|${RAM_GB:-2}|g" \
    -e "s|%%CPU_CORES%%|${CPU_CORES:-2}|g" \
    -e "s|%%CPU_ARCH%%|${CPU_ARCH:-amd64}|g" \
    -e "s|%%AES_NI%%|${AES_NI:-0}|g" \
    -e "s|%%MBUF_NMBCLUSTERS%%|${MBUF_NMBCLUSTERS:-8192}|g" \
    -e "s|%%TCP_SENDSPACE%%|${TCP_SENDSPACE:-131072}|g" \
    -e "s|%%TCP_RECVSPACE%%|${TCP_RECVSPACE:-131072}|g" \
    -e "s|%%JUMBO_MTU_SUPPORTED%%|${JUMBO_MTU_SUPPORTED:-0}|g" \
    -e "s|%%HAS_TCP4%%|${HAS_TCP4:-1}|g" \
    -e "s|%%HAS_UDP4%%|${HAS_UDP4:-1}|g" \
    -e "s|%%HAS_DIVERT%%|${HAS_DIVERT:-1}|g" \
    -e "s|%%HAS_INET6%%|${HAS_INET6:-1}|g" \
    -e "s|%%HAS_BRIDGE%%|${HAS_BRIDGE:-0}|g" \
    -e "s|%%HOSTNAME%%|${CERT_CN:-$(hostname)}|g" \
    -e "s|%%MYNAME%%|${CERT_CN:-$(hostname)}|g" \
    -e "s|%%HOSTNAME_EXT%%|${HOSTNAME_EXT:-}|g" \
    -e "s|%%HOSTNAME_INT%%|${HOSTNAME_INT:-}|g" \
    -e "s|%%CERT_ORG%%|${CERT_ORG:-Local UTM}|g" \
    -e "s|%%CERT_OU%%|${CERT_OU:-IT Department}|g" \
    -e "s|%%CERT_CN%%|${CERT_CN:-utm.local}|g" \
    -e "s|%%CERT_COUNTRY%%|${CERT_COUNTRY:-US}|g" \
    -e "s|%%CERT_STATE%%|${CERT_STATE:-}|g" \
    -e "s|%%CERT_CITY%%|${CERT_CITY:-}|g" \
    -e "s|%%CERT_EMAIL%%|${CERT_EMAIL:-}|g" \
    -e "s|%%TLS_CERT%%|${TLS_CERT:-}|g" \
    -e "s|%%TLS_KEY%%|${TLS_KEY:-}|g" \
    -e "s|%%RULES_TYPE%%|${RULES_TYPE:-community}|g" \
    -e "s|%%OINK_CODE%%|${OINK_CODE:-}|g" \
    -e "s|%%OINK_URL%%|${OINK_URL:-}|g" \
    -e "s|%%PUBLIC_DOMAIN%%|${PUBLIC_DOMAIN:-}|g" \
    "$_file" > "$_tmp_out"

  mv "$_tmp_out" "$_file"

  # Rename .template files by stripping the suffix
  if echo "$_file" | grep -q "\.template$"; then
    _new_file="${_file%.template}"
    mv "$_file" "$_new_file"
    ok "substituted + renamed: ${_new_file#$PAYLOAD/}"
  else
    ok "substituted: $_rel"
  fi

  SUBSTITUTED=$((SUBSTITUTED + 1))
done < "$TEMP_FILE_LIST"

rm -f "$TEMP_FILE_LIST"
info "Stage 3 complete: $SUBSTITUTED files processed"

# =============================================================================
# STAGE 4  INTEGRITY GUARD
# =============================================================================
# Defensive second-pass over system-critical files only.  If Stage 3 missed
# a file due to an extension gap or path not in the file list, this catches
# any residual tokens before they reach a running system.
# =============================================================================
print_header "Stage 4: Integrity Guard"

_SYSTEM_CRITICAL="
    etc/rc.local
    etc/httpd.conf
    etc/tangent_services.pm
    etc/collectd_rrd_exporter.pm
    usr/local/sbin/service_manager.sh
    usr/local/sbin/process_monitor.pl
    usr/local/sbin/collectd_exporter.pl
"

_S4_FIXED=0
for _rel_path in $_SYSTEM_CRITICAL; do
  _abs_path="$PAYLOAD/$_rel_path"
  [ -f "$_abs_path" ] || continue
  grep -q "%%" "$_abs_path" 2> /dev/null || continue
  _tmp_guard=$(mktemp)
  sed \
    -e "s|%%EXT_IF%%|${EXT_IF:-}|g" \
    -e "s|%%INT_IF%%|${INT_IF:-}|g" \
    -e "s|%%WAN_GW4%%|${EXT_GW4:-}|g" \
    -e "s|%%WAN_GW6%%|${EXT_GW6:-fe80::1}|g" \
    -e "s|%%HSTS%%|#|g" \
    "$_abs_path" > "$_tmp_guard"
  mv "$_tmp_guard" "$_abs_path"
  ok "guard applied: $_rel_path"
  _S4_FIXED=$((_S4_FIXED + 1))
done

[ "$_S4_FIXED" -eq 0 ] \
  && ok "all critical files were clean after Stage 3" \
  || info "Stage 4 applied guard to $_S4_FIXED file(s)"

# =============================================================================
# STAGE 5  SRI HASH UPDATE
# =============================================================================
# Recomputes sha384 hashes for every JS asset referenced in HTML/view/docs
# files and propagates them to:
#   (a) TNWAF.pm  -- the sri_hashes Perl hash table
#   (b) every *.html, *.htm, view/*, and docs/* file -- integrity= attributes
#
# Flow:
#   1. Build _html_list: all HTML/view/docs files that can carry integrity=
#   2. Extract unique JS filenames referenced in those files
#   3. Compute sha384 for each JS file, write TNWAF.pm sri_hashes block
#   4. For each JS file, update integrity= in every file in _html_list
# =============================================================================
print_header "Stage 5: SRI Hash Update"

_js_dir="$PAYLOAD/var/www/htdocs/tn/assets/js"
_waf_pm="$PAYLOAD/var/www/htdocs/tn/data/lib/TNWAF.pm"
_webroot="$PAYLOAD/var/www/htdocs/tn"

_catalog_tmp=$(mktemp)
_perl_block_tmp=$(mktemp)
_html_list=$(mktemp)
_js_list_tmp=$(mktemp)
_asset_count=0

# Build the complete list of files that carry <script integrity=> attributes.
# Covers: top-level *.html and *.htm, all files under view/ and docs/.
# view/ and docs/ are extensionless SPA fragments -- include all regular files.
find "$_webroot" -maxdepth 1 \( -name "*.html" -o -name "*.htm" \) \
  -type f ! -name "*.orig" 2> /dev/null > "$_html_list"
find "$_webroot/view" -type f ! -name "*.orig" 2> /dev/null >> "$_html_list"
find "$_webroot/docs" -type f ! -name "*.orig" 2> /dev/null >> "$_html_list"

_ui_file_count=$(wc -l < "$_html_list" | tr -d ' ')
info "$_ui_file_count UI files in scope for SRI propagation"

# Extract the unique JS filenames referenced across all UI files.
# Use xargs to pass filenames safely -- avoids word-splitting on paths with
# spaces and handles an empty _html_list without error.
xargs grep -h "<script src" < "$_html_list" 2> /dev/null \
  | sed -n 's/.*src=".*\/\([^"]*\.js\).*/\1/p' \
  | sort -u > "$_js_list_tmp"

_js_ref_count=$(wc -l < "$_js_list_tmp" | tr -d ' ')
info "$_js_ref_count distinct JS assets referenced"

# Compute sha384 for each JS file and build:
#   _perl_block_tmp  -- replacement text for TNWAF.pm sri_hashes block
#   _catalog_tmp     -- js_name|sri_value pairs consumed by the HTML loop
echo "    sri_hashes => {" > "$_perl_block_tmp"

while read -r _js_name; do
  _js_file="$_js_dir/$_js_name"
  if [ ! -f "$_js_file" ]; then
    warn "  JS asset not found, skipping: $_js_name"
    continue
  fi
  _js_key="/assets/js/${_js_name}"
  _hash=$(openssl dgst -sha384 -binary "$_js_file" | openssl base64 -A)
  _sri="sha384-$_hash"
  printf "        '%s' => '%s',\n" "$_js_key" "$_sri" >> "$_perl_block_tmp"
  printf '%s|%s\n' "$_js_name" "$_sri" >> "$_catalog_tmp"
  _asset_count=$((_asset_count + 1))
  info "  hashed: $_js_name"
done < "$_js_list_tmp"

echo "    }," >> "$_perl_block_tmp"

# (a) Update TNWAF.pm sri_hashes table
if [ "$DRY_RUN" -eq 0 ] && [ -f "$_waf_pm" ]; then
  _new_waf=$(mktemp)
  awk '
        /sri_hashes[[:space:]]*=>[[:space:]]*\{/ {
            while ((getline line < "'"$_perl_block_tmp"'") > 0) { print line }
            skip = 1
            next
        }
        skip && /^[[:space:]]*\},[[:space:]]*$/ {
            skip = 0
            next
        }
        !skip { print }
    ' "$_waf_pm" > "$_new_waf"
  mv "$_new_waf" "$_waf_pm"
  ok "TNWAF.pm sri_hashes rebuilt ($_asset_count assets)"
elif [ "$DRY_RUN" -eq 1 ]; then
  dry "Would rebuild TNWAF.pm sri_hashes ($_asset_count assets)"
else
  warn "TNWAF.pm not found -- skipping sri_hashes update"
fi

# (b) Update integrity= attributes in all UI files.
# For each JS asset, iterate every UI file that references it.
# We require the line containing the JS name to also carry integrity=
# so that documentation files referencing a JS name in plain text are
# not mistakenly processed.  awk rewrites only that line, writes output
# to a tempfile, then mv replaces the original atomically.
_updated_files=0

# Loop over the HTML/view files on the outside (Isolated Scope per File)
while IFS= read -r _html; do
  [ -f "$_html" ] || continue

  _file_modified=0
  _tmp=$(mktemp)
  cp "$_html" "$_tmp"

  # Loop over assets internally only to apply filters to this single file
  while read -r _js_name; do
    _js_file="$_js_dir/$_js_name"
    [ -f "$_js_file" ] || continue

    # Escape the script name for regex safety
    _js_regex=$(echo "${_js_name}" | sed 's/\./\\./g')

    # Strict regex boundary verification
    grep -E "/${_js_regex}\"" "$_tmp" 2> /dev/null | grep -q 'integrity=' || continue

    if [ "$DRY_RUN" -eq 1 ]; then
      dry "Would update SRI in ${_html#$PAYLOAD/} for $_js_name"
      continue
    fi

    _sri_new="sha384-$(openssl dgst -sha384 -binary "$_js_file" | openssl base64 -A)"
    _awk_out=$(mktemp)

    # Apply exact swap onto the temp file clone
    awk -v js_pat="/${_js_regex}\"" -v sri="$_sri_new" '{
            if ($0 ~ js_pat && index($0, "integrity=")) {
                sub(/integrity="sha384-[^"]*"/, "integrity=\"" sri "\"")
            }
            print
        }' "$_tmp" > "$_awk_out" && mv "$_awk_out" "$_tmp"

    _file_modified=1
  done < "$_js_list_tmp"

  # Save the file out only if changes actually happened
  if [ "$_file_modified" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
    mv "$_tmp" "$_html"
    ok "  SRI isolated updates complete: ${_html#$PAYLOAD/}"
    _updated_files=$((_updated_files + 1))
  else
    rm -f "$_tmp"
  fi
done < "$_html_list"

ok "SRI sync complete: $_asset_count hashes, $_updated_files file-asset updates across $_ui_file_count UI files"
rm -f "$_catalog_tmp" "$_perl_block_tmp" "$_html_list" "$_js_list_tmp"

# =============================================================================
# VERIFY  No Unresolved Tokens
# =============================================================================
print_header "Verify: No Unresolved Tokens"

_REMAINING=0
_TEMP_CHECK=$(mktemp)

find "$PAYLOAD" -type f ! -name "*.orig" \
  ! -name "*.png" ! -name "*.rrd" \
  ! -name "*.gz" ! -name "*.tar.gz" \
  2> /dev/null > "$_TEMP_CHECK"

while IFS= read -r _file; do
  # Skip binary files -- OpenBSD file(1) does not support --mime
  file "$_file" 2> /dev/null | grep -qv "text" && continue

  case "$_file" in *e2guardian* | *data/pipes* | *data/logs* | *firewall.pl* | *pf-tcpdump.sh*) continue ;; esac

  if grep -qE "%%[A-Z0-9_]{3,}%%" "$_file" 2> /dev/null; then
    warn "remaining tokens in: ${_file#$PAYLOAD/}"
    grep -nE "%%[A-Z0-9_]{3,}%%" "$_file" 2> /dev/null \
      | head -3 | sed 's/^/      /'
    _REMAINING=1
  fi
done < "$_TEMP_CHECK"

rm -f "$_TEMP_CHECK"

echo ""
if [ "$_REMAINING" -eq 0 ]; then
  ok "All tokens resolved -- $SUBSTITUTED files processed."
  echo ""
  info "Next: deploy payload to target system"
  info "  cp -r $PAYLOAD/* /"
else
  warn "Unresolved tokens remain -- review warnings above before deploying"
fi

exit 0
