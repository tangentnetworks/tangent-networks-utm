#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# =============================================================================
# tn-mtu-probe.sh - NAT66 MTU Discovery and PF MSS Configuration
# =============================================================================
# Part of the TangentNet UTM ecosystem.
#
# Purpose:
#   Determines the correct wire MTU and TCP MSS values for NAT66 deployments
#   by live-probing the IPv6 path with descending ICMPv6 payload sizes.
#   Writes WAN_MTU, WAN_MSS4, WAN_MSS6 and PF_MAX_MSS* compat aliases into
#   /etc/tn-interfaces for consumption by rad.conf, hostname.if and pf.conf
#   generators.
#
# Design principles:
#   - No ifconfig MTU reliance - live probe is the only ground truth
#   - Conservative MSS_SAFETY_MARGIN=40 accommodates IPsec ESP, VLAN, PPPoE
#   - ping6 usage mirrors TN_NET_SET.sh exactly: -c N -s SIZE -w SECS target
#   - No -I flag (OpenBSD ping6 -I takes a source address, not interface name)
#   - EXT_GW6 sourced from tn-interfaces (bare address, no zone suffix)
#   - Gateway ping skipped for link-local gateways - NDP proof is sufficient
#   - Pure ksh, OpenBSD base only, zero external dependencies
#   - ASCII only - no unicode for OpenBSD regex compatibility
#
# Output written to /etc/tn-interfaces (in-place, sed update or append):
#   WAN_MTU="1420"
#   WAN_MSS4="1380"
#   WAN_MSS6="1360"
#   PF_MAX_MSS4_EXT_IF="1380"
#   PF_MAX_MSS6_EXT_IF="1360"
#   PF_MAX_MSS4_INT_IF="1380"
#   PF_MAX_MSS6_INT_IF="1360"
#
# Usage:
#   sh /usr/local/sbin/tn-mtu-probe.sh
#   sh /usr/local/sbin/tn-mtu-probe.sh -v    # verbose
#   sh /usr/local/sbin/tn-mtu-probe.sh -n    # dry-run, no writes
#
# Deployment:
#   Called by UTM_INSTALL.sh after network is confirmed up,
#   before pf.conf, rad.conf and hostname.if generators run.
# =============================================================================

# =============================================================================
# CONFIGURATION
# =============================================================================

TN_INTERFACES="/etc/tn-interfaces"
LOG_FILE="/var/www/tmp/tn-mtu.log"

# Probe targets - same order as TN_NET_SET.sh
TARGET_PRIMARY="2606:4700:4700::1111"
TARGET_SECONDARY="2001:4860:4860::8888"
TARGET_TERTIARY="2620:fe::fe"

# ping6 -w takes seconds on OpenBSD (not milliseconds)
PROBE_TIMEOUT=3
PREFLIGHT_TIMEOUT=3
PROBE_COUNT=2
GW_PING_COUNT=1

# PPPoE fixed MTU
PPPOE_WAN_MTU=1492

# Conservative safety margin: IPv4 hdr 20 + TCP hdr 20 = 40
MSS_SAFETY_MARGIN=40

# Default if all probes fail
DEFAULT_WAN_MTU=1400

# MTU probe ladder - descending, first success wins
LADDER="1500 1492 1480 1472 1460 1452 1440 1428 1420 1400 1384 1372"

# =============================================================================
# RUNTIME STATE
# =============================================================================

VERBOSE=0
DRYRUN=0
EXT_IF=""
INT_IF=""
EXT_GW4=""
EXT_GW6=""
WAN_IS_PPPOE="0"
HAS_INET6="1"
WAN_MTU=""
WAN_MSS4=""
WAN_MSS6=""
INT_MSS4=""
INT_MSS6=""

# =============================================================================
# ARGUMENT PARSING
# =============================================================================
while getopts "vn" opt; do
  case "$opt" in
    v) VERBOSE=1 ;;
    n) DRYRUN=1 ;;
    *)
      printf "Usage: %s [-v] [-n]\n" "$0" >&2
      exit 1
      ;;
  esac
done

# =============================================================================
# LOGGING - matches TN_NET_SET.sh style
# =============================================================================
if [ ! -d "/var/www/tmp" ]; then
  mkdir -p /var/www/tmp
fi

_log() {
  printf "[%s] [%-4s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" \
    >> "$LOG_FILE"
}

ok() {
  printf "  [OK]   %s\n" "$1"
  _log "OK" "$1"
}
err() {
  printf "  [ERR]  %s\n" "$1"
  _log "ERR" "$1"
}
warn() {
  printf "  [WARN] %s\n" "$1"
  _log "WARN" "$1"
}
info() {
  printf "  [INFO] %s\n" "$1"
  _log "INFO" "$1"
}
debug() {
  if [ "$VERBOSE" -eq 1 ]; then
    printf "  [DBG]  %s\n" "$1"
    _log "DBG" "$1"
  fi
}
fatal() {
  printf "  [FATAL] %s\n" "$1"
  _log "ERR" "FATAL: $1"
}
print_header() {
  printf "\n============================================================\n"
  printf "  %s\n" "$1"
  printf "============================================================\n"
  _log "INFO" "=== $1 ==="
}

# =============================================================================
# MSS DERIVATION
# derive_mss PREFIX TYPE MTU
#
# Sets PREFIX_MSS4 and PREFIX_MSS6 from MTU and type.
# Mirrors derive_mss() in TN_NET_SET.sh.
#   ethernet : mss4 = mtu - 40 - margin  mss6 = mtu - 60 - margin
#   pppoe    : mtu fixed to PPPOE_WAN_MTU
# =============================================================================
derive_mss() {
  _dm_pfx="$1"
  _dm_type="$2"
  _dm_mtu="$3"

  case "$_dm_type" in
    pppoe)
      _dm_mtu=$PPPOE_WAN_MTU
      _dm_mss4=$((_dm_mtu - 40 - MSS_SAFETY_MARGIN))
      _dm_mss6=$((_dm_mtu - 60 - MSS_SAFETY_MARGIN))
      ;;
    *)
      _dm_mss4=$((_dm_mtu - 40 - MSS_SAFETY_MARGIN))
      _dm_mss6=$((_dm_mtu - 60 - MSS_SAFETY_MARGIN))
      ;;
  esac

  eval "${_dm_pfx}_MSS4=\"$_dm_mss4\""
  eval "${_dm_pfx}_MSS6=\"$_dm_mss6\""
}

# =============================================================================
# BANNER
# =============================================================================
print_header "tn-mtu-probe.sh starting"
if [ "$DRYRUN" -eq 1 ]; then
  info "Dry-run mode - $TN_INTERFACES will not be modified"
fi

# =============================================================================
# STAGE 1 - SOURCE /etc/tn-interfaces
# =============================================================================
print_header "Stage 1: Sourcing $TN_INTERFACES"

if [ ! -f "$TN_INTERFACES" ]; then
  fatal "$TN_INTERFACES not found - cannot determine interfaces"
  exit 1
fi

. "$TN_INTERFACES"

if [ -z "$EXT_IF" ]; then
  fatal "EXT_IF not set in $TN_INTERFACES"
  exit 1
fi
if [ -z "$INT_IF" ]; then
  fatal "INT_IF not set in $TN_INTERFACES"
  exit 1
fi

ok "EXT_IF=$EXT_IF  INT_IF=$INT_IF"
debug "EXT_GW4=${EXT_GW4:-unset}  EXT_GW6=${EXT_GW6:-unset}"
debug "WAN_IS_PPPOE=${WAN_IS_PPPOE:-0}  HAS_INET6=${HAS_INET6:-1}"

# =============================================================================
# STAGE 2 - PREFLIGHT: IPv6 CONNECTIVITY VALIDATION
#
# Mirrors TN_NET_SET.sh Stage 19 preflight exactly:
#   ping6 -c 1 -w SECS "$EXT_GW6"   (no -I, no zone suffix in EXT_GW6)
#
# Link-local gateway: NDP resolution in the routing table is sufficient
# proof of L2. Gateway ping is unreliable for fe80:: from a script on
# OpenBSD - skip it and rely on internet reachability as proof.
# =============================================================================
print_header "Stage 2: IPv6 preflight connectivity validation"

# --- 2a. Validate EXT_GW6 ---
if [ -z "${EXT_GW6:-}" ]; then
  warn "EXT_GW6 not set in $TN_INTERFACES - IPv6 path probe will be skipped"
  HAS_INET6=0
fi

if [ "${HAS_INET6:-1}" -eq 1 ]; then

  # --- 2b. Check default IPv6 route is present ---
  _cur_gw6=$(route -n show -inet6 2> /dev/null | awk '/^default/{print $2; exit}')
  if [ -z "$_cur_gw6" ]; then
    warn "No default IPv6 route in routing table - IPv6 probe disabled"
    HAS_INET6=0
  else
    ok "Default IPv6 route via $_cur_gw6"
  fi

fi

if [ "${HAS_INET6:-1}" -eq 1 ]; then

  # --- 2c. Determine if gateway is link-local ---
  _gw6_is_ll=0
  case "$EXT_GW6" in
    fe80:* | FE80:*) _gw6_is_ll=1 ;;
  esac

  # --- 2d. Gateway reachability ---
  # For link-local: routing table confirmed above, NDP proves L2 is up.
  # For global/ULA: attempt a ping as TN_NET_SET.sh does.
  if [ "$_gw6_is_ll" -eq 1 ]; then
    ok "Link-local gateway $EXT_GW6 - skipping ping (routing table confirms L2)"
  else
    debug "Pinging IPv6 gateway $EXT_GW6..."
    if ping6 -c "$GW_PING_COUNT" -w "$PREFLIGHT_TIMEOUT" "$EXT_GW6" \
      > /dev/null 2>&1; then
      ok "Gateway $EXT_GW6 reachable"
    else
      warn "Gateway $EXT_GW6 unreachable - IPv6 probe disabled"
      HAS_INET6=0
    fi
  fi

fi

if [ "${HAS_INET6:-1}" -eq 1 ]; then

  # --- 2e. Internet reachability - mirrors TN_NET_SET.sh exactly ---
  _inet6_ok=0
  for _pt in "$TARGET_PRIMARY" "$TARGET_SECONDARY" "$TARGET_TERTIARY"; do
    if ping6 -c 1 -w "$PREFLIGHT_TIMEOUT" "$_pt" > /dev/null 2>&1; then
      ok "IPv6 internet reachable via $_pt"
      _inet6_ok=1
      break
    fi
    debug "  $_pt unreachable"
  done

  if [ "$_inet6_ok" -eq 0 ]; then
    warn "IPv6 internet unreachable - IPv6 probe disabled"
    HAS_INET6=0
  fi

fi

# =============================================================================
# STAGE 3 - PATH MTU DISCOVERY
#
# _test_mtu6 and _find_mtu6 are taken directly from TN_NET_SET.sh Stage 19.
#
# ping6 -s on OpenBSD: -s is the ICMPv6 payload size (data bytes).
# wire bytes = payload + IPv6 hdr (40) + ICMPv6 hdr (8) = payload + 48
# So: payload = wire_mtu - 48
# _test_mtu6 receives wire_mtu and converts: -s $(($wire_mtu - 48))
# =============================================================================
print_header "Stage 3: Path MTU Discovery"

# Exactly as in TN_NET_SET.sh
_test_mtu6() { ping6 -c "$PROBE_COUNT" -s $(($1 - 48)) -w "$PROBE_TIMEOUT" "$2" > /dev/null 2>&1; }
_test_mtu4() { ping -c 3 -s $(($1 - 28)) "$2" > /dev/null 2>&1; }

# _find_mtu6 and _find_mtu4 are called inside $() so stdout is captured as
# the return value. All logging MUST go to stderr to avoid polluting WAN_MTU.
# Only the single bare number is printed to stdout.

_find_mtu6() {
  for _t in "$TARGET_PRIMARY" "$TARGET_SECONDARY" "$TARGET_TERTIARY"; do
    ping6 -c 1 -w "$PREFLIGHT_TIMEOUT" "$_t" > /dev/null 2>&1 || continue
    [ "$VERBOSE" -eq 1 ] && printf "  [DBG]  Probing IPv6 via %s\n" "$_t" >&2
    for _m in $LADDER; do
      [ "$VERBOSE" -eq 1 ] && printf "  [DBG]    Testing MTU=%s\n" "$_m" >&2
      if _test_mtu6 "$_m" "$_t"; then
        printf "  [OK]   IPv6 MTU=%s confirmed via %s\n" "$_m" "$_t" >&2
        _log "OK" "IPv6 MTU=$_m confirmed via $_t"
        printf "%s" "$_m"
        return 0
      fi
    done
  done
  printf "%s" "$DEFAULT_WAN_MTU"
}

_find_mtu4() {
  for _t in "$TARGET_PRIMARY" "$TARGET_SECONDARY" "$TARGET_TERTIARY"; do
    ping -c 1 "$_t" > /dev/null 2>&1 || continue
    [ "$VERBOSE" -eq 1 ] && printf "  [DBG]  Probing IPv4 via %s\n" "$_t" >&2
    for _m in $LADDER; do
      [ "$VERBOSE" -eq 1 ] && printf "  [DBG]    Testing MTU=%s\n" "$_m" >&2
      if _test_mtu4 "$_m" "$_t"; then
        printf "  [OK]   IPv4 MTU=%s confirmed via %s\n" "$_m" "$_t" >&2
        _log "OK" "IPv4 MTU=$_m confirmed via $_t"
        printf "%s" "$_m"
        return 0
      fi
    done
  done
  printf "%s" "$DEFAULT_WAN_MTU"
}

if [ "${WAN_IS_PPPOE:-0}" -eq 1 ]; then
  WAN_MTU="$PPPOE_WAN_MTU"
  ok "PPPoE: MTU fixed at $WAN_MTU"
else
  WAN_MTU=""

  # IPv6 probe first (mirrors TN_NET_SET.sh)
  if [ "${HAS_INET6:-1}" -eq 1 ]; then
    info "Running IPv6 MTU probe ladder..."
    WAN_MTU=$(_find_mtu6)
    ok "IPv6 path MTU: $WAN_MTU"
  fi

  # IPv4 fallback if IPv6 probe was skipped or unavailable
  if [ -z "$WAN_MTU" ] && [ -n "${EXT_GW4:-}" ]; then
    info "Running IPv4 MTU probe ladder (fallback)..."
    if ping -c 2 "$EXT_GW4" > /dev/null 2>&1; then
      WAN_MTU=$(_find_mtu4)
      ok "IPv4 path MTU: $WAN_MTU"
    else
      warn "IPv4 gateway $EXT_GW4 unreachable"
    fi
  fi

  if [ -z "$WAN_MTU" ]; then
    warn "All MTU probes failed - using conservative default $DEFAULT_WAN_MTU"
    WAN_MTU="$DEFAULT_WAN_MTU"
  fi
fi

# =============================================================================
# STAGE 4 - MSS DERIVATION
# =============================================================================
print_header "Stage 4: MSS Derivation"

_wan_type="ethernet"
[ "${WAN_IS_PPPOE:-0}" -eq 1 ] && _wan_type="pppoe"

derive_mss "WAN" "$_wan_type" "$WAN_MTU"
derive_mss "INT" "ethernet" "1500"

# Backward-compat aliases consumed by existing pf.conf template
PF_MAX_MSS4_EXT_IF="$WAN_MSS4"
PF_MAX_MSS6_EXT_IF="$WAN_MSS6"
PF_MAX_MSS4_INT_IF="$INT_MSS4"
PF_MAX_MSS6_INT_IF="$INT_MSS6"

ok "WAN MTU=$WAN_MTU  MSS4=$WAN_MSS4  MSS6=$WAN_MSS6"
ok "LAN MSS4=$INT_MSS4  MSS6=$INT_MSS6"

# =============================================================================
# STAGE 5 - WRITE TO /etc/tn-interfaces
#
# Key present -> sed updates in place
# Key absent  -> appended at end of file
# Dry-run     -> log what would be written, touch nothing
# =============================================================================
print_header "Stage 5: Writing values to $TN_INTERFACES"

_write_or_append() {
  _wa_key="$1"
  _wa_val="$2"
  _wa_file="$3"

  if grep -q "^${_wa_key}=" "$_wa_file" 2> /dev/null; then
    sed -i "s|^${_wa_key}=.*|${_wa_key}=${_wa_val}|" "$_wa_file"
    ok "  Updated : ${_wa_key}=${_wa_val}"
  else
    printf '%s=%s\n' "$_wa_key" "$_wa_val" >> "$_wa_file"
    ok "  Appended: ${_wa_key}=${_wa_val}"
  fi
}

if [ "$DRYRUN" -eq 1 ]; then
  info "Would write to $TN_INTERFACES:"
  info "  WAN_MTU=\"$WAN_MTU\""
  info "  WAN_MSS4=\"$WAN_MSS4\""
  info "  WAN_MSS6=\"$WAN_MSS6\""
  info "  PF_MAX_MSS4_EXT_IF=\"$PF_MAX_MSS4_EXT_IF\""
  info "  PF_MAX_MSS6_EXT_IF=\"$PF_MAX_MSS6_EXT_IF\""
  info "  PF_MAX_MSS4_INT_IF=\"$PF_MAX_MSS4_INT_IF\""
  info "  PF_MAX_MSS6_INT_IF=\"$PF_MAX_MSS6_INT_IF\""
else
  _write_or_append "WAN_MTU" "\"$WAN_MTU\"" "$TN_INTERFACES"
  _write_or_append "WAN_MSS4" "\"$WAN_MSS4\"" "$TN_INTERFACES"
  _write_or_append "WAN_MSS6" "\"$WAN_MSS6\"" "$TN_INTERFACES"
  _write_or_append "PF_MAX_MSS4_EXT_IF" "\"$PF_MAX_MSS4_EXT_IF\"" "$TN_INTERFACES"
  _write_or_append "PF_MAX_MSS6_EXT_IF" "\"$PF_MAX_MSS6_EXT_IF\"" "$TN_INTERFACES"
  _write_or_append "PF_MAX_MSS4_INT_IF" "\"$PF_MAX_MSS4_INT_IF\"" "$TN_INTERFACES"
  _write_or_append "PF_MAX_MSS6_INT_IF" "\"$PF_MAX_MSS6_INT_IF\"" "$TN_INTERFACES"
  ok "Values written to $TN_INTERFACES"
fi

# =============================================================================
# STAGE 6 - FINAL SUMMARY
# =============================================================================
print_header "tn-mtu-probe.sh complete"
info "  EXT_IF           : $EXT_IF"
info "  INT_IF           : $INT_IF"
info "  WAN_MTU          : $WAN_MTU"
info "  WAN_MSS4         : $WAN_MSS4"
info "  WAN_MSS6         : $WAN_MSS6"
info "  PF_MAX_MSS4_EXT  : $PF_MAX_MSS4_EXT_IF"
info "  PF_MAX_MSS6_EXT  : $PF_MAX_MSS6_EXT_IF"
info "  PF_MAX_MSS4_INT  : $PF_MAX_MSS4_INT_IF"
info "  PF_MAX_MSS6_INT  : $PF_MAX_MSS6_INT_IF"
if [ "$DRYRUN" -eq 1 ]; then
  info "  Dry-run - $TN_INTERFACES was NOT modified"
fi

exit 0
