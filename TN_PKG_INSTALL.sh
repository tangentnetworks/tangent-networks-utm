#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# =============================================================================
# TN_PKG_INSTALL.sh -- Tangent Networks Package Installer v6.4.0
# =============================================================================
# Stage 2 of the TN UTM installer.
#
# Responsibilities:
#  00. Pre-flight checks (root, dependencies, environment guards)
#  01. Run syspatch -- patch OS, set reboot flag on errata
#  02. Upgrade all installed packages (pkg_add -Uu)
#  03. Refresh pkg-index.txt from mirror
#  04. Verify SHA256 hashes for custom local packages
#  05. Install mirror packages          (MIRROR_PKGS)
#  06. Install version-resolved packages (VERSION_PKGS)
#  07. Install unflavored packages      (UNFLAVORED_PKGS)
#  08. Install custom local packages    (CUSTOM_PKGS)
#  09. Verify all installed packages
#  10. Bootstrap infrastructure (dirs, files, ownership, governance)
#  11. Deploy payload (sbin, etc configs, webroot)
#  12. Merge system configs (sysctl, logging, httpd, crontab)
#  13. Initialise authdb (inline ksh -- sqlite3 + /dev/urandom, no perl)
#  14. Service smoke tests (rc.d enable+start; local binary launch+verify)
#  15. Final consolidated report
#  16. Write /root/packages-setup on full success
#  17. Validate payload/etc/pf.conf syntax (pfctl -nf), deploy to /etc/pf.conf,
#      reload pf ruleset -- only runs when all prior phases succeeded cleanly.
#
# ERROR HANDLING / RESUME:
#   No automatic rollback. On any failure the operator is asked:
#     y  -> problem fixed, retry the failed step immediately.
#     n  -> write a phase checkpoint and exit cleanly.
#            On re-run, completed phases are skipped automatically.
#
#   Rollback artifacts (pre-install pkg snapshot, backed-up configs) are
#   preserved in ROLLBACK_DIR for manual use.
#
# AUTHOR: Tangent Networks
# VERSION: 6.4.0
# =============================================================================

# -e intentionally omitted -- errors handled via phase_error() / retry loops.
set -uo pipefail

umask 022

# =============================================================================
# PATHS
# =============================================================================
TNDIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD_DIR="$TNDIR/payload"
LOG_DIR="$TNDIR/logs"
LOGFILE="$LOG_DIR/pkg-install.log"
PKG_DIR="$TNDIR/packages"
# PKG_DIR_ARCH, PKG_INDEX, and MANIFEST are set after arch detection below.
# Declared here as empty so any early reference produces a clear error rather
# than silently using the non-arch path.
PKG_DIR_ARCH=""
PKG_INDEX=""
MANIFEST=""
STATUS_OK="/root/packages-setup"
TN_INTERFACES="/etc/tn-interfaces"
SCHEMA="$TNDIR/schema.sql"
ROLLBACK_DIR="$TNDIR/rollback/$(date '+%Y%m%d_%H%M%S')"
PHASE_STATE_FILE="$TNDIR/.install_phases"

# Per-run state files -- survive resume across script restarts.
# Written by each phase that produces cross-phase state; read back at startup.
_STATE_PKG_ERR="$TNDIR/.state_pkg_err"
_STATE_SMOKE="$TNDIR/.state_smoke"
_STATE_RESOLVED="$TNDIR/.state_resolved"

BASE="/var/www/htdocs/tn/data"
AUTH_DB="$BASE/db/auth.db"
KEYS_DIR="$BASE/keys"
SESSION_DIR="$BASE/run/session"

# =============================================================================
# INSTALL STATE
# =============================================================================
INSTALL_COMPLETE=0
REBOOT_REQUIRED=0
RESOLVED_VERSION_PKGS=""
PKG_ERR_COUNT=0
SMOKE_ERR_COUNT=0
PKGS_INSTALLED_THIS_RUN=""

# Restore cross-phase state from previous run if resuming.
# These files are written by their respective phases and read here so that
# Phase 10 always sees the real error counts even when earlier phases are
# skipped via the checkpoint system.
[ -f "$_STATE_PKG_ERR" ] && PKG_ERR_COUNT=$(cat "$_STATE_PKG_ERR")
[ -f "$_STATE_SMOKE" ] && {
  SMOKE_ERR_COUNT=$(head -1 "$_STATE_SMOKE")
  SMOKE_RESULTS=$(tail -n +2 "$_STATE_SMOKE")
}
[ -f "$_STATE_RESOLVED" ] && RESOLVED_VERSION_PKGS=$(cat "$_STATE_RESOLVED")

mkdir -p "$LOG_DIR"

# =============================================================================
# COLOUR -- only when stdout is a terminal
# =============================================================================
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  CYAN=''
  BOLD=''
  NC=''
fi

# =============================================================================
# LOGGING
# =============================================================================
_log() {
  local _ll="$1"
  shift
  printf "[%s] [%-5s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$_ll" "$*" \
    >> "$LOGFILE"
}

ok() {
  printf "  ${GREEN}[OK]${NC}    %s\n" "$1"
  _log "OK" "$1"
}
err() {
  printf "  ${RED}[ERR]${NC}   %s\n" "$1"
  _log "ERR" "$1"
}
warn() {
  printf "  ${YELLOW}[WARN]${NC}  %s\n" "$1"
  _log "WARN" "$1"
}
info() {
  printf "  ${CYAN}[INFO]${NC}  %s\n" "$1"
  _log "INFO" "$1"
}

print_header() {
  echo ""
  echo "============================================================"
  printf "  ${BOLD}%s${NC}\n" "$1"
  echo "============================================================"
  _log "INFO" "=== $1 ==="
}

print_section() {
  echo ""
  printf "  ${CYAN}-- %s --${NC}\n" "$1"
  _log "INFO" "-- $1 --"
}

print_phase_notice() {
  echo ""
  echo "  ============================================================"
  printf "  ${YELLOW}*** NOTICE ***${NC}  %s\n" "$1"
  echo "  ============================================================"
  shift
  while [ $# -gt 0 ]; do
    printf "  ${CYAN}>>>${NC} %s\n" "$1"
    shift
  done
  echo "  ============================================================"
  echo ""
}

run_optional() {
  "$@" || warn "Non-fatal: '$*' returned $? (continuing)"
}

printf "\n=== RUN %s ===\n" "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOGFILE"

# =============================================================================
# PHASE CHECKPOINT / RESUME SYSTEM
# =============================================================================
phase_done() {
  local _id="$1"
  grep -qxF "DONE:${_id}" "$PHASE_STATE_FILE" 2> /dev/null && return 0
  printf "DONE:%s\n" "$_id" >> "$PHASE_STATE_FILE"
  _log "INFO" "Phase checkpoint: $_id"
}

phase_completed() {
  grep -qxF "DONE:${1}" "$PHASE_STATE_FILE" 2> /dev/null
}

phase_error() {
  local _id="$1" _desc="$2"
  err "Phase $_id failed: $_desc"
  echo ""
  echo "  ============================================================"
  echo "  INSTALLER PAUSED -- Phase $_id"
  echo "  Error: $_desc"
  echo "  ============================================================"
  echo "  Fix the problem from another console, then answer below."
  echo ""
  printf "  Has the problem been fixed? Continue? (y/n): "
  local _ans
  read -r _ans < /dev/tty
  case "$_ans" in
    y | Y | yes | YES)
      info "Operator confirmed fix -- retrying."
      return 1
      ;;
    *)
      warn "Operator chose to stop. Checkpointing current state."
      warn "Re-run the installer to resume from the next incomplete phase."
      _log "WARN" "Install paused at $_id by operator choice."
      exit 0
      ;;
  esac
}

# =============================================================================
# SNAPSHOT
# =============================================================================
snapshot_state() {
  mkdir -p "$ROLLBACK_DIR"
  pkg_info -a | awk '{print $1}' > "$ROLLBACK_DIR/pkg-list-before.txt"
  _log "INFO" "Pre-install snapshot: $ROLLBACK_DIR/pkg-list-before.txt"
  ok "Rollback reference snapshot: $ROLLBACK_DIR"
}

record_pkg() {
  PKGS_INSTALLED_THIS_RUN="$PKGS_INSTALLED_THIS_RUN $1"
}

# pkg_run: pkg_add with live output + ksh-compatible exit capture (no PIPESTATUS)
pkg_run() {
  local _label="$1"
  shift
  {
    "$@" 2>&1
    echo $? > /tmp/tn_pkg_exit.$$
  } | tee -a "$LOGFILE"
  local _e
  _e=$(cat /tmp/tn_pkg_exit.$$)
  rm -f /tmp/tn_pkg_exit.$$
  if [ "$_e" -ne 0 ]; then
    err "$_label failed (exit $_e)"
    return 1
  fi
  return 0
}

# =============================================================================
# SOURCE INTERFACES
# =============================================================================
if [ -f "$TN_INTERFACES" ]; then
  . "$TN_INTERFACES"
else
  err "$TN_INTERFACES not found. Run TN_NET_SET.sh first."
  exit 1
fi

# =============================================================================
# DNS CONFIRMATION (only when PUBLIC_DOMAIN is configured)
# =============================================================================
if [ "${PUBLIC_DOMAIN:-none}" != "none" ] && [ -n "${PUBLIC_DOMAIN:-}" ]; then
  print_header "Public Domain DNS Verification"
  info "Target Domain: $PUBLIC_DOMAIN"
  info "External IP:   ${EXT_IP4:-<not set>}"
  echo ""
  warn "ACME requires your DNS A record for [$PUBLIC_DOMAIN]"
  warn "to point exactly to [${EXT_IP4:-<not set>}]."
  echo ""
  printf "  Have you updated your DNS records? (y/n) [y]: "
  read -r DNS_CONFIRM < /dev/tty
  if [ "$DNS_CONFIRM" = "n" ] || [ "$DNS_CONFIRM" = "N" ]; then
    print_header "DNS Setup Instructions"
    echo "  1. Log into your DNS Provider"
    echo "  2. Create an A record for: $PUBLIC_DOMAIN"
    echo "  3. Point it to: ${EXT_IP4:-<set EXT_IP4 in tn-interfaces>}"
    echo ""
    warn "Install continues with self-signed certificate."
    warn "SSL renewal will fail until DNS is resolved."
    printf "  Press [ENTER] to continue..."
    read -r _ < /dev/tty
  else
    ok "Proceeding with SSL configuration for $PUBLIC_DOMAIN."
  fi
fi

# =============================================================================
# CONFIGURATION
# =============================================================================
# =============================================================================
# ENVIRONMENT DETECTION & ARCHITECTURE BOUNDS (AUTOMATED)
# =============================================================================
OS_VER=$(uname -r)
_RAW_ARCH=$(uname -m)

case "$_RAW_ARCH" in
  amd64) OS_ARCH="amd64" ;;
  aarch64 | arm64) OS_ARCH="aarch64" ;;
  *)
    err "Unsupported architecture: $_RAW_ARCH"
    exit 1
    ;;
esac

# =============================================================================
# MIRROR CONFIGURATION
# =============================================================================
PKG_DIR_ARCH="${PKG_DIR}/${OS_VER}/${OS_ARCH}"
PKG_INDEX="${PKG_DIR_ARCH}/pkg-index.txt"
MANIFEST="${PKG_DIR_ARCH}/SHA256"
export PKG_CACHE="$PKG_DIR_ARCH"

# =============================================================================
# MIRROR SELECTION AND REACHABILITY CHECK
# =============================================================================
# Mirrors are tried in order. pkg_add uses the full PKG_PATH chain so if
# the primary fails for a package the next mirror is attempted automatically.
# Cloudflare is last -- it rate-limits bulk installs and should only be
# used as a last resort.
# Mirror list sourced from https://www.openbsd.org/ftp.html (official only).
#
# Coverage:
#   Singapore   -- mirror.freedif.org          (Singapore opensource software mirror)
#   Japan       -- ftp.jaist.ac.jp             (JAIST)
#   Australia   -- mirror.aarnet.edu.au        (AARNet)
#   Europe      -- ftp.nluug.nl                (Association of professional UNIX and Linux users)
#   CDN         -- mirror.leaseweb.com         (LEASEWEB CDN )
#   CDN         -- mirror.planetunix.net       (CDN)
#   Origin      -- ftp.openbsd.org             (canonical, slow but authoritative)
#   CDN         -- cloudflare.cdn.openbsd.org  (last resort, rate-limits bulk)
# =============================================================================

# Full mirror list in preferred order -- paths expanded with OS_VER/OS_ARCH
_MIRRORS="\
https://mirror.freedif.org/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH} \
https://ftp.jaist.ac.jp/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH} \
https://mirror.aarnet.edu.au/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH} \
https://ftp.nluug.nl/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH} \
https://mirror.leaseweb.com/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH} \
https://mirror.planetunix.net/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH} \
https://ftp.openbsd.org/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH} \
https://cloudflare.cdn.openbsd.org/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH}"

# Base URLs only for reachability probing.
# Cloudflare is excluded -- it always responds to HEAD (rate-limiting happens
# later during bulk download, not at the probe stage, so it would always
# appear reachable and tell us nothing useful).
_PROBE_MIRRORS="\
https://mirror.freedif.org \
https://ftp.jaist.ac.jp \
https://mirror.leaseweb.com \
https://mirror.aarnet.edu.au \
https://mirror.planetunix.net \
https://ftp.nluug.nl \
https://ftp.openbsd.org"

print_header "Mirror Selection"
info "Probing mirrors for reachability (8s timeout each)..."

_reachable=""
_unreachable=""

for _m in $_PROBE_MIRRORS; do
  _url="${_m}/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH}/"
  if curl -sf --max-time 8 --head "$_url" > /dev/null 2>&1; then
    ok "  Reachable : $_m"
    _reachable="${_reachable} ${_m}"
  else
    warn "  Unreachable: $_m"
    _unreachable="${_unreachable} ${_m}"
  fi
done

if [ -z "$_reachable" ]; then
  warn "No preferred mirror reachable -- falling back to Cloudflare only"
  warn "Large installs may be rate-limited. Consider retrying later."
  export PKG_PATH="https://cloudflare.cdn.openbsd.org/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH}"
else
  # Build PKG_PATH: reachable mirrors first (in original order),
  # then unreachable preferred mirrors (pkg_add may still reach them),
  # then Cloudflare always last.
  _pkg_path=""

  # Pass 1: reachable mirrors in order
  for _m in $_MIRRORS; do
    _base=$(echo "$_m" | sed 's|/pub/OpenBSD/.*||')
    # Skip Cloudflare -- added explicitly at the end
    case "$_base" in
      *cloudflare*) continue ;;
    esac
    case "$_reachable" in
      *"$_base"*) _pkg_path="${_pkg_path}${_m}:" ;;
    esac
  done

  # Pass 2: unreachable preferred mirrors (fallback, worth trying)
  for _m in $_MIRRORS; do
    _base=$(echo "$_m" | sed 's|/pub/OpenBSD/.*||')
    case "$_base" in
      *cloudflare*) continue ;;
    esac
    case "$_reachable" in
      *"$_base"*) ;; # already added in pass 1
      *) _pkg_path="${_pkg_path}${_m}:" ;;
    esac
  done

  # Always append Cloudflare last
  _pkg_path="${_pkg_path}https://cloudflare.cdn.openbsd.org/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH}"

  export PKG_PATH="$_pkg_path"
fi

info "Host Machine Metrics:"
info "  -> OS Release : OpenBSD $OS_VER"
info "  -> Arch Type  : $OS_ARCH"
info "  -> Package Src: $PKG_DIR_ARCH"
info "  -> Reachable  :${_reachable:- (none)}"
[ -n "$_unreachable" ] \
  && info "  -> Unreachable:${_unreachable} (kept as fallback in PKG_PATH)"
info "  -> PKG_PATH   :"
# Split on https:// to avoid breaking the scheme colon
echo "$PKG_PATH" | sed 's|:https://|\nhttps://|g' | while read -r _p; do
  [ -n "$_p" ] && info "                 $_p"
done

# =============================================================================
# AUTOMATED LIFECYCLE GATE
# =============================================================================
if [ ! -d "$PKG_DIR_ARCH" ]; then
  echo ""
  err "========================================================================="
  err " ERROR: UNSUPPORTED OR END-OF-LIFE (EOL) ENVIRONMENT DETECTED"
  err "========================================================================="
  err "The running OS version ($OS_VER) does not match the active bundles inside"
  err "your distribution directory."
  err ""
  err "Missing target directory: $PKG_DIR_ARCH"
  err ""
  err "Currently active deployment channels available in this build bundle:"

  _FOUND_ANY=0
  for _v_dir in $(ls -d "${PKG_DIR}/"[0-9].* 2> /dev/null); do
    _v_name=$(basename "$_v_dir")
    if [ -d "${_v_dir}/${OS_ARCH}" ]; then
      err "  -> OpenBSD ${_v_name} (${OS_ARCH})"
      _FOUND_ANY=1
    fi
  done

  if [ "$_FOUND_ANY" -eq 0 ]; then
    err "  -> [None found! The packages/ folder is empty or unpopulated]"
  fi
  err "========================================================================="
  exit 1
fi

# =============================================================================
# PACKAGE LISTS
# =============================================================================
MIRROR_PKGS="curl base64 bzip2 clamav collectd collectd-ping collectd-rrdtool dante daq drill \
iso-codes jq libb2 libdnet libevent libffi libiconv libltdl libnet liboping libpaper libsigsegv \
libstatgrab libtool libyajl lunzip oinkmaster p5-Crypt-PBKDF2 p5-Crypt-SSLeay p5-DateManip \
p5-DateTime p5-Digest-SHA3 p5-File-Scan-ClamAV p5-File-Slurp p5-File-Slurp-Tiny p5-File-Which \
p5-HTML-Lint p5-IO-Socket-Timeout p5-IPC-Run p5-JSON p5-JSON-XS p5-LWP-Protocol-https \
p5-MIME-Lite p5-MIME-Types p5-Mail-SpamAssassin p5-Net-IP p5-Net-SMTP-SSL p5-Readonly \
p5-Sys-Hostname-Long p5-Text-Markdown p5-XML-Parser p5-libwww pcre rrdtool socat sqlite3 \
truncate wget xz zip p5-DBD-SQLite2 tree"

VERSION_PKGS="db-[0-9] python-[0-9]"
UNFLAVORED_PKGS="pmacct-- unzip--"

CUSTOM_PKGS="SSLproxy-0.9.9.tgz e2guardian-5.3.5.tgz imspector-0.9.tgz p3scan-2.3.2.tgz \
smtp-gated-1.4.20.0.tgz snort-2.9.20p8.tgz snortsentry-8.1.7.tgz"

# Payload tarballs -- no SHA256 required; extracted after package install
PAYLOAD_TARBALLS="rules.tar.gz lists.tar.gz"

RCD_SERVICES="cron dhcpd ftpproxy ftpproxy6 httpd ntpd rad slaacd slowcgi smtpd syslogd unbound"
LOCAL_SERVICES="snort snortinline snortsentry e2guardian collectd p3scan clamd freshclam \
pmacct sockd spamd smtp-gated sslproxy imspector tcpdump"

# =============================================================================
# PRE-FLIGHT
# =============================================================================
print_header "Tangent Networks -- Package Installer v6.4.0"
info "Log:    $LOGFILE"
info "Phases: $PHASE_STATE_FILE"
echo ""

warn "pkg_add output is LIVE on stdout and mirrored to log."
warn "Silence mid-phase = mirror not responding -- check connectivity."
warn "Do NOT delete or overwrite: $LOGFILE"
echo ""

if [ "$(id -u)" -ne 0 ]; then
  err "Must run as root: doas ksh $0"
  exit 1
fi

print_header "Pre-flight: Environment Guards"

_require_var() {
  local _var="$1" _desc="$2" _val
  eval "_val=\"\${${_var}:-}\""
  if [ -z "$_val" ]; then
    err "Required variable \$$_var is unset or empty ($_desc)"
    exit 1
  fi
  ok "$_var is set"
}

_require_file() {
  local _path="$1" _desc="$2"
  if [ ! -f "$_path" ]; then
    err "Required file not found: $_path ($_desc)"
    exit 1
  fi
  ok "Found: $_path"
}

_require_var INT_IP4 "internal interface IP (from tn-interfaces)"
_require_var INT_IF "internal interface name (from tn-interfaces)"
_require_var TLS_CERT "TLS certificate path (from tn-interfaces)"
_require_var TLS_KEY "TLS private key path (from tn-interfaces)"
_require_var CERT_CN "TLS common name / server name (from tn-interfaces)"

_require_file "$MANIFEST" "SHA256 manifest"
_require_file "$SCHEMA" "schema.sql"
_require_file "$PAYLOAD_DIR/etc/sysctl.conf" "payload sysctl.conf"
_require_file "$PAYLOAD_DIR/etc/syslog.conf" "payload syslog.conf"
_require_file "$PAYLOAD_DIR/etc/newsyslog.conf" "payload newsyslog.conf"
# NOTE: payload/etc/httpd.conf is NOT required -- httpd.conf is generated
#       from scratch by _merge_httpd() using variables from tn-interfaces.
_require_file "$PAYLOAD_DIR/etc/crontab" "payload crontab"
_require_file "$PAYLOAD_DIR/var/unbound/etc/unbound.conf" "payload unbound.conf"

for _pkg in $CUSTOM_PKGS; do
  _require_file "$PKG_DIR_ARCH/$_pkg" "custom local package"
done

HAVE_SYSPATCH=0
command -v syspatch > /dev/null 2>&1 && HAVE_SYSPATCH=1 && ok "syspatch found" \
  || warn "syspatch not found -- OS patching will be skipped"

ok "All pre-flight guards passed."

snapshot_state

# =============================================================================
# SHARED HELPERS
# =============================================================================
setup_dir() {
  local _dir="$1" _owner="$2" _group="$3" _mode="$4"
  mkdir -p "$_dir"
  chown "$_owner:$_group" "$_dir"
  chmod "$_mode" "$_dir"
}

setup_file() {
  local _file="$1" _owner="$2" _group="$3" _mode="$4"
  touch "$_file"
  chown "$_owner:$_group" "$_file"
  chmod "$_mode" "$_file"
}

# Cached pkg_info snapshot -- refreshed before each package phase.
# Avoids forking pkg_info once per package in _pkg_install_or_accept.
_PKG_INFO_CACHE=""

_refresh_pkg_cache() {
  _PKG_INFO_CACHE=$(pkg_info -a 2> /dev/null | awk '{print $1}')
}

# =============================================================================
# PACKAGE INDEX FETCH -- unconditional, every run
# =============================================================================
# The pkg-index.txt is always re-fetched regardless of phase checkpoints.
# Phase 3 (version-resolved packages) greps this file at runtime -- if it is
# absent or stale from a prior run the grep silently fails and version
# resolution produces no output, causing "could not resolve" errors.
# The fetch is cheap (one HTTP request) and must never be gated by a
# phase checkpoint.
# =============================================================================
print_header "Package Index Fetch"
mkdir -p "$PKG_DIR_ARCH"

# Index fetch uses Cloudflare directly -- it reliably serves index.txt.
# PKG_PATH is colon-separated for pkg_add but ftp needs a single URL.
# Other mirrors are replicas and may not serve the index consistently.
_INDEX_URL="https://cloudflare.cdn.openbsd.org/pub/OpenBSD/${OS_VER}/packages/${OS_ARCH}/index.txt"

while true; do
  info "Fetching package index from Cloudflare (timeout: 30s)..."
  if ftp -w 30 -o - "$_INDEX_URL" \
    | awk '{gsub(/\.tgz$/, "", $NF); print $NF}' > "$PKG_INDEX" 2> /dev/null \
    && [ -s "$PKG_INDEX" ]; then
    ok "pkg-index.txt updated: $PKG_INDEX ($(wc -l < "$PKG_INDEX" | tr -d ' ') entries)"
    break
  else
    err "Mirror index fetch failed or produced empty file."
    err "Check connectivity: ftp -o - $_INDEX_URL"
    phase_error "index-fetch" "mirror index fetch failed" || continue
    break
  fi
done

# =============================================================================
# PHASE 0: System Patch & Package Sync
# =============================================================================
if phase_completed "phase0"; then
  warn "Phase 0 already complete -- skipping."
else
  print_header "Phase 0: System Patch & Package Sync"

  print_phase_notice "Phase 0: Read Before Proceeding" \
    "" \
    "CONDITION 1 -- Download failure (timeout / mirror unreachable / rate-limited):" \
    "  The installer will pause and prompt [y/n]." \
    "  Fix connectivity from another console, then answer [y] to retry." \
    "  Already-downloaded packages are skipped automatically (hash-verified)." \
    "" \
    "CONDITION 2 -- Partial install (pkg_add failed mid-install):" \
    "  A broken dependency tree may exist on the system." \
    "  From another console, clean and reinstall the failed package:" \
    "    pkg_delete -Iv <packagename>" \
    "    pkg_add -Iv <packagename>" \
    "  Then answer [y] at the installer prompt to continue."

  if [ "$HAVE_SYSPATCH" -eq 1 ]; then
    print_section "Running syspatch"

    # FIX: pre-assign to avoid unbound variable with set -uo pipefail
    SYSPATCH_EXIT=0
    SYSPATCH_OUT=$(syspatch 2>&1) || SYSPATCH_EXIT=$?
    [ -n "$SYSPATCH_OUT" ] && printf '%s\n' "$SYSPATCH_OUT" | tee -a "$LOGFILE"

    if printf '%s\n' "$SYSPATCH_OUT" | grep -qF "syspatch: Read-only filesystem, aborting"; then
      warn "syspatch: Read-only filesystem -- applying checkfs workaround"
      sed -e 's/checkfs/#checkfs/g' /usr/sbin/syspatch > /root/syspatch_tn
      chmod 700 /root/syspatch_tn
      info "Running checkfs-stripped syspatch pass..."
      ksh /root/syspatch_tn 2>&1 | tee -a "$LOGFILE" || true
      rm -f /root/syspatch_tn
      info "Rebuilding device database..."
      dev_mkdb 2>&1 | tee -a "$LOGFILE" || true
      SYSPATCH_OUT=""
      SYSPATCH_EXIT=0
    fi

    if [ "$SYSPATCH_EXIT" -eq 0 ] || [ "$SYSPATCH_EXIT" -eq 2 ]; then
      if printf '%s' "$SYSPATCH_OUT" | grep -q "syspatch updated itself"; then
        warn "syspatch updated itself -- running second pass..."
        SYSPATCH_EXIT_2=0
        SYSPATCH_OUT_2=$(syspatch 2>&1) || SYSPATCH_EXIT_2=$?
        [ -n "$SYSPATCH_OUT_2" ] && printf '%s\n' "$SYSPATCH_OUT_2" | tee -a "$LOGFILE"
        printf '%s' "$SYSPATCH_OUT_2" | grep -q "Errata" && REBOOT_REQUIRED=1
      elif printf '%s' "$SYSPATCH_OUT" | grep -q "Errata"; then
        REBOOT_REQUIRED=1
      fi
      ok "syspatch complete"
    else
      while true; do
        phase_error "phase0" "syspatch failed (exit $SYSPATCH_EXIT)" || continue
        break
      done
    fi
  else
    warn "Skipping syspatch (not available)"
  fi

  print_section "Upgrading installed packages (targeted)"
  # Replace the blanket pkg_add -Uu with a targeted upgrade that only touches
  # packages the mirror actually has a newer version of. On re-runs where most
  # packages are already current this avoids the full index scan and download
  # negotiation that makes pkg_add -Uu slow even when there is nothing to do.
  #
  # Strategy:
  #   1. Snapshot installed packages from pkg_info -a into a temp file.
  #      Writing to a file rather than piping into a while loop avoids the
  #      ksh subshell problem where variable assignments inside a pipe body
  #      are lost when the subshell exits.
  #   2. For each installed package, look up its stem in PKG_INDEX (the fresh
  #      mirror index fetched unconditionally above). If the mirror has a
  #      strictly higher version, queue the stem for upgrade.
  #   3. Version comparison uses sort -V (version-aware sort) to correctly
  #      handle multi-part version strings like 8.9 vs 8.10 where lexicographic
  #      comparison gives the wrong answer.
  #   4. If the installed version is >= mirror version (common after an errata
  #      patch that has not yet propagated to all mirrors) the package is
  #      skipped -- we never downgrade.
  #   5. Queued stems are written to a second temp file to keep all assignments
  #      in the main shell scope. Both temp files land on /tmp which is MFS
  #      on this system, so no disk wear.
  #   6. pkg_add -u (without -I) is used so dependency resolution runs
  #      normally. Skipping dependency checks with -I risks a broken package
  #      tree if an upgrade pulls in a new dependency.
  #
  # PKG_INDEX contains one entry per line in the form: stem-version
  # It is produced by the index fetch above which strips the .tgz suffix.
  _inst_tmp=$(mktemp /tmp/tn_inst.XXXXXX)
  _upgr_tmp=$(mktemp /tmp/tn_upgr.XXXXXX)

  # Snapshot installed package names (stem-version, one per line)
  pkg_info -a 2> /dev/null | awk '{print $1}' > "$_inst_tmp"
  info "  Installed packages: $(wc -l < "$_inst_tmp" | tr -d ' ') total"

  # Build exclusion set from CUSTOM_PKGS - these are pinned local builds
  # that must never be upgraded from the mirror regardless of version.
  # Strip the .tgz suffix and version to get bare stems for comparison.
  _custom_stems=""
  for _cp in $CUSTOM_PKGS; do
    _cs=$(printf '%s' "$_cp" | sed -E 's/-[0-9][^ ]*\.tgz$//' | sed 's/--$//')
    _custom_stems="$_custom_stems $_cs"
  done

  while IFS= read -r _inst_pkg; do
    # Derive stem: strip version suffix and unflavored marker (--)
    _inst_stem=$(printf '%s' "$_inst_pkg" | sed -E 's/-[0-9][^ ]*$//')

    # Skip custom local packages - these are pinned builds not managed
    # by the mirror. Version differences are intentional.
    case " $_custom_stems " in
      *" $_inst_stem "*) continue ;;
    esac

    # Derive installed version: last -<digit>... token, leading dash stripped
    _inst_ver=$(printf '%s' "$_inst_pkg" | sed -nE 's/.*-([0-9][^ ]*)/\1/p')

    # Skip packages with no parseable version (meta-packages, quirks, etc.)
    [ -z "$_inst_ver" ] && continue

    # Find the highest available version for this stem in the mirror index.
    # tail -1 picks the last (highest) entry when multiple versions exist.
    _idx_line=$(grep "^${_inst_stem}-[0-9]" "$PKG_INDEX" 2> /dev/null | tail -1)

    # Not in index: custom local package or dependency-only package with no
    # mirror entry. Skip -- pkg_add cannot upgrade what it cannot find.
    [ -z "$_idx_line" ] && continue

    # Derive mirror version from the index entry
    _idx_ver=$(printf '%s' "$_idx_line" | sed -nE 's/.*-([0-9][^ ]*)/\1/p')
    [ -z "$_idx_ver" ] && continue

    # Version comparison via sort -V.
    # sort -V understands 8.9 < 8.10, p0/p1 patchlevel suffixes, etc.
    # tail -1 gives the higher of the two versions.
    # If installed is already the higher (or equal), skip.
    _higher=$(printf '%s\n%s\n' "$_inst_ver" "$_idx_ver" | sort -V | tail -1)
    if [ "$_higher" = "$_inst_ver" ] || [ "$_inst_ver" = "$_idx_ver" ]; then
      continue
    fi

    # Mirror has a strictly higher version -- queue this stem for upgrade
    info "  queued: $_inst_stem  $_inst_ver -> $_idx_ver"
    printf '%s\n' "$_inst_stem" >> "$_upgr_tmp"
  done < "$_inst_tmp"

  if [ ! -s "$_upgr_tmp" ]; then
    ok "All installed packages are current -- nothing to upgrade."
  else
    # Collapse newline-separated stems into a space-separated list for pkg_add.
    _upgrade_list=$(tr '\n' ' ' < "$_upgr_tmp")
    info "Running pkg_add -u on queued packages..."
    # SC2086: _upgrade_list is intentionally unquoted so pkg_add receives
    # each stem as a separate argument. Quoting would pass the entire
    # space-separated string as one argument and pkg_add would reject it.
    # shellcheck disable=SC2086
    pkg_add -uv $_upgrade_list 2>&1 | tee -a "$LOGFILE" || true
    ok "Targeted upgrade complete."
  fi

  # Clean up temp files. rm -f is safe even if mktemp failed and the
  # variables are empty -- rm -f on an empty string is a no-op on OpenBSD.
  rm -f "$_inst_tmp" "$_upgr_tmp"

  phase_done "phase0"
fi

# =============================================================================
# PHASE 1: Verify SHA256 Hashes
# =============================================================================
if phase_completed "phase1"; then
  warn "Phase 1 already complete -- skipping."
else
  print_header "Phase 1: Verify SHA256 Hashes"

  _verify_hash() {
    local _file="$1" _bn
    _bn=$(basename "$_file")
    printf "  [HASH] %-42s" "$_bn"
    local _exp _act
    _exp=$(grep "(${_bn})" "$MANIFEST" | awk '{print $NF}')
    if [ -z "$_exp" ]; then
      printf "${RED}NO ENTRY${NC}\n"
      err "No SHA256 entry in manifest for: $_bn"
      return 1
    fi
    _act=$(sha256 -q "$_file")
    if [ "$_act" = "$_exp" ]; then
      printf "${GREEN}OK${NC}\n"
      _log "OK" "Hash verified: $_bn"
    else
      printf "${RED}FAIL${NC}\n"
      err "Hash mismatch: $_bn  expected=$_exp  actual=$_act"
      return 1
    fi
  }

  print_section "Custom packages"
  for pkg in $CUSTOM_PKGS; do
    while true; do
      _verify_hash "$PKG_DIR_ARCH/$pkg" && break \
        || {
          phase_error "phase1" "hash failed: $pkg" || continue
          break
        }
    done
  done

  ok "All hashes verified."
  phase_done "phase1"
fi

# =============================================================================
# _pkg_install_or_accept
#
# Install a package or accept an already-installed version that satisfies
# the requirement, without forking pkg_info per package.
#
# Mirror indexes lag behind what is already installed -- this is especially
# common during errata cycles when OpenBSD pushes patch updates faster than
# CDN mirrors propagate their index. Blindly running pkg_add with a stale
# index name will either downgrade the package (harmful) or conflict-fail.
#
# Algorithm:
#   1. Derive stem from the package name (strip version suffix and -- marker).
#   2. Derive target version from the package name, or resolve from PKG_INDEX
#      when only a bare stem was given (common case for MIRROR_PKGS).
#   3. Query _PKG_INFO_CACHE (populated once per phase by refresh_pkg_cache)
#      instead of forking pkg_info on every call.
#   4. If installed and target version known:
#        - Same major AND installed >= target  -> accept, skip pkg_add.
#        - Different major or installed < target -> fall through to install.
#   5. If installed but no version resolvable (not in index, not in name)
#      -> accept as-is, skip pkg_add.
#   6. Otherwise run pkg_add with retry loop via phase_error so the operator
#      can fix and continue without restarting the entire phase.
#
# Sets global RESOLVED_VERSION_PKGS so Phase 6 verification knows what to
# check. Always calls record_pkg so the rollback manifest is complete.
#
# Arguments:
#   $1  label       - display name for ok/err messages
#   $2  pkg_name    - name passed to pkg_add (may include version or glob)
#   $3  phase_id    - phase checkpoint name for phase_error calls
#   $4  extra_flags - optional extra flags for pkg_add (e.g. "-z" for
#                     unflavored packages). Intentionally unquoted at call
#                     site to allow word splitting of multiple flags.
# =============================================================================
_pkg_install_or_accept() {
  _pia_label="$1"
  _pia_pkg="$2"
  _pia_phase="$3"
  _pia_flags="${4:-}"

  # Derive stem: strip version suffix and unflavored marker.
  # sed -E 's/-[0-9][^ ]*$//' handles stems that contain digits correctly:
  #   sqlite3-3.50.7p0  -> sqlite3   (not "sqlite" as grep -oE would give)
  #   p5-JSON-XS-4.03   -> p5-JSON-XS
  #   python-3.12.13    -> python
  #   pmacct--          -> pmacct    (unflavored, no version suffix)
  #   curl              -> curl      (bare stem, no version)
  _pia_stem=$(printf '%s' "$_pia_pkg" \
    | sed -E 's/-[0-9][^ ]*$//' \
    | sed 's/--$//')

  # Derive target version: the last -<digit>... token, leading dash stripped.
  # Returns empty for bare stems (curl) and unflavored packages (pmacct--).
  _pia_target_ver=$(printf '%s' "$_pia_pkg" \
    | sed -nE 's/.*-([0-9][^ ]*)/\1/p')

  # If no version in the package name, resolve from the local pkg-index.
  # Without this, bare stems like "curl" leave _pia_target_ver empty and
  # the guard below falls through to pkg_add even when a newer patch is
  # already installed, causing a conflict error.
  if [ -z "$_pia_target_ver" ] && [ -f "$PKG_INDEX" ]; then
    _pia_idx_match=$(grep "^${_pia_stem}-[0-9]" "$PKG_INDEX" | tail -1)
    if [ -n "$_pia_idx_match" ]; then
      _pia_target_ver=$(printf '%s' "$_pia_idx_match" \
        | sed -nE 's/.*-([0-9][^ ]*)/\1/p')
    fi
  fi

  # Query the in-memory cache instead of forking pkg_info once per package.
  # _PKG_INFO_CACHE is populated by refresh_pkg_cache before each phase loop.
  _pia_installed=$(printf '%s\n' "$_PKG_INFO_CACHE" \
    | awk -v s="$_pia_stem" 'BEGIN{q="^"s"-[0-9]"} $0 ~ q {print; exit}')

  if [ -n "$_pia_installed" ] && [ -n "$_pia_target_ver" ]; then
    # Extract installed version for comparison.
    _pia_inst_ver=$(printf '%s' "$_pia_installed" \
      | sed -nE 's/.*-([0-9][^ ]*)/\1/p')

    if [ -n "$_pia_inst_ver" ]; then
      # Compare major version only (first dot-separated field).
      # Minor differences (curl 8.16 -> 8.19) are the same upstream series
      # and should be accepted when installed is newer. A genuine series
      # change (python 3.11 -> 3.12) uses a different stem on OpenBSD and
      # is handled as a separate entry in VERSION_PKGS.
      _pia_inst_major=$(printf '%s' "$_pia_inst_ver" | awk -F. '{print $1}')
      _pia_tgt_major=$(printf '%s' "$_pia_target_ver" | awk -F. '{print $1}')

      if [ "$_pia_inst_major" = "$_pia_tgt_major" ]; then
        # Same major: accept if installed >= target.
        _pia_higher=$(printf '%s\n%s\n' "$_pia_inst_ver" "$_pia_target_ver" \
          | sort -V | tail -1)
        if [ "$_pia_higher" = "$_pia_inst_ver" ] \
          || [ "$_pia_inst_ver" = "$_pia_target_ver" ]; then
          ok "$_pia_stem: installed $_pia_inst_ver >= mirror $_pia_target_ver -- accepted, skipping install."
          RESOLVED_VERSION_PKGS="$RESOLVED_VERSION_PKGS $_pia_installed"
          record_pkg "$_pia_installed"
          return 0
        fi
      fi
      # Different major or installed < target: fall through to pkg_add.
      info "$_pia_stem: installed $_pia_inst_ver, mirror $_pia_target_ver -- installing."
    fi
  elif [ -n "$_pia_installed" ] && [ -z "$_pia_target_ver" ]; then
    # Package present but no version resolvable from index or name.
    # Accept what is installed rather than risk a conflict.
    ok "$_pia_stem: already installed ($_pia_installed) -- skipping."
    record_pkg "$_pia_installed"
    return 0
  fi

  # Installation needed: run pkg_add with operator retry on failure.
  while true; do
    # SC2086: _pia_flags is intentionally unquoted. It may contain multiple
    # flags (e.g. "-z -I") that must reach pkg_add as separate arguments.
    # Quoting would pass the entire string as a single argument.
    # shellcheck disable=SC2086
    pkg_run "$_pia_label" pkg_add -Iv $_pia_flags "$_pia_pkg" && {
      ok "$_pia_label installed."
      RESOLVED_VERSION_PKGS="$RESOLVED_VERSION_PKGS $_pia_pkg"
      record_pkg "$_pia_pkg"
      return 0
    } || {
      phase_error "$_pia_phase" "$_pia_label install failed" || continue
      break
    }
  done
}

# =============================================================================
# PHASE 2: Install Mirror Packages
# =============================================================================
if phase_completed "phase2"; then
  warn "Phase 2 already complete -- skipping."
else
  print_header "Phase 2: Install Mirror Packages"

  print_section "Installing quirks"
  pkg_add -Iv quirks 2>&1 | tee -a "$LOGFILE" || true
  record_pkg "quirks"

  print_section "Installing mirror packages"
  info "This phase may take several minutes. If output stops, check mirror connectivity."
  _refresh_pkg_cache
  for _pkg in $MIRROR_PKGS; do
    _pkg_install_or_accept "$_pkg" "$_pkg" "phase2"
  done
  ok "Mirror packages installed."
  phase_done "phase2"
fi

# =============================================================================
# PHASE 3: Install Version-Resolved Packages
# =============================================================================
if phase_completed "phase3"; then
  warn "Phase 3 already complete -- skipping."
else
  print_header "Phase 3: Install Version-Resolved Packages"

  _refresh_pkg_cache
  for pattern in $VERSION_PKGS; do
    pkg=$(grep "^${pattern}" "$PKG_INDEX" | tail -1)
    if [ -z "$pkg" ]; then
      while true; do
        phase_error "phase3" "could not resolve $pattern" || continue
        break
      done
      continue
    fi
    info "Resolved: $pattern --> $pkg"
    _pkg_install_or_accept "$pkg" "$pkg" "phase3"
  done

  phase_done "phase3"
  printf '%s\n' "$RESOLVED_VERSION_PKGS" > "$_STATE_RESOLVED"
  ok "Resolved package list persisted for resume."
fi

# =============================================================================
# PHASE 4: Install Unflavored Packages
# =============================================================================
if phase_completed "phase4"; then
  warn "Phase 4 already complete -- skipping."
else
  print_header "Phase 4: Install Unflavored Packages"

  _refresh_pkg_cache
  for pkg in $UNFLAVORED_PKGS; do
    info "Installing: $pkg"
    _pkg_install_or_accept "$pkg" "$pkg" "phase4" "-z"
  done

  phase_done "phase4"
fi

# =============================================================================
# PHASE 5: Install Custom Local Packages
# =============================================================================
# Custom packages are pinned local builds not available on the mirror.
# Unlike mirror packages, there is no index to resolve versions from --
# the version is encoded in the filename itself (e.g. e2guardian-5.3.5.tgz).
#
# This phase does NOT use a checkpoint skip. Instead each package is checked
# individually against the installed package database. This means:
#   - Fresh install: nothing present, pkg_add installs from local .tgz
#   - Re-run, same version: already installed, skipped with no pkg_add call
#   - Re-run, updated .tgz: version differs, pkg_add installs the new build
#
# The phase_done checkpoint is intentionally removed so that updating a
# custom .tgz and re-running the installer picks up the change automatically.
# =============================================================================
if phase_completed "phase5"; then
  warn "Phase 5 already complete -- skipping."
else
  print_header "Phase 5: Install Custom Local Packages"

  # Refresh cache so we see the current state after phases 2, 3, 4
  refresh_pkg_cache

  for _pkg in $CUSTOM_PKGS; do
    # Derive display name and exact version from filename
    # e.g. e2guardian-5.3.5.tgz -> NAME=e2guardian-5.3.5, stem=e2guardian, ver=5.3.5
    _cpkg_name=$(printf '%s' "$_pkg" | sed 's/\.tgz$//')
    _cpkg_stem=$(printf '%s' "$_cpkg_name" | sed -E 's/-[0-9][^ ]*$//')
    _cpkg_ver=$(printf '%s' "$_cpkg_name" | sed -nE 's/.*-([0-9][^ ]*)/\1/p')

    # Check cache for exact stem-version match
    _cpkg_installed=$(printf '%s\n' "$_PKG_INFO_CACHE" \
      | awk -v s="$_cpkg_stem" 'BEGIN{q="^"s"-[0-9]"} $0 ~ q {print; exit}')

    if [ -n "$_cpkg_installed" ]; then
      _cpkg_inst_ver=$(printf '%s' "$_cpkg_installed" \
        | sed -nE 's/.*-([0-9][^ ]*)/\1/p')
      if [ "$_cpkg_inst_ver" = "$_cpkg_ver" ]; then
        ok "$_cpkg_stem: installed $_cpkg_inst_ver matches payload -- skipping."
        record_pkg "$_cpkg_name"
        continue
      fi
      # Version mismatch -- installed version differs from payload.
      # This covers both upgrade (payload newer) and rollback (payload older).
      info "$_cpkg_stem: installed $_cpkg_inst_ver, payload $_cpkg_ver -- installing."
    fi

    while true; do
      pkg_run "$_cpkg_name" pkg_add -D unsigned -Iv "$PKG_DIR_ARCH/$_pkg" && {
        ok "$_cpkg_name installed."
        record_pkg "$_cpkg_name"
        break
      } || {
        phase_error "phase5" "$_cpkg_name failed" || continue
        break
      }
    done
  done

  phase_done "phase5"
fi

# =============================================================================
# PHASE 6: Verify Installation
# =============================================================================
if phase_completed "phase6"; then
  warn "Phase 6 already complete -- skipping."
else
  print_header "Phase 6: Verify Installation"
  PKG_ERR_COUNT=0

  # =========================================================================
  # SANITIZATION GATE: Clean all list variables before running any logic
  # =========================================================================
  # This converts 'unzip--' to 'unzip' while leaving 'smtp-gated' perfectly intact.

  CLEAN_MIRROR_PKGS=""
  for _p in $MIRROR_PKGS; do
    CLEAN_MIRROR_PKGS="$CLEAN_MIRROR_PKGS ${_p%%--}"
  done

  CLEAN_RESOLVED_PKGS=""
  for _p in $RESOLVED_VERSION_PKGS; do
    CLEAN_RESOLVED_PKGS="$CLEAN_RESOLVED_PKGS ${_p%%--}"
  done

  CLEAN_UNFLAVORED_PKGS=""
  for _p in $UNFLAVORED_PKGS; do
    CLEAN_UNFLAVORED_PKGS="$CLEAN_UNFLAVORED_PKGS ${_p%%--}"
  done

  CLEAN_CUSTOM_PKGS=""
  for _p in $CUSTOM_PKGS; do
    CLEAN_CUSTOM_PKGS="$CLEAN_CUSTOM_PKGS ${_p%%--}"
  done
  # =========================================================================

  # Cleaned standard helper function
  _verify_stem() {
    local _s="$1" _i
    _i=$(pkg_info -a 2> /dev/null | awk -v s="$_s" '$1 ~ "^" s "-[0-9]" {print $1; exit}')
    if [ -n "$_i" ]; then
      ok "Found: $_i"
    else
      err "Missing: $_s"
      PKG_ERR_COUNT=$((PKG_ERR_COUNT + 1))
    fi
  }

  print_section "Mirror packages"
  for stem in $CLEAN_MIRROR_PKGS; do
    _verify_stem "$stem"
  done

  print_section "Version-resolved packages"
  for pkg in $CLEAN_RESOLVED_PKGS; do
    _vstem=$(echo "$pkg" | sed -E 's/-[0-9].*//')
    _i=$(pkg_info -a 2> /dev/null | awk -v s="$_vstem" '$1 ~ "^" s "-[0-9]" {print $1; exit}')
    if [ -n "$_i" ]; then
      ok "Found: $_i (from $pkg)"
    else
      err "Missing: $pkg"
      PKG_ERR_COUNT=$((PKG_ERR_COUNT + 1))
    fi
  done

  print_section "Unflavored packages"
  for stem in $CLEAN_UNFLAVORED_PKGS; do
    if pkg_info -I "$stem" | grep -q "^${stem}-"; then
      ok "Found: $stem"
    else
      err "Missing: $stem"
      PKG_ERR_COUNT=$((PKG_ERR_COUNT + 1))
    fi
  done

  print_section "Custom packages"
  for pkg in $CLEAN_CUSTOM_PKGS; do
    STEM=$(echo "$pkg" | sed -E 's/-[0-9].*//; s/\.tgz//')
    _verify_stem "$STEM"
  done

  if [ "$PKG_ERR_COUNT" -gt 0 ]; then
    while true; do
      phase_error "phase6" "$PKG_ERR_COUNT package(s) missing" || continue
      break
    done
  else
    ok "All packages verified."
    printf '%d\n' "$PKG_ERR_COUNT" > "$_STATE_PKG_ERR"
    phase_done "phase6"
  fi
fi

# =============================================================================
# PHASE 7: Bootstrap Infrastructure
# =============================================================================
if phase_completed "phase7"; then
  warn "Phase 7 already complete -- skipping."
else
  print_header "Phase 7: Bootstrap Infrastructure"

  # --- MFS AND DIRECTORY SETUP FOR PMACCT ---
  # Using established BASE variable from line 618
  print_section "Configuring MFS and PMACCT Infrastructure"

  # 1. Create the physical mount points and storage dirs using $BASE
  mkdir -p "$BASE/logs/pf"
  mkdir -p "$BASE/pipes/pmacct"
  mkdir -p "$BASE/network/pmacct/ext"

  # 2. Add MFS entries to /etc/fstab if they aren't there
  grep -q "$BASE/logs/pf" /etc/fstab \
    || echo "swap $BASE/logs/pf mfs rw,nodev,nosuid,noexec,-s=262144 0 0" >> /etc/fstab

  grep -q "$BASE/pipes/pmacct" /etc/fstab \
    || echo "swap $BASE/pipes/pmacct mfs rw,nosuid,nodev,noatime,noexec,-s=64m 0 0" >> /etc/fstab

  # 3. Mount them immediately so Phase 9 can use them
  mount "$BASE/logs/pf" 2> /dev/null || true
  mount "$BASE/pipes/pmacct" 2> /dev/null || true

  # 4. Set Permissions (root:www 775)
  chown -R root:www "$BASE/network/pmacct"
  chown -R root:www "$BASE/pipes/pmacct"
  chmod -R 775 "$BASE/network/pmacct"
  chmod -R 775 "$BASE/pipes/pmacct"

  # 5. Initialize the log files for the smoke test
  touch "$BASE/pipes/pmacct/ext_if_json.log"
  touch "$BASE/pipes/pmacct/int_if_json.log"
  chown root:www "$BASE/pipes/pmacct/"*.log
  chmod 644 "$BASE/pipes/pmacct/"*.log

  ok "Infrastructure prepared for PMACCT and PFLOG1"

  # -------------------------------------------------------------------------
  # STEP 1: sbin payload
  # -------------------------------------------------------------------------
  chmod -R 0700 "$PAYLOAD_DIR/usr/local/sbin/."
  chown -R root:wheel "$PAYLOAD_DIR/usr/local/sbin/."
  find "$PAYLOAD_DIR/usr/local/sbin" -type f \
    ! -name "*.orig" ! -name "*.stale" | while read -r _f; do
    echo "/usr/local/sbin/$(basename "$_f")"
  done > "$ROLLBACK_DIR/sbin-manifest.txt"
  # find+cpio instead of cp -Rp so *.orig and *.stale are excluded cleanly.
  # cpio -p preserves permissions; -d creates destination dirs as needed.
  (cd "$PAYLOAD_DIR" && find usr/local/sbin -type f \
    ! -name "*.orig" ! -name "*.stale" \
    | cpio -pdu /)
  ok "sbin payload deployed."

  # -------------------------------------------------------------------------
  # STEP 2: unbound.conf
  # resolv.conf is committed after Phase 9 once unbound is confirmed running.
  # Writing it here would break network operations between Phase 7 and Phase 9.
  # -------------------------------------------------------------------------
  print_section "Deploying unbound.conf"
  cp -p "$PAYLOAD_DIR/var/unbound/etc/unbound.conf" /var/unbound/etc/
  ok "unbound.conf deployed."

  # -------------------------------------------------------------------------
  # STEP 3[a]: etc/ and usr/local/etc direct deployment
  # Patch payload/etc/collectd.conf with live hardware values before the
  # find loop deploys it -- this ensures the backup of the existing
  # /etc/collectd.conf happens as part of the normal deploy flow.
  # -------------------------------------------------------------------------
  print_header "Deploying Configuration Files"
  _NET_BACKUP="${TNDIR}/net-backup"
  mkdir -p "$ROLLBACK_DIR/etc"
  mkdir -p "$_NET_BACKUP"

  if [ -f /etc/rc ] && [ ! -f "${_NET_BACKUP}/rc" ]; then
    cp -p /etc/rc "${_NET_BACKUP}/rc"
    ok "Pre-deploy backup: /etc/rc -> ${_NET_BACKUP}/rc"
  fi

  _collectd_conf_patch() {
    local _conf="${PAYLOAD_DIR}/etc/collectd.conf"
    [ -f "$_conf" ] || {
      warn "collectd.conf not in payload -- skipping patch"
      return 0
    }

    # Root partition from mount -- /dev/sd0a on /
    _root_part=$(mount 2> /dev/null \
      | awk '$3 == "/" {print $1}' \
      | sed 's|/dev/||')
    _root_disk=$(printf '%s' "$_root_part" | sed 's/[a-z]$//')

    # Fallback to first physical disk from hw.disknames
    if [ -z "$_root_disk" ]; then
      _raw=$(sysctl -n hw.disknames 2> /dev/null || true)
      for _entry in $(printf '%s\n' "$_raw" | tr ',' ' '); do
        _dev="${_entry%%:*}"
        case "$_dev" in cd* | fd* | ram* | vnd*) continue ;; esac
        _root_disk="$_dev"
        _root_part="${_dev}a"
        break
      done
      warn "Root partition not found via mount -- falling back to: ${_root_part}"
    fi

    [ -z "$_root_disk" ] \
      && {
        err "Cannot determine root disk -- collectd.conf not patched"
        return 1
      }

    _cc_tmp=$(mktemp)
    sed \
      -e "s|Disk \"sd[0-9]*\"|Disk \"${_root_disk}\"|g" \
      -e "s|Device \"/dev/sd[0-9][a-z]\"|Device \"/dev/${_root_part}\"|g" \
      "$_conf" > "$_cc_tmp"
    mv "$_cc_tmp" "$_conf"

    ok "payload collectd.conf: Disk      -> ${_root_disk}"
    ok "payload collectd.conf: df Device -> /dev/${_root_part}"
  }
  _collectd_conf_patch

  # -------------------------------------------------------------------------
  # STEP 3[a-ii]: Patch collectd_exporter.pl with live hardware values.
  #
  # Three classes of stale token in the payload file:
  #
  #   1. ping-          -- gateway IP token never substituted.
  #      ping_droprate-   EXT_GW4 from tn-interfaces supplies the real value.
  #      ping_stddev-
  #
  #   2. disk-sd1       -- hardcoded disk device assumption.
  #      swap-dev_sd1b    Same root disk detection used by _collectd_conf_patch
  #                       above is reused here for consistency.
  #
  #   3. %%EXT_IF%%     -- interface tokens: already handled by TN_SUBSTITUTE.sh
  #      %%INT_IF%%       but we verify they are clean and warn if not.
  #
  # The payload file is patched IN PLACE before the find+cpio deploy loop
  # copies it to /usr/local/sbin/ -- same pattern as _collectd_conf_patch.
  # -------------------------------------------------------------------------
  _collectd_exporter_patch() {
    local _exp="${PAYLOAD_DIR}/usr/local/sbin/collectd_exporter.pl"
    [ -f "$_exp" ] || {
      warn "collectd_exporter.pl not in payload -- skipping patch"
      return 0
    }

    # --- Gateway IP from tn-interfaces (already dot-sourced above) ---
    local _gw="${EXT_GW4:-}"
    if [ -z "$_gw" ]; then
      err "EXT_GW4 is unset -- cannot patch ping targets in collectd_exporter.pl"
      return 1
    fi

    # --- Root disk: reuse the same detection as _collectd_conf_patch ---
    local _root_disk
    _root_disk=$(mount 2>/dev/null \
      | awk '$3 == "/" {print $1}' \
      | sed 's|/dev/||; s|[a-z]$||')

    if [ -z "$_root_disk" ]; then
      local _raw
      _raw=$(sysctl -n hw.disknames 2>/dev/null || true)
      for _entry in $(printf '%s\n' "$_raw" | tr ',' ' '); do
        local _dev="${_entry%%:*}"
        case "$_dev" in cd* | fd* | ram* | vnd*) continue ;; esac
        _root_disk="$_dev"
        break
      done
      [ -n "$_root_disk" ] \
        && warn "collectd_exporter.pl: root disk via fallback: ${_root_disk}" \
        || { err "Cannot determine root disk -- collectd_exporter.pl disk not patched"; return 1; }
    fi

    local _swap_dev="${_root_disk}b"
    local _tmp
    _tmp=$(mktemp /tmp/tn_exp_patch.XXXXXX)

    sed \
      -e "s|\"\$HOST/ping/ping-\"|\"${HOST:-tangent}/ping/ping-${_gw}\"|g" \
      -e "s|\"\$HOST/ping/ping_droprate-\"|\"${HOST:-tangent}/ping/ping_droprate-${_gw}\"|g" \
      -e "s|\"\$HOST/ping/ping_stddev-\"|\"${HOST:-tangent}/ping/ping_stddev-${_gw}\"|g" \
      -e "s|disk-sd[0-9]*/disk_octets|disk-${_root_disk}/disk_octets|g" \
      -e "s|swap-dev_sd[0-9]*b/swap|swap-dev_${_swap_dev}/swap|g" \
      "$_exp" > "$_tmp" && mv "$_tmp" "$_exp" || {
        rm -f "$_tmp"
        err "collectd_exporter.pl patch failed"
        return 1
      }

    # Verify no bare ping- tokens remain
    if grep -qE '"[^"]*ping[^"]*-"[[:space:]]*,' "$_exp"; then
      warn "collectd_exporter.pl: bare ping token may remain -- check manually"
    fi

    # Warn if interface tokens were not substituted by TN_SUBSTITUTE.sh
    if grep -q '%%EXT_IF%%\|%%INT_IF%%' "$_exp"; then
      err "collectd_exporter.pl: %%EXT_IF%% or %%INT_IF%% not substituted -- run TN_SUBSTITUTE.sh first"
      return 1
    fi

    ok "collectd_exporter.pl: ping gateway -> ${_gw}"
    ok "collectd_exporter.pl: disk         -> ${_root_disk}"
    ok "collectd_exporter.pl: swap device  -> ${_swap_dev}"
  }
  _collectd_exporter_patch

  find "$PAYLOAD_DIR/etc" -type f \
    ! -name "fstab" \
    ! -name "sysctl.conf" \
    ! -name "pf.conf" \
    ! -name "httpd.conf" \
    ! -name "syslog.conf" \
    ! -name "newsyslog.conf" \
    ! -name "crontab" \
    ! -name "*.orig" \
    ! -name "*.stale" > /tmp/tn_etc_files.$$

  while IFS= read -r _src; do
    _rel="${_src#$PAYLOAD_DIR}"
    mkdir -p "$(dirname "$_rel")"
    [ -f "$_rel" ] && cp "$_rel" "$ROLLBACK_DIR/etc/$(basename "$_rel").bak" 2> /dev/null || true
    cp "$_src" "$_rel"
    # rc.local must be executable -- OpenBSD rc only sources it if -x
    # cp without -p strips the execute bit so set it explicitly here
    [ "$(basename "$_rel")" = "rc.local" ] && chmod +x "$_rel"
    ok "Deployed: $_rel"
  done < /tmp/tn_etc_files.$$
  rm -f /tmp/tn_etc_files.$$

  # -------------------------------------------------------------------------
  # STEP 3[b]: usr/local/etc/ direct deploys
  # -------------------------------------------------------------------------
  _USR_ETC_SRC="$PAYLOAD_DIR/usr/local/etc"

  if [ -d "$_USR_ETC_SRC" ]; then
    print_header "Deploying /usr/local/etc Configuration Files"
    find "$_USR_ETC_SRC" -type f ! -name "*.orig" ! -name "*.stale" > /tmp/tn_usr_etc_files.$$
    while IFS= read -r _src; do
      _rel="${_src#$PAYLOAD_DIR}"
      mkdir -p "$(dirname "$_rel")"
      if [ -f "$_rel" ]; then
        mkdir -p "$ROLLBACK_DIR/usr_local_etc"
        cp "$_rel" "$ROLLBACK_DIR/usr_local_etc/$(basename "$_rel").bak" 2> /dev/null
      fi
      cp "$_src" "$_rel"
      ok "Deployed: $_rel"
    done < /tmp/tn_usr_etc_files.$$
    rm -f /tmp/tn_usr_etc_files.$$

    # SSLproxy CA key must be 600 -- cp without -p resets permissions.
    # Placed here after all deploys so nothing can clobber it afterward.
    if [ -f /usr/local/etc/sslproxy/ca.key ]; then
      chmod 600 /usr/local/etc/sslproxy/ca.key
      chown root:wheel /usr/local/etc/sslproxy/ca.key
      ok "/usr/local/etc/sslproxy/ca.key set to 600 root:wheel"
    fi
  else
    info "Skipping /usr/local/etc: Source directory not found in payload."
  fi

  # If /etc/doas.conf is absent, the installer copies the default configuration from
  # /etc/examples/doas.conf. Doas command logging is also enabled, allowing future
  # privilege-escalation events to be recorded and reviewed.
  if [ ! -f /etc/doas.conf ]; then
      info "/etc/doas.conf not found. Copying example configuration..."
      cp /etc/examples/doas.conf /etc/

      # Optional: Secure the file permissions right away
      chmod 0600 /etc/doas.conf
  else
      ok "/etc/doas.conf already exists. No action taken."
  fi

  # -------------------------------------------------------------------------
  # STEP 4: Webroot deploy
  # -------------------------------------------------------------------------
  print_header "Deploying WEBROOT"
  # find+cpio instead of cp -R so *.orig and *.stale are excluded cleanly.
  # cpio -p preserves permissions; -d creates destination dirs as needed.
  (cd "$PAYLOAD_DIR" && find var/www -type f \
    ! -name "*.orig" ! -name "*.stale" \
    | cpio -pdu /)

  chown -R www:www /var/www/htdocs/tn
  find /var/www/htdocs/tn -type d -exec chmod 755 {} +
  find /var/www/htdocs/tn -type f -exec chmod 644 {} +
  find /var/www/htdocs/tn -type f \( \
    -name "*.png" -o -name "*.ico" -o -name "*.jpg" \
    -o -name "*.js" -o -name "*.css" \
    -o -name "*.woff" -o -name "*.woff2" \
    -o -name "*.html" -o -name "*.json" \
    \) -exec chmod 644 {} +
  find /var/www/htdocs/tn/cgi-bin -type f -name "*.pl" -exec chmod 750 {} +
  find /var/www/htdocs/tn/cgi-bin -type d -exec chmod 750 {} +

  touch "$ROLLBACK_DIR/webroot-deployed"
  ok "WEBROOT deployed."

  # -------------------------------------------------------------------------
  # STEP 5: Set service account supplementary groups.
  # Must happen BEFORE the broad chown/find sweep and BEFORE setup_dir/
  # setup_file so that all ownership and group membership is consistent
  # from the moment files are created. usermod -G on OpenBSD SETS (not
  # appends) the supplementary list -- call once per user here only.
  # -------------------------------------------------------------------------
  print_section "Setting service account group memberships"
  for _user in _snort _e2guardian _clamav _collectd _p3scan; do
    if id "$_user" > /dev/null 2>&1; then
      usermod -G www "$_user"
      ok "  $_user: supplementary group www set"
    else
      warn "  $_user: user not found -- skipping usermod"
    fi
  done

  # -------------------------------------------------------------------------
  # STEP 6: Broad webroot ownership/permission reset.
  # Runs after webroot deploy and after usermod, before setup_dir/setup_file.
  # setup_dir/setup_file below will override specific paths as needed --
  # this sweep just establishes a safe baseline.
  # -------------------------------------------------------------------------
  chown -R www:www /var/www/htdocs/tn
  find /var/www/htdocs/tn -type d -exec chmod 755 {} +
  find /var/www/htdocs/tn -type f -exec chmod 644 {} +
  find /var/www/htdocs/tn/cgi-bin -type f -name "*.pl" -exec chmod 750 {} +
  find /var/www/htdocs/tn/cgi-bin -type d -exec chmod 750 {} +
  ok "Broad webroot ownership/permissions reset (baseline)."

  # -------------------------------------------------------------------------
  # STEP 7: run/ directories -- specific owners/modes override the baseline.
  # -------------------------------------------------------------------------
  print_section "run/ directories"
  setup_dir "$BASE/run" www www 755
  setup_dir "$BASE/rrd" _collectd www 755
  setup_dir "$BASE/sockets" _collectd www 755
  setup_dir "$BASE/sockets/collectd" _collectd www 755
  setup_dir "$BASE/services" www www 755
  setup_dir "$BASE/services/queue" www www 755
  setup_dir "$BASE/services/queue/background" www www 755
  setup_dir "$BASE/services/queue/e2gfilters" www www 755
  setup_dir "$BASE/services/queue/e2gfilters/outcome" www www 755
  setup_dir "$BASE/services/queue/e2gfilters/request" www www 755
  setup_dir "$BASE/services/queue/outcome" www www 755
  setup_dir "$BASE/services/queue/pf-rules" www www 755
  setup_dir "$BASE/services/queue/request" www www 755
  setup_dir "$BASE/services/queue/unbound" www www 755
  setup_dir "$BASE/services/queue/unbound/outcome" www www 755
  setup_dir "$BASE/services/queue/unbound/request" www www 755
  setup_dir "$BASE/services/queue/request" www www 755
  setup_dir "$BASE/queue" www www 2770
  setup_dir "$BASE/queue/reuest" www www 755
  setup_dir "$BASE/queue/outcome" www www 755
  setup_dir "$BASE/run/clamav" _clamav _clamav 755
  setup_dir "$BASE/run/collectd" _collectd www 755
  setup_dir "$BASE/run/e2guardian" _e2guardian www 755
  setup_dir "$BASE/run/p3scan" _p3scan wheel 755
  setup_dir "$BASE/run/pmacct" root www 755
  # NOTE: session dir must be 750 (not 755) -- session keys live here.
  # Phase 8 _authdb_dir also sets this to 750; match it here to avoid
  # any window where the mode is wrong.
  setup_dir "$BASE/run/session" root www 750
  setup_dir "$BASE/run/smtp-gated" _smtp-gated www 755
  setup_dir "$BASE/run/snort" _snort www 2755
  setup_dir "$BASE/run/snortsentry" root www 755
  setup_dir "$BASE/run/sockd" _sockd www 755
  setup_dir "$BASE/run/spamd" _spamd www 755
  setup_dir "$BASE/run/sslproxy" _sslproxy www 755
  setup_dir "$BASE/run/webui" www www 750

  setup_file "$BASE/run/e2guardian/blockedflash.swf" _e2guardian _e2guardian 644
  setup_file "$BASE/run/e2guardian/e2guardian.pid" _e2guardian _e2guardian 644
  setup_file "$BASE/run/e2guardian/transparent1x1.gif" _e2guardian _e2guardian 644
  setup_file "$BASE/run/session/hmac.key" root www 440
  setup_file "$BASE/run/session/session.key" root www 440
  setup_file "$BASE/run/smtp-gated/smtp-gated.pid" _smtp-gated www 644

  setup_dir "$BASE/archive" root www 755

  # -------------------------------------------------------------------------
  # STEP 8: tmp/ directories
  # -------------------------------------------------------------------------
  print_section "tmp/ directories"
  setup_dir "$BASE/tmp" www www 755
  setup_dir "$BASE/tmp/clamav" _clamav wheel 755
  setup_dir "$BASE/tmp/collectd" _collectd www 755
  setup_dir "$BASE/tmp/collectd/fifo" _collectd www 755
  setup_dir "$BASE/tmp/e2guardian" _e2guardian _clamav 755

  # -------------------------------------------------------------------------
  # STEP 9: pipes/
  # -------------------------------------------------------------------------
  setup_dir "$BASE/pipes/pmacct" root www 2755
  ok "pmacct pipe: setgid www applied."

  # -------------------------------------------------------------------------
  # STEP 10: logs/ -- 775 where service user AND www both need to write
  # -------------------------------------------------------------------------
  print_section "Log directories and seed files"
  LOGBASE="$BASE/logs"
  setup_dir "$LOGBASE" www www 755
  setup_dir "$LOGBASE/cron" root wheel 755
  setup_dir "$LOGBASE/pf" root wheel 755
  setup_dir "$LOGBASE/snort" _snort www 3775
  setup_dir "$LOGBASE/ftp-proxy" _ftp_proxy www 755
  setup_dir "$LOGBASE/imspector" _imspector www 755
  setup_dir "$LOGBASE/pmacct" root www 755
  setup_dir "$LOGBASE/httpd" www www 755
  setup_dir "$LOGBASE/e2guardian" _e2guardian www 775
  setup_dir "$LOGBASE/snortsentry" root www 755
  setup_dir "$LOGBASE/spamd" _spamd www 755
  setup_dir "$LOGBASE/smtp-gated" _smtp-gated www 755
  setup_dir "$LOGBASE/p3scan" _p3scan www 755
  setup_dir "$LOGBASE/sockd" _sockd www 755
  setup_dir "$LOGBASE/sslproxy" _sslproxy www 755
  setup_dir "$LOGBASE/collectd" _collectd www 755
  setup_dir "$LOGBASE/rad" _rad www 755
  setup_dir "$LOGBASE/unbound" _unbound www 755
  setup_dir "$LOGBASE/dhcpd" _dhcp www 755
  setup_dir "$LOGBASE/system" root wheel 755
  setup_dir "$LOGBASE/waf" www www 755
  setup_dir "$LOGBASE/bootlog" root wheel 755
  setup_dir "$LOGBASE/doas" www www 750
  setup_dir "$LOGBASE/csp" www www 755
  setup_dir "$LOGBASE/rotation" www www 755
  setup_dir "$LOGBASE/rotation/logarchiver" www www 750
  setup_dir "$LOGBASE/rotation/dhcpd" www www 755
  setup_dir "$LOGBASE/freshclam" _clamav _clamav 755
  setup_dir "$LOGBASE/clamd" _clamav _clamav 755

  setup_file "$LOGBASE/.rotation_meta" root www 644
  setup_file "$LOGBASE/security.log" www www 644
  setup_file "$LOGBASE/control.log" www www 644
  setup_file "$LOGBASE/e2g_whitelist.log" root www 644
  setup_file "$LOGBASE/pf/pflog1.log" www wheel 644
  setup_file "$LOGBASE/snort/snort.log" _snort www 644
  setup_file "$LOGBASE/snort/snortinline.log" _snort www 644
  setup_file "$LOGBASE/snort/oinkmaster.log" _snort www 644
  setup_file "$LOGBASE/snort/alert.log" _snort www 644
  setup_file "$LOGBASE/ftp-proxy/ftp-proxy.log" _ftp_proxy www 644
  setup_file "$LOGBASE/imspector/imspector.log" _imspector www 644
  setup_file "$LOGBASE/pmacct/pmacct.log" root www 644
  setup_file "$LOGBASE/httpd/httpd_access.log" www www 644
  setup_file "$LOGBASE/httpd/httpd_error.log" www www 644
  setup_file "$LOGBASE/e2guardian/e2guardian.log" _e2guardian www 664
  setup_file "$LOGBASE/e2guardian/access.log" _e2guardian www 664
  setup_file "$LOGBASE/snortsentry/snortsentry.log" root www 644
  setup_file "$LOGBASE/spamd/spamd.log" _spamd www 644
  setup_file "$LOGBASE/smtp-gated/smtp-gated.log" _smtp-gated www 644
  setup_file "$LOGBASE/p3scan/p3scan.log" _p3scan www 644
  setup_file "$LOGBASE/sockd/sockd.log" _sockd www 644
  setup_file "$LOGBASE/sslproxy/sslproxy.log" _sslproxy www 644
  setup_file "$LOGBASE/sslproxy/sslproxy_connect.log" _sslproxy www 644
  setup_file "$LOGBASE/collectd/exporter.log" root www 644
  setup_file "$LOGBASE/collectd/collectd.log" _collectd www 644
  setup_file "$LOGBASE/rad/rad.log" _rad www 644
  setup_file "$LOGBASE/unbound/unbound.log" _unbound www 644
  setup_file "$LOGBASE/dhcpd/dhcpd.log" _dhcp www 644
  setup_file "$LOGBASE/dhcpd/dhcpd_watcher.mtime" root www 644
  setup_file "$LOGBASE/dhcpd/dhcpd_watcher.state" root www 644
  setup_file "$LOGBASE/system/daemon" root wheel 644
  setup_file "$LOGBASE/system/messages" root wheel 644
  setup_file "$LOGBASE/system/queue_processor.log" root www 644
  setup_file "$LOGBASE/waf/access.log" www www 644
  setup_file "$LOGBASE/waf/error.log" www www 644
  setup_file "$LOGBASE/waf/security.log" www www 644
  setup_file "$LOGBASE/bootlog/services.json" www www 644
  setup_file "$LOGBASE/bootlog/services.log" root wheel 644
  setup_file "$LOGBASE/bootlog/rc.local.log" www www 644
  setup_file "$LOGBASE/bootlog/.rotation_stamp" www www 644
  setup_file "$LOGBASE/bootlog/ipv6-route-check.log" root wheel 644
  setup_file "$LOGBASE/doas/doas.log" www www 644
  setup_file "$LOGBASE/csp/security.log" www www 644
  setup_file "$LOGBASE/rotation/monitor.log" www www 644
  setup_file "$LOGBASE/rotation/newsyslog_rename.log" www www 644
  setup_file "$LOGBASE/rotation/cleanup.log" root www 644
  setup_file "$LOGBASE/rotation/logarchiver/rotation.log" www www 760
  setup_file "$LOGBASE/freshclam/freshclam.log" _clamav _clamav 640
  setup_file "$LOGBASE/clamd/clamd.log" _clamav _clamav 644

  ok "Log scaffolding complete."

  # -------------------------------------------------------------------------
  # STEP 11: smtp-gated And p3scan spool
  # -------------------------------------------------------------------------
  mkdir -p "$BASE/spool/smtp-gated/msg"
  chown -R _smtp-gated:_clamav "$BASE/spool/smtp-gated"
  chmod -R 775 "$BASE/spool/smtp-gated"
  ok "_smtp-gated spool secured."

  mkdir -p "$BASE/spool/p3scan/notify"
  mkdir -p "$BASE/spool/p3scan/children"
  chown -R _p3scan:_p3scan "$BASE/spool/p3scan"
  chmod -R 775 "$BASE/spool/p3scan"
  ok "_p3scan spool secured."

  install -d -o www -g www -m 755 /var/www/tmp

  setup_dir "$BASE/db" www www 755
  setup_dir "$BASE/db/pf" www www 755
  setup_dir "$BASE/db/e2g" www www 755
  setup_dir "$BASE/db/unbound" www www 755
  setup_dir "$BASE/db/GeoIP" www www 755
  setup_dir "$BASE/keys" www www 755
  setup_dir "$BASE/config" www www 755
  setup_dir "$BASE/rrd" _collectd www 755

  ok "Infrastructure governance complete."

  # -------------------------------------------------------------------------
  # STEP 12: Traversal assertion.
  # Verify that service accounts can traverse the data directory chain.
  # This catches any accidental mode regression from the steps above.
  # -------------------------------------------------------------------------
  print_section "Traversal assertion"
  for _tdir in \
    /var/www/htdocs/tn \
    /var/www/htdocs/tn/data \
    /var/www/htdocs/tn/data/logs \
    /var/www/htdocs/tn/data/logs/e2guardian; do
    _m=$(stat -f "%Lp" "$_tdir")
    case "$_m" in
      *5 | *7) ok "Traversal ok: $_tdir ($_m)" ;;
      *)
        err "No world-execute on $_tdir ($_m) -- service accounts cannot traverse"
        while true; do
          phase_error "phase7" "traversal check failed: $_tdir" || continue
          break
        done
        ;;
    esac
  done

  # -------------------------------------------------------------------------
  # STEP 13: Config merges
  # -------------------------------------------------------------------------

  # merge_sysctl
  _merge_sysctl() {
    print_header "Tuning System Kernel (sysctl.conf)"
    local _src="$PAYLOAD_DIR/etc/sysctl.conf" _dst="/etc/sysctl.conf"
    cp "$_dst" "$ROLLBACK_DIR/etc/sysctl.conf" 2> /dev/null || true
    while IFS= read -r _line; do
      case "$_line" in "#"* | "") continue ;; esac
      local _key
      _key=$(printf '%s' "$_line" | cut -d= -f1)
      if grep -q "^${_key}" "$_dst"; then
        sed -i "s|^${_key}.*|${_line}|" "$_dst"
      else
        echo "$_line" >> "$_dst"
      fi
    done < "$_src"
    sysctl -f "$_dst" > /dev/null
    ok "sysctl.conf synchronised and applied."
  }

  # merge_logging
  _merge_logging() {
    local _f _src _dst _tmp
    for _f in syslog.conf newsyslog.conf; do
      print_header "Merging $_f"
      _src="$PAYLOAD_DIR/etc/$_f"
      _dst="/etc/$_f"
      cp "$_dst" "$ROLLBACK_DIR/etc/$_f" 2> /dev/null || true
      _tmp=$(mktemp /tmp/tn_merge.XXXXXX)
      cat "$_src" > "$_tmp"
      echo "" >> "$_tmp"
      while IFS= read -r _line; do
        case "$_line" in "#"* | "") continue ;; esac
        local _key
        _key=$(printf '%s' "$_line" | awk '{print $1}')
        grep -qF "$_key" "$_src" || echo "$_line" >> "$_tmp"
      done < "$_dst"
      cp "$_tmp" "$_dst"
      rm -f "$_tmp"
      ok "$_f merged."
    done
    if pgrep -x syslogd > /dev/null 2>&1; then
      run_optional pkill -HUP syslogd
      ok "syslogd reloaded."
    else
      info "syslogd not running -- will pick up config on start."
    fi
  }

  # merge_httpd
  #
  # DESIGN: httpd.conf is generated entirely from scratch using printf --
  # no heredoc, no payload template file, no external token substitution
  # script. All values are sourced directly from /etc/tn-interfaces (already
  # dot-sourced above). This eliminates BOM injection, heredoc quoting bugs,
  # and the "unresolved %% tokens" class of failure completely.
  #
  # CRITICAL: listen on lines are written with individual printf calls
  # directly to the output file. They must NEVER be stored in shell variables
  # via $(...) first -- command substitution strips trailing newlines, causing
  # multiple listen lines to collapse onto one line and triggering httpd's
  # "tls options without tls listener" error.
  #
  # EXISTING CONF STRATEGY:
  #   1. If /etc/httpd.conf exists, mv it to /etc/httpd.conf-Stale and
  #      snapshot a copy to ROLLBACK_DIR. No automatic merge is attempted.
  #   2. Generate our conf and syntax-check it (httpd -n).
  #   3. Deploy it. Print a notice pointing the operator at -Stale if they
  #      had custom server{} blocks to carry forward.
  _merge_httpd() {
    print_header "Generating and deploying httpd.conf"

    local _live="/etc/httpd.conf"
    local _stale="/etc/httpd.conf-Stale"
    local _ours="/tmp/httpd.conf.ours.$$"

    # ------------------------------------------------------------------
    # Resolve TLS paths from tn-interfaces; abort early if absent.
    # These variables are populated by NETWORK_SETUP.sh and validated
    # by the pre-flight _require_var checks above.
    # ------------------------------------------------------------------
    local _tls_cert="${TLS_CERT:-}"
    local _tls_key="${TLS_KEY:-}"
    local _int_ip="${INT_IP4:-}"
    local _ext_ip="${EXT_IP4:-}"
    local _cn="${CERT_CN:-tangentutm.localdomain}"

    if [ -z "$_tls_cert" ] || [ -z "$_tls_key" ]; then
      err "TLS_CERT or TLS_KEY is unset in $TN_INTERFACES -- cannot generate httpd.conf"
      err "  TLS_CERT=${_tls_cert:-<unset>}"
      err "  TLS_KEY=${_tls_key:-<unset>}"
      return 1
    fi
    if [ -z "$_int_ip" ]; then
      err "INT_IP4 is unset in $TN_INTERFACES -- cannot generate httpd.conf"
      return 1
    fi

    info "  CN:       $_cn"
    info "  INT_IP4:  $_int_ip"
    info "  EXT_IP4:  ${_ext_ip:-<not set, WAN listener omitted>}"
    info "  TLS_CERT: $_tls_cert"
    info "  TLS_KEY:  $_tls_key"

    # ------------------------------------------------------------------
    # STEP 1: Move any existing conf aside as -Stale for manual reference.
    # We do NOT attempt to merge -- the operator merges by hand if needed.
    # Also snapshot to ROLLBACK_DIR so the rollback machinery can restore.
    # ------------------------------------------------------------------
    if [ -f "$_live" ]; then
      mkdir -p "$ROLLBACK_DIR/etc"
      cp "$_live" "$ROLLBACK_DIR/etc/httpd.conf"
      mv "$_live" "$_stale"
      ok "Existing httpd.conf moved to: $_stale  (rollback copy in $ROLLBACK_DIR/etc/)"
    fi

    # ------------------------------------------------------------------
    # STEP 2: Generate our canonical httpd.conf using printf only.
    #
    # IMPORTANT: listener lines (listen on ...) are written directly to
    # the file one-by-one with individual printf calls.  They are NEVER
    # stored in shell variables via $(...) first -- command substitution
    # strips trailing newlines, which causes the listener lines to merge
    # onto a single line and makes httpd -n report
    # "tls options without tls listener" for the entire TLS block.
    # ------------------------------------------------------------------

    # Header / comments
    printf '# /etc/httpd.conf\n' > "$_ours"
    printf '# Tangent Networks - HTTPD Configuration\n' >> "$_ours"
    printf '# Generated by TN_PKG_INSTALL.sh on %s\n' "$(date)" >> "$_ours"
    printf '# Source of truth: %s\n' "$TN_INTERFACES" >> "$_ours"
    printf '#\n' >> "$_ours"
    printf '#   CN        : %s\n' "$_cn" >> "$_ours"
    printf '#   INT_IP4   : %s\n' "$_int_ip" >> "$_ours"
    printf '#   EXT_IP4   : %s\n' "${_ext_ip:-<none>}" >> "$_ours"
    printf '#   TLS_CERT  : %s\n' "$_tls_cert" >> "$_ours"
    printf '#   TLS_KEY   : %s\n' "$_tls_key" >> "$_ours"
    printf '\n' >> "$_ours"

    # MIME types
    printf '# =============================================\n' >> "$_ours"
    printf '# Global types definition\n' >> "$_ours"
    printf '# =============================================\n' >> "$_ours"
    printf '\n' >> "$_ours"
    printf 'types {\n' >> "$_ours"
    printf '        include "/usr/share/misc/mime.types"\n' >> "$_ours"
    printf '        application/x-x509-ca-cert          crt pem\n' >> "$_ours"
    printf '        text/css                            css\n' >> "$_ours"
    printf '        text/html                           html htm\n' >> "$_ours"
    printf '        application/javascript              js\n' >> "$_ours"
    printf '        application/json                    json metrics\n' >> "$_ours"
    printf '        text/plain                          txt status\n' >> "$_ours"
    printf '        image/png                           png\n' >> "$_ours"
    printf '        image/jpeg                          jpg jpeg\n' >> "$_ours"
    printf '        image/x-icon                        ico\n' >> "$_ours"
    printf '        image/svg+xml                       svg\n' >> "$_ours"
    printf '}\n' >> "$_ours"
    printf '\n' >> "$_ours"

    # HTTP redirect server -- Generic wildcard port 80 listener
    printf '# =============================================\n' >> "$_ours"
    printf '# HTTP - Redirect all to HTTPS\n' >> "$_ours"
    printf '# =============================================\n' >> "$_ours"
    printf '\n' >> "$_ours"
    printf 'server "default_http" {\n' >> "$_ours"
    printf '    listen on * port 80\n' >> "$_ours"
    printf '\n' >> "$_ours"
    printf '    location "/certs/*" {\n' >> "$_ours"
    printf '        root "/htdocs/tn"\n' >> "$_ours"
    printf '    }\n' >> "$_ours"
    printf '\n' >> "$_ours"
    printf '    location "/*" {\n' >> "$_ours"
    printf '        block return 301 "https://$HTTP_HOST$REQUEST_URI"\n' >> "$_ours"
    printf '    }\n' >> "$_ours"
    printf '}\n' >> "$_ours"

    # HTTPS main server -- Generic wildcard TLS port 443 listener
    printf '# =============================================\n' >> "$_ours"
    printf '# HTTPS - All traffic via router.pl (TNWAF)\n' >> "$_ours"
    printf '# =============================================\n' >> "$_ours"
    printf '\n' >> "$_ours"
    printf 'server "default_https" {\n' >> "$_ours"
    printf '    listen on * tls port 443\n' >> "$_ours"
    printf '\n' >> "$_ours"
    printf '    tls {\n' >> "$_ours"
    printf '        certificate "%s"\n' "$_tls_cert" >> "$_ours"
    printf '        key "%s"\n' "$_tls_key" >> "$_ours"
    printf '        protocols "tlsv1.2, tlsv1.3"\n' >> "$_ours"
    printf '        ciphers "HIGH:!aNULL"\n' >> "$_ours"
    printf '    }\n' >> "$_ours"
    printf '\n' >> "$_ours"
    printf '    root "/htdocs/tn"\n' >> "$_ours"
    printf '    directory index "index.html"\n' >> "$_ours"
    printf '    log syslog\n' >> "$_ours"
    printf '\n' >> "$_ours"

    # Static locations -- served directly, no FastCGI
    printf '    # Maintenance page -- served directly, no fastcgi\n' >> "$_ours"
    printf '    location "/maintenance.html" {\n' >> "$_ours"
    printf '        root "/htdocs/tn"\n' >> "$_ours"
    printf '    }\n' >> "$_ours"
    printf '\n' >> "$_ours"
    printf '    # CA cert download -- static, no FastCGI\n' >> "$_ours"
    printf '    location "/certs/*" {\n' >> "$_ours"
    printf '        root "/htdocs/tn"\n' >> "$_ours"
    printf '    }\n' >> "$_ours"
    printf '\n' >> "$_ours"

    # PWA required files -- must be pre-auth accessible, bypass router.pl
    # sw.js scope must be served from web root for full-app service worker coverage.
    # manifest.json must be reachable before session exists (Chrome install prompt).
    printf '    # PWA required files -- static, no FastCGI\n' >> "$_ours"
    printf '    location "/sw.js" {\n' >> "$_ours"
    printf '        root "/htdocs/tn"\n' >> "$_ours"
    printf '    }\n' >> "$_ours"
    printf '\n' >> "$_ours"
    printf '    location "/manifest.json" {\n' >> "$_ours"
    printf '        root "/htdocs/tn"\n' >> "$_ours"
    printf '    }\n' >> "$_ours"
    printf '\n' >> "$_ours"

    # Sensitive db subdirs routed through WAF (not hard-blocked)
    printf '    # Route sensitive db subdirs through WAF -- defence in depth\n' >> "$_ours"
    for _waf_loc in \
      "/data/db/GeoIP/*" \
      "/data/db/pf/*" \
      "/data/db/unbound/*" \
      "/data/db/e2g/*"; do
      printf '    location "%s" {\n' "$_waf_loc" >> "$_ours"
      printf '        fastcgi socket "/run/slowcgi.sock"\n' >> "$_ours"
      printf '        request rewrite "/cgi-bin/router.pl"\n' >> "$_ours"
      printf '    }\n' >> "$_ours"
    done
    printf '\n' >> "$_ours"
    printf '    location "/data/db/TNAuditFilesList.json" {\n' >> "$_ours"
    printf '        fastcgi socket "/run/slowcgi.sock"\n' >> "$_ours"
    printf '        request rewrite "/cgi-bin/router.pl"\n' >> "$_ours"
    printf '    }\n' >> "$_ours"
    printf '\n' >> "$_ours"

    # Hard-block paths that must never be served
    printf '    # Hard-block paths that must never be served\n' >> "$_ours"
    for _blk in \
      "/data/db/*" \
      "/data/keys/*" \
      "/data/config/*" \
      "/data/lib/*" \
      "/data/scripts/*" \
      "/data/session/*" \
      "/data/run/*" \
      "/data/queue/*"; do
      printf '    location "%s" {\n        block return 403\n    }\n' "$_blk" >> "$_ours"
    done
    printf '\n' >> "$_ours"

    # Catch-all -- everything through router.pl (TNWAF)
    printf '    # Everything else goes through router.pl (TNWAF)\n' >> "$_ours"
    printf '    location "/*" {\n' >> "$_ours"
    printf '        fastcgi socket "/run/slowcgi.sock"\n' >> "$_ours"
    printf '        request rewrite "/cgi-bin/router.pl"\n' >> "$_ours"
    printf '    }\n' >> "$_ours"
    printf '}\n' >> "$_ours"

    ok "httpd.conf generated ($(wc -l < "$_ours" | tr -d ' ') lines)"

    # ------------------------------------------------------------------
    # STEP 3: Syntax-check, then deploy.
    # ------------------------------------------------------------------
    local _sout _sexit
    _sout=$(httpd -n -f "$_ours" 2>&1) && _sexit=0 || _sexit=$?
    if [ "$_sexit" -ne 0 ]; then
      err "httpd -n FAILED on generated conf (installer bug -- report this):"
      printf '%s\n' "$_sout" | while IFS= read -r _l; do err "  $_l"; done
      err "  Generated conf preserved at: $_ours"
      [ -f "$_stale" ] && warn "  Previous conf still available at: $_stale"
      return 1
    fi

    cp "$_ours" "$_live"
    chmod 644 "$_live"
    rm -f "$_ours"

    ok "httpd.conf deployed and syntax-verified: $_live"
    info "  Serving INT: $_int_ip${_ext_ip:+    EXT: $_ext_ip}"
    if [ -f "$_stale" ]; then
      print_phase_notice \
        "ACTION REQUIRED -- manual merge may be needed" \
        "Your previous httpd.conf is preserved at: $_stale" \
        "Our new conf is live at: $_live" \
        "If you had custom server{} blocks, merge them by hand:" \
        "  diff $_stale $_live" \
        "  vi $_live" \
        "  httpd -n && rcctl reload httpd"
    fi
  }

  # merge_crontab
  #
  # DESIGN: OpenBSD has two separate crontab systems:
  #
  #   /etc/crontab        -- system crontab, read directly by crond.
  #                          FORMAT: min hour day month wday USER command
  #                          (7 fields -- has a user column).
  #                          Managed with cp/cat, NOT with crontab(1).
  #
  #   /var/cron/tabs/root -- per-user root crontab, managed by crontab(1).
  #                          FORMAT: min hour day month wday command
  #                          (6 fields -- NO user column).
  #                          crontab(1) only touches this file.
  #
  # The payload crontab is a SYSTEM crontab (it has a user column: root, www).
  # It must be written to /etc/crontab directly, not via crontab(1).
  #
  # Merge strategy:
  #   1. Back up /etc/crontab.
  #   2. Start with the payload as the authoritative base (it owns all
  #      /usr/local/sbin entries and sets the correct env vars).
  #   3. Append any non-duplicate, non-/usr/local/sbin job entries from the
  #      existing /etc/crontab that are not already covered by the payload.
  #      These are OpenBSD system jobs (newsyslog, daily, weekly, monthly).
  #      We only carry forward actual job lines, never env-var lines --
  #      the payload env block (SHELL, PATH, HOME, MAILTO) is authoritative.
  #   4. Validate: every non-comment, non-blank, non-var line must have >= 7
  #      fields (5 time fields + user field + command).
  #   5. Write atomically to /etc/crontab and reload cron.
  #
  # This avoids all six failure modes from the original implementation:
  #   - Wrong target file (was writing to /var/cron/tabs/root via crontab(1))
  #   - Format mismatch (5-field vs 7-field)
  #   - Bare command line with no time fields (e.g. the stray 'drill' line)
  #   - Duplicate env vars overriding payload settings
  #   - crontab(1) rejecting #~ OpenBSD randomized-time syntax
  #   - sed stripping /usr/local/sbin from the wrong file
  _merge_crontab() {
    print_header "Syncing Appliance Crontab (/etc/crontab)"

    local _src="$PAYLOAD_DIR/etc/crontab" # payload -- authoritative base
    local _dst="/etc/crontab"             # system crontab -- direct write target
    local _out _existing_jobs
    local _lineno _fields _skipped _added

    _out=$(mktemp /tmp/tn_cron_out.XXXXXX)
    _existing_jobs=$(mktemp /tmp/tn_cron_existing.XXXXXX)

    # --- Backup ---
    if [ -f "$_dst" ]; then
      cp "$_dst" "$ROLLBACK_DIR/etc/crontab.bak"
      ok "Backed up: $_dst -> $ROLLBACK_DIR/etc/crontab.bak"
    fi

    # --- Step 1: Validate and write payload as the base ---
    # The payload is authoritative. We validate every job line (>=7 fields)
    # and pass through env-var lines (VAR=val), comments, and blank lines
    # unchanged. Any malformed job line is logged and dropped.
    _lineno=0
    _skipped=0
    while IFS= read -r _line; do
      _lineno=$((_lineno + 1))
      case "$_line" in
        "" | "#"* | *"="*)
          # Blank lines, comments (#, #~), env-var assignments: pass through.
          printf '%s\n' "$_line" >> "$_out"
          continue
          ;;
      esac
      # Job line: must have >= 7 fields (5 time + user + command)
      _fields=$(printf '%s' "$_line" | awk '{print NF}')
      if [ "${_fields:-0}" -lt 7 ]; then
        warn "Payload crontab line $_lineno: only $_fields field(s) -- DROPPED: $_line"
        _skipped=$((_skipped + 1))
      else
        printf '%s\n' "$_line" >> "$_out"
      fi
    done < "$_src"
    [ "$_skipped" -gt 0 ] && warn "$_skipped malformed payload line(s) dropped."

    # --- Step 2: Harvest system job lines from existing /etc/crontab ---
    # Rules for a line to be carried forward from the existing file:
    #   - Must be a job line (not blank, not comment, not env-var)
    #   - Must have >= 7 fields (system /etc/crontab also uses user column)
    #     Exception: OpenBSD default /etc/crontab has 6-field lines (no user).
    #     We accept >= 6 fields and normalise by inserting 'root' as user
    #     when exactly 6 fields are present.
    #   - Must NOT contain /usr/local/sbin (those are owned by the payload)
    #   - Must NOT already appear in the payload output (dedup by command
    #     column: last field of the time+user block, i.e. field 6 onward)
    _added=0
    if [ -f "$_dst" ]; then
      while IFS= read -r _line; do
        case "$_line" in
          "" | "#"* | *"="*) continue ;; # skip blanks, comments, vars
        esac

        # Skip any line that is already owned by the payload
        case "$_line" in
          */usr/local/sbin/*) continue ;;
        esac

        _fields=$(printf '%s' "$_line" | awk '{print NF}')

        # Normalise 6-field OpenBSD system lines (no user col) to 7-field
        # by inserting 'root' as the user field before the command.
        if [ "${_fields:-0}" -eq 6 ]; then
          _line=$(printf '%s' "$_line" | awk '{
            print $1, $2, $3, $4, $5, "root", $6
          }')
          _fields=7
        fi

        # Drop anything that still doesn't have enough fields
        if [ "${_fields:-0}" -lt 7 ]; then
          warn "Existing crontab line skipped (only $_fields fields): $_line"
          continue
        fi

        # Dedup: extract the command portion (fields 6 onward after time+user)
        # and check if it already appears in the payload output.
        _cmd=$(printf '%s' "$_line" | awk '{for(i=7;i<=NF;i++) printf "%s%s",$i,(i<NF?" ":"\n")}')
        if grep -qF "$_cmd" "$_out" 2> /dev/null; then
          info "  Existing job already in payload -- skipped: $_cmd"
          continue
        fi

        printf '%s\n' "$_line" >> "$_existing_jobs"
        _added=$((_added + 1))
      done < "$_dst"
    fi

    # Append preserved existing jobs with a section header
    if [ "$_added" -gt 0 ]; then
      printf '\n# PRESERVED SYSTEM JOBS (from previous /etc/crontab)\n' >> "$_out"
      cat "$_existing_jobs" >> "$_out"
      ok "Preserved $_added existing system crontab job(s)."
    else
      info "No existing system jobs to preserve (all covered by payload or none present)."
    fi

    rm -f "$_existing_jobs"

    # --- Step 3: Final validation of the merged output ---
    # Every non-comment, non-blank, non-var line must have >= 7 fields.
    _lineno=0
    _bad=0
    while IFS= read -r _line; do
      _lineno=$((_lineno + 1))
      case "$_line" in "" | "#"* | *"="*) continue ;; esac
      _fields=$(printf '%s' "$_line" | awk '{print NF}')
      if [ "${_fields:-0}" -lt 7 ]; then
        err "Merged crontab line $_lineno has only $_fields fields: $_line"
        _bad=$((_bad + 1))
      fi
    done < "$_out"

    if [ "$_bad" -gt 0 ]; then
      err "$_bad invalid line(s) in merged crontab. Aborting -- original preserved."
      rm -f "$_out"
      return 1
    fi

    # --- Step 4: Atomic write to /etc/crontab ---
    cp "$_out" "$_dst"
    chmod 600 "$_dst"
    chown root:wheel "$_dst"
    rm -f "$_out"

    # --- Step 5: Signal cron to reload ---
    # On OpenBSD, cron re-reads /etc/crontab automatically on its next
    # minute tick. A SIGHUP makes it reload immediately.
    if pgrep -x cron > /dev/null 2>&1; then
      pkill -HUP cron 2> /dev/null || true
      ok "cron signalled to reload /etc/crontab."
    else
      info "cron not running -- will pick up /etc/crontab on next start."
    fi

    ok "/etc/crontab merged and installed ($(grep -c '' "$_dst") lines)."
  }

  while true; do _merge_sysctl && break || {
    phase_error "phase7" "sysctl merge failed" || continue
    break
  }; done
  while true; do _merge_logging && break || {
    phase_error "phase7" "logging merge failed" || continue
    break
  }; done
  while true; do _merge_httpd && break || {
    phase_error "phase7" "httpd merge failed" || continue
    break
  }; done
  while true; do _merge_crontab && break || {
    phase_error "phase7" "crontab merge failed" || continue
    break
  }; done

  # -------------------------------------------------------------------------
  # STEP 14: Payload tarballs
  # -------------------------------------------------------------------------
  info "Extracting UTM rules and lists..."
  if [ -d /etc/snort ]; then
    tar -xzf "$PAYLOAD_DIR/rules.tar.gz" -C /etc/snort
    ok "Snort rules deployed."
  else
    while true; do
      phase_error "phase7" "/etc/snort missing" || continue
      break
    done
  fi

  # -------------------------------------------------------------------------
  # STEP 14a: Immediate oinkmaster run
  # Fetches current VRT rules right after the bundled snapshot is deployed.
  # local.rules is already on disk from rules.tar.gz and is never touched
  # by oinkmaster. Skipped if RULES_TYPE is not "registered" or oinkmaster
  # is not installed -- smoke tests will run on the bundled snapshot instead.
  # -------------------------------------------------------------------------
  _OINK_SCRIPT="/usr/local/sbin/oinkmaster_update_snortinline.sh"
  _OINK_BIN="/usr/local/bin/oinkmaster"
  if [ "${RULES_TYPE:-}" = "registered" ] && [ -n "${OINK_CODE:-}" ]; then
    if [ ! -x "$_OINK_BIN" ]; then
      warn "oinkmaster not installed -- skipping live rule fetch (smoke tests use bundled snapshot)"
    elif [ ! -x "$_OINK_SCRIPT" ]; then
      warn "$_OINK_SCRIPT not found -- skipping live rule fetch (smoke tests use bundled snapshot)"
    else
      print_phase_notice "Oinkmaster Rule Download" \
        "Downloading the Snort VRT ruleset (~130MB) via wget." \
        "This typically takes 10-20 minutes depending on your connection." \
        "The script is NOT hung -- silence here is normal."
      info "Fetching current VRT rules via oinkmaster..."
      if "$_OINK_SCRIPT" >> "$LOGFILE" 2>&1; then
        ok "VRT rules updated -- system starts with current ruleset"
      else
        warn "oinkmaster fetch failed -- smoke tests will run on bundled snapshot"
        warn "Check $LOGFILE and verify OINK_CODE is valid and snort.org is reachable"
      fi
    fi
  else
    info "RULES_TYPE=${RULES_TYPE:-unset} -- skipping live rule fetch"
  fi
  if [ -d /etc/e2guardian ]; then
    tar -xzf "$PAYLOAD_DIR/lists.tar.gz" -C /etc/e2guardian
    ok "e2guardian lists deployed."
  else
    while true; do
      phase_error "phase7" "/etc/e2guardian missing" || continue
      break
    done
  fi

  # -------------------------------------------------------------------------
  # STEP 14b: e2guardian adult filter list generation
  # Runs e2g_adult_filter.sh to generate lists in-place under /etc/e2guardian.
  # -------------------------------------------------------------------------
  _E2G_FILTER="/usr/local/sbin/e2g_get_intel.sh"
  if [ -d /etc/e2guardian ]; then
    if [ ! -x "$_E2G_FILTER" ]; then
      while true; do
        phase_error "phase7" "$_E2G_FILTER not found or not executable" || continue
        break
      done
    else
      print_phase_notice "e2guardian List Generation" \
        "Building adult filter lists via e2g_get_intel.sh." \
        "This typically takes 15-20 minutes -- script is NOT hung."
      info "Running e2g_get_intel.sh..."
      info "LOGFILE=[${LOGFILE}]"
      info "E2G_EXIT test:"

      # Safely execute with detached stdin to prevent interactive stalls
      /usr/local/sbin/e2g_get_intel.sh < /dev/null > "${LOGFILE}" 2>&1
      _E2G_EXIT_CODE=$?

      info "Script exit was $_E2G_EXIT_CODE"

      if [ "$_E2G_EXIT_CODE" -eq 0 ]; then
        if grep -q "Script completed successfully" /tmp/e2guardian-feed.log 2> /dev/null; then
          ok "e2guardian adult filter lists generated."
        else
          while true; do
            phase_error "phase7" "e2g_get_intel.sh exited 0 but success marker absent in /tmp/e2guardian-feed.log" || continue
            break
          done
        fi
      else
        while true; do
          phase_error "phase7" "e2g_get_intel.sh failed (exit $_E2G_EXIT_CODE)" || continue
          break
        done
      fi
    fi
  else
    while true; do
      phase_error "phase7" "/etc/e2guardian missing" || continue
      break
    done
  fi

  # -------------------------------------------------------------------------
  # FINAL GUARD: /etc/rc.local executable bit
  # cp without -p strips the execute bit. OpenBSD /etc/rc only sources
  # rc.local if it is executable -- a 644 rc.local means nothing starts
  # at boot. This guard fires last in phase 7 after all deploy operations
  # have completed so nothing can clobber it afterward.
  # -------------------------------------------------------------------------
  if [ -f /etc/rc.local ]; then
    _rcl_mode=$(stat -f "%Lp" /etc/rc.local 2> /dev/null || echo "000")
    if [ "$_rcl_mode" != "700" ]; then
      chmod 700 /etc/rc.local
      ok "/etc/rc.local mode was ${_rcl_mode} -- set to 700"
    else
      ok "/etc/rc.local is 700"
    fi
  else
    warn "/etc/rc.local not found after deploy -- boot services will not start"
  fi

  ok "Phase 7 complete."
  phase_done "phase7"
fi

# =============================================================================
# PHASE 8: Initialise AuthDB (inline ksh -- no perl)
# =============================================================================
if phase_completed "phase8"; then
  warn "Phase 8 already complete -- skipping."
else
  print_header "Phase 8: Initialise AuthDB"

  if ! command -v sqlite3 > /dev/null 2>&1; then
    err "sqlite3 not found -- was Phase 2 (mirror packages) completed?"
    exit 1
  fi
  ok "sqlite3: $(command -v sqlite3)"

  _www_uid=$(id -u www 2> /dev/null) || {
    err "User www not found"
    exit 1
  }
  _www_gid=$(id -g www 2> /dev/null) || {
    err "Group www not found"
    exit 1
  }
  info "www uid=$_www_uid gid=$_www_gid"

  _authdb_dir() {
    local _d="$1" _m="$2" _o="$3" _g="$4"
    mkdir -p "$_d"
    chown "$_o:$_g" "$_d"
    chmod "$_m" "$_d"
    info "Dir: $_d ($_m $_o:$_g)"
  }

  APP_ROOT="/var/www/htdocs/tn"
  DATA_DIR="$APP_ROOT/data"
  DB_DIR="$DATA_DIR/db"

  _authdb_dir "$DATA_DIR" 755 www www
  _authdb_dir "$DB_DIR" 750 www www
  _authdb_dir "$KEYS_DIR" 750 root www
  _authdb_dir "$DATA_DIR/config" 750 www www
  _authdb_dir "$DATA_DIR/logs" 755 www www
  _authdb_dir "$DATA_DIR/logs/waf" 755 www www
  _authdb_dir "$DATA_DIR/logs/csp" 755 www www
  _authdb_dir "$DATA_DIR/run" 755 www www
  # run/session: 750 root:www -- consistent with Phase 7 setup_dir above
  _authdb_dir "$DATA_DIR/run/session" 750 root www

  ok "Directory tree established."

  info "Initialising database: $AUTH_DB"
  [ -f "$AUTH_DB" ] && {
    warn "Existing auth.db found -- removing."
    rm -f "$AUTH_DB"
  }

  while true; do
    sqlite3 "$AUTH_DB" < "$SCHEMA" >> "$LOGFILE" 2>&1 && break \
      || {
        phase_error "phase8" "sqlite3 schema apply failed" || continue
        break
      }
  done

  chown root:www "$AUTH_DB"
  chmod 0640 "$AUTH_DB"
  [ -s "$AUTH_DB" ] || {
    err "auth.db is empty after schema apply"
    exit 1
  }
  ok "auth.db created (0640 root:www): $AUTH_DB"

  _gen_key() {
    local _kname="$1" _kpath="$KEYS_DIR/$1" _hex
    [ -f "$_kpath" ] && {
      warn "$_kname exists -- replacing."
      rm -f "$_kpath"
    }
    _hex=$(dd if=/dev/urandom bs=32 count=1 2> /dev/null | od -An -tx1 | tr -d ' \n')
    [ "${#_hex}" -eq 64 ] || {
      err "Key generation failed: ${#_hex} chars"
      exit 1
    }
    printf '%s' "$_hex" > "$_kpath"
    chown root:www "$_kpath"
    chmod 0440 "$_kpath"
    ok "$_kname generated (0440 root:www)"
  }

  _gen_key "session.key"
  _gen_key "hmac.key"

  touch "$ROLLBACK_DIR/authdb-created"

  [ -f "$AUTH_DB" ] && [ -s "$AUTH_DB" ] || {
    err "auth.db missing or empty"
    exit 1
  }
  ok "auth.db present and non-empty."

  for _key in session.key hmac.key; do
    _kpath="$KEYS_DIR/$_key"
    [ -f "$_kpath" ] || {
      err "Key missing: $_kpath"
      exit 1
    }
    [ -s "$_kpath" ] || {
      err "Key empty:   $_kpath"
      exit 1
    }
    _kperm=$(stat -f "%Lp" "$_kpath")
    _kowner=$(stat -f "%Su:%Sg" "$_kpath")
    [ "$_kperm" = "440" ] || {
      err "Key perms wrong: $_kpath ($_kperm)"
      exit 1
    }
    [ "$_kowner" = "root:www" ] || {
      err "Key owner wrong: $_kpath ($_kowner)"
      exit 1
    }
    ok "$_key: 0440 root:www"
  done

  chown -R www:www "$DB_DIR"
  ok "Phase 8 complete -- AuthDB initialised."
  phase_done "phase8"
fi

# =============================================================================
# PHASE 9: Service Smoke Tests
# =============================================================================
if phase_completed "phase9"; then
  warn "Phase 9 already complete -- skipping."
else
  print_header "Phase 9: Service Smoke Tests"

  _DATAROOT="/var/www/htdocs/tn/data"
  _RUNROOT="${_DATAROOT}/run"
  _LOGROOT="${_DATAROOT}/logs"
  SMOKE_RESULTS=""
  SMOKE_ERR_COUNT=0

  _smoke_pass() {
    ok "SMOKE [$1]: $2"
    SMOKE_RESULTS="${SMOKE_RESULTS}${1}:PASS:${2}
"
  }

  _smoke_fail() {
    err "SMOKE [$1]: FAILED -- $2"
    SMOKE_RESULTS="${SMOKE_RESULTS}${1}:FAIL:${2}
"
    SMOKE_ERR_COUNT=$((SMOKE_ERR_COUNT + 1))
  }

  _wait_for_file() {
    local _p="$1" _max="$2" _lbl="$3" _s=0
    while [ "$_s" -lt "$_max" ]; do
      [ -e "$_p" ] && return 0
      sleep 1
      _s=$((_s + 1))
      [ $((_s % 10)) -eq 0 ] && info "  waiting for ${_lbl}... (${_s}/${_max}s)"
    done
    return 1
  }

  _stop_procs() {
    local _pat="$1" _sig="${2:-TERM}" _pids
    _pids=$(pgrep -f "$_pat" 2> /dev/null || true)
    [ -z "$_pids" ] && return 0
    echo "$_pids" | xargs kill -"$_sig" 2> /dev/null || true
    sleep 2
    _pids=$(pgrep -f "$_pat" 2> /dev/null || true)
    [ -n "$_pids" ] && echo "$_pids" | xargs kill -9 2> /dev/null || true
  }

  # rc.d smoke
  _smoke_rcd() {
    local _svc="$1"
    info "Smoke [rc.d]: $_svc"
    case "$_svc" in slowcgi) rcctl set slowcgi flags "-t 600" 2>&1 | tee -a "$LOGFILE" ;; esac

    if [ "$_svc" = "syslogd" ]; then
      rcctl enable syslogd 2>&1 | tee -a "$LOGFILE" || true
      rcctl start syslogd 2>&1 | tee -a "$LOGFILE"
      rcctl check syslogd > /dev/null 2>&1 \
        && _smoke_pass "syslogd" "running (restarted at phase start)" \
        || _smoke_fail "syslogd" "not running after restart"
      return
    fi

    rcctl enable "$_svc" 2>&1 | tee -a "$LOGFILE" || {
      _smoke_fail "$_svc" "rcctl enable failed"
      return
    }
    if ! rcctl check "$_svc" > /dev/null 2>&1; then
      rcctl -f start "$_svc" 2>&1 | tee -a "$LOGFILE" || {
        _smoke_fail "$_svc" "rcctl start failed"
        return
      }
      sleep 2
    fi
    rcctl check "$_svc" > /dev/null 2>&1 || {
      _smoke_fail "$_svc" "rcctl check failed after start"
      return
    }
    local _pid
    _pid=$(pgrep -x "$_svc" 2> /dev/null | head -1 || true)
    _smoke_pass "$_svc" "running PID=${_pid:-unknown}"
  }

  # ===========================================================================
  # PRE-SMOKE TEARDOWN
  # ===========================================================================
  # Stop all services before smoke testing. On a running system (post-upgrade
  # or re-run) old binaries from the previous version may still be in memory.
  # Testing against a running stale daemon:
  #   - Passes the smoke test but validates the OLD binary, not the new one.
  #   - Causes "already running" false failures for single-instance daemons.
  #   - Leaves the system in an inconsistent state (old daemon + new config).
  #
  # Procedure for each service:
  #   1. rcctl stop  -- graceful rc.d stop (SIGTERM + wait)
  #   2. rcctl disable -- prevent rc.d from auto-restarting during the window
  #   3. _stop_procs -- SIGTERM any survivors, SIGKILL after 2s
  #   4. Clean up stale PID files and sockets so new starts aren't blocked
  #
  # rc.d services are re-enabled by _smoke_rcd during the test loop.
  # Local services that are left running (p3scan, smtp-gated, sslproxy,
  # imspector) are intentionally NOT killed here -- they are stopped
  # individually in their own smoke test blocks below.
  # ===========================================================================
  print_section "Pre-smoke: Stopping all services"

  # Stop and disable rc.d managed services
  for _svc in $RCD_SERVICES; do
    if rcctl check "$_svc" > /dev/null 2>&1; then
      info "  Stopping rc.d service: $_svc"
      rcctl stop "$_svc" 2>&1 | tee -a "$LOGFILE" || true
    fi
    rcctl disable "$_svc" 2>&1 | tee -a "$LOGFILE" || true
  done
  ok "rc.d services stopped and disabled."

  # Stop local services by process pattern -- SIGTERM then SIGKILL
  # These cover services not managed by rc.d and any survivors from rc.d stop.
  for _pat in \
    snort snortsentry e2guardian collectd p3scan clamd freshclam \
    pmacctd sockd spamd smtp-gated sslproxy imspector; do
    _stop_procs "$_pat"
  done
  ok "Local service processes stopped."

  # Clean stale PID files and sockets that would block fresh starts
  for _pidfile in \
    "${_RUNROOT}/snort/snort.pid" \
    "${_RUNROOT}/snortsentry/snortsentry.pid" \
    "${_RUNROOT}/e2guardian/e2guardian.pid" \
    "${_RUNROOT}/p3scan/p3scan.pid" \
    "${_RUNROOT}/clamd/clamd.pid" \
    "${_RUNROOT}/sockd/sockd.pid" \
    "${_RUNROOT}/spamd/spamd.pid" \
    "${_RUNROOT}/smtp-gated/smtp-gated.pid" \
    "${_RUNROOT}/sslproxy/sslproxy.pid" \
    "${_RUNROOT}/imspector/imspector.pid"; do
    [ -f "$_pidfile" ] && {
      rm -f "$_pidfile"
      info "  Removed stale PID: $_pidfile"
    }
  done

  # Remove stale sockets
  for _sock in \
    "${_RUNROOT}/clamd/clamd.socket" \
    "/tmp/clamd.socket" \
    "/tmp/imspector.sock"; do
    [ -S "$_sock" ] && {
      rm -f "$_sock"
      info "  Removed stale socket: $_sock"
    }
  done

  # Brief settle time -- let the kernel reclaim ports and file descriptors
  sleep 3
  ok "Pre-smoke teardown complete. All services stopped."

  print_section "rc.d Service Tests"

  if [ -n "${INT_IF:-}" ]; then
    info "Setting dhcpd flags to interface: $INT_IF"
    rcctl set dhcpd flags "$INT_IF" 2>&1 | tee -a "$LOGFILE"
  else
    warn "INT_IF not found; dhcpd flags may be incorrect."
  fi

  _smoke_rcd "syslogd"

  for _svc in $RCD_SERVICES; do
    [ "$_svc" = "syslogd" ] && continue
    _smoke_rcd "$_svc"
  done

  print_section "Local Service Tests"

  # SNORT IDS then IPS
  info "Smoke [local]: snort IDS"
  _SNORT="/usr/local/bin/snort"
  _SNORTIDS="/etc/snort/snort.conf"
  _SNORTIPS="/etc/snort/snortinline.conf"
  _SNORTRUN="${_RUNROOT}/snort"
  _SNORTLOG="${_LOGROOT}/snort"
  _SNORT_PID="${_SNORTRUN}/snort.pid"

  if [ ! -x "$_SNORT" ]; then
    _smoke_fail "snort" "binary not found: $_SNORT"
    _smoke_fail "snortinline" "binary not found: $_SNORT"
  elif [ ! -f "$_SNORTIDS" ]; then
    _smoke_fail "snort" "IDS config not found: $_SNORTIDS"
  else
    "$_SNORT" -i "$INT_IF" -d -c "$_SNORTIDS" \
      -u _snort -g _snort -b \
      -l "$_SNORTLOG" --pid-path "$_SNORTRUN" 2>&1 \
      | grep -v "flowbits key.*set but not ever checked" \
      | tee -a "$LOGFILE" &
    _snort_ids_pid=""
    _sw=0
    while [ "$_sw" -lt 180 ]; do
      _snort_ids_pid=$(ps aux 2> /dev/null | awk -v c="$_SNORTIDS" '/^_snort/ && $0 ~ c {print $2; exit}')
      [ -n "$_snort_ids_pid" ] && break
      sleep 5
      _sw=$((_sw + 5))
      [ $((_sw % 30)) -eq 0 ] && info "  waiting for snort IDS process... (${_sw}/180s)"
    done
    if [ -n "$_snort_ids_pid" ]; then
      _smoke_pass "snort" "IDS running PID=${_snort_ids_pid}"
    else
      _smoke_fail "snort" "process not found after 180s"
    fi

    _snort_kill_pids=$(ps aux 2> /dev/null | awk -v c="$_SNORTIDS" '/^_snort/ && $0 ~ c {print $2}')
    [ -n "$_snort_kill_pids" ] && echo "$_snort_kill_pids" | xargs kill -9 2> /dev/null || true

    sleep 3

    if [ ! -f "$_SNORTIPS" ]; then
      _smoke_fail "snortinline" "IPS config not found: $_SNORTIPS"
    else
      info "Smoke [local]: snort IPS"
      "$_SNORT" -d -Q -c "$_SNORTIPS" \
        -u _snort -g _snort -b \
        -l "$_SNORTLOG" --pid-path "$_SNORTRUN" 2>&1 \
        | grep -v "flowbits key.*set but not ever checked" \
        | tee -a "$LOGFILE" &
      _snort_ips_pid=""
      _sw=0
      while [ "$_sw" -lt 180 ]; do
        _snort_ips_pid=$(ps aux 2> /dev/null | awk -v c="$_SNORTIPS" '/^_snort/ && $0 ~ c {print $2; exit}')
        [ -n "$_snort_ips_pid" ] && break
        sleep 5
        _sw=$((_sw + 5))
        [ $((_sw % 30)) -eq 0 ] && info "  waiting for snort IPS process... (${_sw}/180s)"
      done
      if [ -n "$_snort_ips_pid" ]; then
        _smoke_pass "snortinline" "IPS running PID=${_snort_ips_pid}"
      else
        _smoke_fail "snortinline" "process not found after 180s"
      fi

      _snort_kill_pids=$(ps aux 2> /dev/null | awk -v c="$_SNORTIPS" '/^_snort/ && $0 ~ c {print $2}')
      [ -n "$_snort_kill_pids" ] && echo "$_snort_kill_pids" | xargs kill -9 2> /dev/null || true
      sleep 3
    fi
  fi

  # SNORTSENTRY
  info "Smoke [local]: snortsentry"
  _SNORTSENTRY="/usr/local/sbin/snortsentry"
  _SNORTSENTRY_CONF="/etc/snort/snortsentry.conf"
  if [ ! -x "$_SNORTSENTRY" ]; then
    _smoke_fail "snortsentry" "binary not found"
  elif [ ! -f "$_SNORTSENTRY_CONF" ]; then
    _smoke_fail "snortsentry" "config not found: $_SNORTSENTRY_CONF"
  else
    "$_SNORTSENTRY" -f "$_SNORTSENTRY_CONF" 2>&1 | tee -a "$LOGFILE" &
    sleep 30
    _ssentrypid=$(ps aux 2> /dev/null | grep snortsentry | grep perl | awk '{print $2}' | head -1 || true)
    if [ -n "$_ssentrypid" ]; then
      _smoke_pass "snortsentry" "running PID=${_ssentrypid}"
      kill -9 "$_ssentrypid" 2> /dev/null || true
    else
      _smoke_fail "snortsentry" "perl process not found after 30s"
      _stop_procs "snortsentry"
    fi
  fi

  # E2GUARDIAN
  # FIX: Removed the three `chmod o+x` lines that were papering over a
  # Phase 7 traversal issue. Traversal permissions are now correctly set
  # by the find sweep and traversal assertion in Phase 7. If e2guardian
  # fails here due to a permission error, it is a genuine Phase 7 bug
  # that needs to be fixed there -- not masked here.
  info "Smoke [local]: e2guardian"
  _E2G="/usr/local/sbin/e2guardian"
  _E2GTEMPDIR="${E2GTEMPDIR:-${_DATAROOT}/tmp/e2guardian}"
  if [ ! -x "$_E2G" ]; then
    _smoke_fail "e2guardian" "binary not found"
  else
    [ -d "$_E2GTEMPDIR" ] || mkdir -p "$_E2GTEMPDIR"
    chown -R _e2guardian:_clamav "$_E2GTEMPDIR"
    "$_E2G" 2>&1 | tee -a "$LOGFILE" &
    _e2g_pid=""
    _sw=0
    while [ "$_sw" -lt 120 ]; do
      _e2g_pid=$(ps aux 2> /dev/null | grep '[e]2guardian' | awk '{print $2}' | head -1)
      [ -n "$_e2g_pid" ] && break
      sleep 5
      _sw=$((_sw + 5))
      [ $((_sw % 20)) -eq 0 ] && info "  waiting for e2guardian process... (${_sw}/120s)"
    done
    if [ -n "$_e2g_pid" ]; then
      _smoke_pass "e2guardian" "running PID=${_e2g_pid}"
    else
      _smoke_fail "e2guardian" "process not found after 120s"
    fi
    pkill -f "$_E2G" 2> /dev/null || true
    sleep 5
  fi

  # COLLECTD
  info "Smoke [local]: collectd"
  _COLLECTD="/usr/local/sbin/collectd"
  _COLLECTD_CONF="/etc/collectd.conf"
  if [ ! -x "$_COLLECTD" ]; then
    _smoke_fail "collectd" "binary not found"
  elif [ ! -f "$_COLLECTD_CONF" ]; then
    _smoke_fail "collectd" "config not found"
  else
    "$_COLLECTD" -C "$_COLLECTD_CONF" 2>&1 | tee -a "$LOGFILE"
    sleep 5
    pgrep -x "collectd" > /dev/null 2>&1 \
      && _smoke_pass "collectd" "running PID=$(pgrep -x collectd | head -1)" \
      || _smoke_fail "collectd" "not found after 5s"
    _stop_procs "collectd"
  fi

  # P3SCAN
  info "Smoke [local]: p3scan"
  _P3SCAN="/usr/local/sbin/p3scan"
  _P3SCAN_CONF="/etc/p3scan/p3scan.conf"
  _P3SCANRUN="${_RUNROOT}/p3scan"
  if [ ! -x "$_P3SCAN" ]; then
    _smoke_fail "p3scan" "binary not found"
  elif [ ! -f "$_P3SCAN_CONF" ]; then
    _smoke_fail "p3scan" "config not found: $_P3SCAN_CONF"
  else
    [ -d "$_P3SCANRUN" ] || mkdir -p "$_P3SCANRUN"
    chown _p3scan:www "$_P3SCANRUN"
    "$_P3SCAN" -f "$_P3SCAN_CONF" 2>&1 | tee -a "$LOGFILE" &
    sleep 15
    pgrep -x "p3scan" > /dev/null 2>&1 \
      && _smoke_pass "p3scan" "running PID=$(pgrep -x p3scan | head -1) -- left running" \
      || _smoke_fail "p3scan" "not found after 15s"
  fi

  # -------------------------------------------------------------------------
  # CLAMAV -- Phase 1 of 2: freshclam (one-shot signature update)
  # -------------------------------------------------------------------------
  # freshclam MUST complete before clamd starts. clamd loads virus signatures
  # from /var/db/clamav at startup; if the database is absent or stale,
  # clamd will refuse to start. Running freshclam in daemon mode (-d) here
  # would be wrong: we need it to finish and exit before clamd is launched.
  # -------------------------------------------------------------------------
  info "Smoke [local]: freshclam (populating /var/db/clamav before clamd starts)"
  _FRESHCLAM="/usr/local/bin/freshclam"
  _FRESHCLAM_LOGFILE="${_LOGROOT}/freshclam/freshclam.log"
  _FRESHCLAM_CONF="/etc/freshclam.conf"

  if [ ! -x "$_FRESHCLAM" ]; then
    _smoke_fail "freshclam" "binary not found: $_FRESHCLAM"
  elif [ ! -f "$_FRESHCLAM_CONF" ]; then
    _smoke_fail "freshclam" "config not found: $_FRESHCLAM_CONF"
  else
    [ -d "${_LOGROOT}/freshclam" ] || mkdir -p "${_LOGROOT}/freshclam"
    chown _clamav:_clamav "${_LOGROOT}/freshclam"

    info "  Running one-shot freshclam (foreground -- this may take a moment)..."
    # Run synchronously (no &) so the shell waits for DB download to complete.
    # Output goes to both the freshclam log and the master installer log.
    "$_FRESHCLAM" --config-file="$_FRESHCLAM_CONF" \
      --log="$_FRESHCLAM_LOGFILE" >> "$LOGFILE" 2>&1
    _fc_exit=$?
    if [ "$_fc_exit" -eq 0 ] || [ "$_fc_exit" -eq 1 ]; then
      # Exit 1 means "already up to date" -- not an error.
      _smoke_pass "freshclam" "DB update complete (exit ${_fc_exit})"
    else
      # Non-zero (other than 1) is a genuine failure. We warn rather than
      # hard-fail so that clamd can still attempt startup with whatever DB
      # version is already present in /var/db/clamav.
      warn "freshclam exited ${_fc_exit} -- clamd will attempt startup with existing DB"
      _smoke_fail "freshclam" "update failed (exit ${_fc_exit}) -- clamd may not start"
    fi
  fi

  # -------------------------------------------------------------------------
  # CLAMAV -- Phase 2 of 2: clamd (starts only after freshclam has exited)
  # -------------------------------------------------------------------------
  info "Smoke [local]: clamd"
  _CLAMD="/usr/local/sbin/clamd"
  _CLAMD_CONF="/etc/clamd.conf"
  _CLAMRUN="${_DATAROOT}/run/clamav"
  _CLAMTMP="${_DATAROOT}/tmp/clamav"
  _CLAMD_LOGFILE="${_LOGROOT}/clamd/clamd.log"
  _CLAMD_PID="${_CLAMRUN}/clamd.pid"
  _CLAMD_SOCK="${_CLAMTMP}/clamd.socket"

  if [ ! -x "$_CLAMD" ]; then
    _smoke_fail "clamd" "binary not found: $_CLAMD"
  elif [ ! -f "$_CLAMD_CONF" ]; then
    _smoke_fail "clamd" "config not found: $_CLAMD_CONF"
  else
    # Ensure run/tmp directories exist with correct ownership
    for _d in "$_CLAMRUN" "$_CLAMTMP"; do
      [ -d "$_d" ] || mkdir -p "$_d"
    done
    { [ "$(stat -f '%Su' "$_CLAMRUN")" != "_clamav" ] \
      || [ "$(stat -f '%Sg' "$_CLAMRUN")" != "_clamav" ]; } \
      && chown _clamav:_clamav "$_CLAMRUN"
    { [ "$(stat -f '%Su' "$_CLAMTMP")" != "_clamav" ] \
      || [ "$(stat -f '%Sg' "$_CLAMTMP")" != "wheel" ]; } \
      && chown _clamav:wheel "$_CLAMTMP"

    # Clean up any stale PID/socket from a previous run
    if [ -f "$_CLAMD_PID" ]; then
      if pgrep -F "$_CLAMD_PID" > /dev/null 2>&1; then
        info "  Existing clamd process found (PID $(cat "$_CLAMD_PID")) -- skipping start"
      else
        info "  Removing stale PID file: $_CLAMD_PID"
        rm -f "$_CLAMD_PID"
      fi
    fi
    rm -f "$_CLAMD_SOCK"

    # Launch clamd. Append to the dedicated clamd log and the master log.
    "$_CLAMD" -c "$_CLAMD_CONF" >> "$_CLAMD_LOGFILE" 2>&1 &

    info "  Waiting for clamd socket (Max 600s -- Some low grade SBCs require up to 480s.)..."
    _wait_for_file "$_CLAMD_SOCK" 600 "clamd socket"
    _clamd_wait_rc=$?

    if [ "$_clamd_wait_rc" -ne 0 ]; then
      _smoke_fail "clamd" "socket not ready after 600s: $_CLAMD_SOCK"
    else
      # Give clamd a brief moment to finish privilege-drop before reading PID
      sleep 2
      _clamd_pid=$(pgrep -x "clamd" 2> /dev/null | head -1 || true)
      _smoke_pass "clamd" "socket ready, running PID=${_clamd_pid:-unknown}"
    fi

    pkill -x "clamd" 2> /dev/null || true
  fi

  # PMACCT
  info "Smoke [local]: pmacct"
  _PMACCTD="/usr/local/sbin/pmacctd"
  _PMACCT_MFS="${_DATAROOT}/pipes/pmacct"
  _pmacct_ok=0
  [ -d "$_PMACCT_MFS" ] || mkdir -p "$_PMACCT_MFS"
  touch "${_PMACCT_MFS}/ext_if_json.log" "${_PMACCT_MFS}/int_if_json.log"
  chmod 644 "${_PMACCT_MFS}/ext_if_json.log" "${_PMACCT_MFS}/int_if_json.log"
  if [ ! -x "$_PMACCTD" ]; then
    _smoke_fail "pmacct" "binary not found"
  else
    for _pconf in ext_if_json_mfs int_if_json_mfs ext_if_json_log; do
      _pcf="/etc/pmacct/${_pconf}.conf"
      if [ ! -f "$_pcf" ]; then
        warn "pmacct: config not found: $_pcf (skipping)"
        continue
      fi
      "$_PMACCTD" -f "$_pcf" 2>&1 | tee -a "$LOGFILE"
      _pm_pid="" _pm_w=0
      while [ "$_pm_w" -lt 15 ]; do
        _pm_pid=$(ps aux 2> /dev/null | grep '[p]macctd' | awk '{print $2}' | head -1)
        [ -n "$_pm_pid" ] && break
        sleep 1
        _pm_w=$((_pm_w + 1))
      done
      if [ -n "$_pm_pid" ]; then
        _pmacct_ok=$((_pmacct_ok + 1))
        info "pmacct: $_pconf started ok PID=${_pm_pid}"
        pkill -f "$_PMACCTD" 2> /dev/null || true
        sleep 2
      else
        warn "pmacct: $_pconf did not appear in ps after 15s"
        pkill -f "$_PMACCTD" 2> /dev/null || true
      fi
    done
    [ "$_pmacct_ok" -gt 0 ] \
      && _smoke_pass "pmacct" "${_pmacct_ok}/3 configs started ok" \
      || _smoke_fail "pmacct" "no pmacctd config started successfully"
  fi

  # SOCKD / DANTE
  info "Smoke [local]: sockd"
  _SOCKD="/usr/local/sbin/sockd"
  _SOCKD_CONF="/etc/sockd.conf"
  _SOCKD_PID="/var/www/htdocs/tn/data/run/sockd/sockd.pid"
  if [ ! -x "$_SOCKD" ]; then
    _smoke_fail "sockd" "binary not found"
  elif [ ! -f "$_SOCKD_CONF" ]; then
    _smoke_fail "sockd" "config not found: $_SOCKD_CONF"
  else
    [ -d "${_RUNROOT}/sockd" ] || mkdir -p "${_RUNROOT}/sockd"
    "$_SOCKD" -D -f "$_SOCKD_CONF" -p "$_SOCKD_PID" 2>&1 | tee -a "$LOGFILE" &
    _sockd_pid="" _sw=0
    while [ "$_sw" -lt 15 ]; do
      _sockd_pid=$(ps aux 2> /dev/null | grep '[s]ockd' | awk '{print $2}' | head -1)
      [ -n "$_sockd_pid" ] && break
      sleep 1
      _sw=$((_sw + 1))
    done
    if [ -n "$_sockd_pid" ]; then
      _smoke_pass "sockd" "running PID=${_sockd_pid}"
    else
      _smoke_fail "sockd" "not found in ps after 15s"
    fi
    pkill sockd 2> /dev/null || true
  fi

  # SPAMD
  info "Smoke [local]: spamd"
  _SPAMD="/usr/local/bin/spamd"
  _SPAMD_PID="/var/www/htdocs/tn/data/run/spamd/spamd.pid"
  if [ ! -x "$_SPAMD" ]; then
    _smoke_fail "spamd" "binary not found"
  else
    [ -d "${_RUNROOT}/spamd" ] || mkdir -p "${_RUNROOT}/spamd"
    "$_SPAMD" -L -d -x -u _spamdaemon -r "$_SPAMD_PID" 2>&1 | tee -a "$LOGFILE" &
    _spamd_pid="" _sw=0
    while [ "$_sw" -lt 15 ]; do
      _spamd_pid=$(ps aux 2> /dev/null | grep '[s]pamd' | awk '{print $2}' | head -1)
      [ -n "$_spamd_pid" ] && break
      sleep 1
      _sw=$((_sw + 1))
    done
    if [ -n "$_spamd_pid" ]; then
      _smoke_pass "spamd" "running PID=${_spamd_pid}"
    else
      _smoke_fail "spamd" "not found in ps after 15s"
    fi
    pkill -f spamd 2> /dev/null || true
  fi

  # SMTP-GATED
  # NOTE: rcctl status smtp-gated is unreliable during smoke tests (it checks
  # rc.d enabled state, not live process presence). pgrep -x is authoritative
  # for confirming the daemon is actually running after privilege-drop fork.
  info "Smoke [local]: smtp-gated"
  _SMTPGATED="/usr/local/sbin/smtp-gated"
  _SMTPGATED_CONF="/usr/local/etc/smtp-gated/smtp-gated.conf"
  _SMTPDGATED_PID="$BASE/run/smtp-gated/smtp-gated.pid"

  if [ -f "$_SMTPDGATED_PID" ]; then
    rm -f "$_SMTPDGATED_PID"
  fi

  if [ ! -x "$_SMTPGATED" ]; then
    _smoke_fail "smtp-gated" "binary not found: $_SMTPGATED"
  elif [ ! -f "$_SMTPGATED_CONF" ]; then
    _smoke_fail "smtp-gated" "config not found: $_SMTPGATED_CONF"
  else
    # Launch directly without tee: smtp-gated performs a privilege-drop fork
    # after startup. Piping through tee would keep the process as a child of
    # tee and prevent the fork from completing before pgrep runs, producing
    # a false-negative even when the daemon is healthy.
    "$_SMTPGATED" "$_SMTPGATED_CONF" >> "$LOGFILE" 2>&1
    sleep 10
    # pgrep -x matches the exact process name -- consistent with the rest of
    # Phase 9 and immune to false positives from grep self-matching.
    _smtpg_pid=$(pgrep -x "smtp-gated" 2> /dev/null | head -1 || true)
    if [ -n "$_smtpg_pid" ]; then
      _smoke_pass "smtp-gated" "running PID=${_smtpg_pid} -- left running"
    else
      _smoke_fail "smtp-gated" "not found via pgrep after 10s"
    fi
  fi

  # SSLPROXY
  info "Smoke [local]: sslproxy"
  _SSLPROXY="/usr/local/bin/sslproxy"
  _SSLPROXY_CONF="/usr/local/etc/sslproxy/sslproxy.conf"
  if [ ! -x "$_SSLPROXY" ]; then
    _smoke_fail "sslproxy" "binary not found"
  elif [ ! -f "$_SSLPROXY_CONF" ]; then
    _smoke_fail "sslproxy" "config not found"
  else
    "$_SSLPROXY" -f "$_SSLPROXY_CONF" 2>&1 | tee -a "$LOGFILE" &
    sleep 5
    pgrep -x "sslproxy" > /dev/null 2>&1 \
      && _smoke_pass "sslproxy" "running PID=$(pgrep -x sslproxy | head -1) -- left running" \
      || _smoke_fail "sslproxy" "not found after 5s"
  fi

  # IMSPECTOR
  info "Smoke [local]: imspector"
  _IMSPECTOR="/usr/local/sbin/imspector"
  _IMSPECTOR_CONF="/usr/local/etc/imspector/imspector.conf"
  if [ ! -x "$_IMSPECTOR" ]; then
    _smoke_fail "imspector" "binary not found: $_IMSPECTOR"
  elif [ ! -f "$_IMSPECTOR_CONF" ]; then
    _smoke_fail "imspector" "config not found: $_IMSPECTOR_CONF"
  else
    [ -d /tmp/imspector ] || mkdir -p /tmp/imspector
    chown -R _imspector:_imspector /tmp/imspector
    "$_IMSPECTOR" -c "$_IMSPECTOR_CONF" 2>&1 | tee -a "$LOGFILE" &
    sleep 5
    pgrep -x "imspector" > /dev/null 2>&1 \
      && _smoke_pass "imspector" "running PID=$(pgrep -x imspector | head -1) -- left running" \
      || _smoke_fail "imspector" "not found after 5s"
  fi

  # TCPDUMP -- verify BPF capture works on pflog1
  # pflog1 is the PF logging interface.
  # This test confirms:
  #   1. tcpdump binary is executable
  #   2. pflog1 interface exists and is up
  #   3. BPF device is accessible (kernel not denying capture)
  # NOTE: -c 1 will block until one packet arrives on pflog1. Since PF may
  # not be generating log events during install, we run with a timeout.
  info "Smoke [local]: tcpdump"
  _TCPDUMP="/usr/sbin/tcpdump"
  if [ ! -x "$_TCPDUMP" ]; then
    _smoke_fail "tcpdump" "binary not found: $_TCPDUMP"
  elif ! ifconfig pflog1 > /dev/null 2>&1; then
    _smoke_fail "tcpdump" "pflog1 interface not found -- PF logging pipeline broken"
  else
    # Use -c 1 with a timeout -- pflog1 may have no traffic during install.
    # We background tcpdump, wait briefly, then check if it's still alive
    # (meaning it opened BPF successfully and is waiting for packets).
    # A failed open exits immediately; a successful open blocks on read.
    "$_TCPDUMP" -i pflog1 -c 1 > /dev/null 2>&1 &
    _td_pid=$!
    sleep 2
    if kill -0 "$_td_pid" > /dev/null 2>&1; then
      # Still running -- BPF open succeeded, waiting for packets
      kill "$_td_pid" > /dev/null 2>&1 || true
      wait "$_td_pid" 2> /dev/null || true
      _smoke_pass "tcpdump" "BPF capture ok on pflog1 (PF logging interface)"
    else
      # Exited immediately -- either got a packet (success) or failed to open
      wait "$_td_pid"
      _td_exit=$?
      if [ "$_td_exit" -eq 0 ]; then
        _smoke_pass "tcpdump" "BPF capture ok on pflog1 (packet received)"
      else
        _smoke_fail "tcpdump" "BPF open failed on pflog1 (exit $_td_exit)"
      fi
    fi
  fi

  phase_done "phase9"

  # Disable resolvd before writing resolv.conf -- it monitors DHCP/RA events
  # and will overwrite the file. Unbound is not started until Phase 9 but the
  # config is already in place; resolv.conf pointing to loopback is correct
  # at this stage and will be live by the time Phase 9 brings unbound up.
  rcctl disable resolvd 2> /dev/null || true
  rcctl stop resolvd 2> /dev/null || true
  truncate -s0 /etc/resolv.conf
  printf "nameserver 127.0.0.1\nnameserver ::1\n" > /etc/resolv.conf
  ok "resolv.conf committed (resolvd disabled, unbound starts Phase 9)."

  # Persist smoke results so Phase 10 reports correctly on resume
  printf '%d\n%s\n' "$SMOKE_ERR_COUNT" "$SMOKE_RESULTS" > "$_STATE_SMOKE"
  ok "Smoke results persisted for resume."
fi

# =============================================================================
# PHASE 9a: GeoIP Data and Threat Intel Seeding
# =============================================================================
# Two steps, independent of each other:
#
#   1. get_geoip_data.pl  -- downloads current MaxMind GeoLite2 databases
#      into the webroot GeoIP directory. Non-fatal: the UTM operates without
#      GeoIP data but the geo-blocking and geo-reporting panels will be empty.
#
#   2. intel.txt deploy   -- copies payload/etc/pf/intel.txt to
#      data/db/pf/intel.txt (www:www 0644). This is the seed threat
#      intelligence blocklist used by pfblock.sh on first boot. Without it
#      the <blocklist> PF table starts empty until the first feed fetch.
#
# Neither step is gated by a phase checkpoint -- they are fast, idempotent,
# and safe to re-run. A failure in either step produces a warning and
# continues; the installer does not stop.
# =============================================================================
print_header "Phase 9a: GeoIP Data and Threat Intel Seeding"

# -------------------------------------------------------------------------
# STEP 1: GeoIP database fetch
# -------------------------------------------------------------------------
_GEOIP_SCRIPT="/usr/local/sbin/get_geoip_data.pl"
_GEOIP_DIR="$BASE/db/GeoIP"

print_section "GeoIP database fetch"

if [ ! -x "$_GEOIP_SCRIPT" ]; then
  warn "get_geoip_data.pl not found or not executable: $_GEOIP_SCRIPT"
  warn "GeoIP databases not populated -- geo panels will be empty until manually run."
else
  mkdir -p "$_GEOIP_DIR"
  chown www:www "$_GEOIP_DIR"
  chmod 755 "$_GEOIP_DIR"

  info "Running get_geoip_data.pl ..."
  if perl "$_GEOIP_SCRIPT" >> "$LOGFILE" 2>&1; then
    ok "GeoIP databases fetched: $_GEOIP_DIR"
  else
    warn "get_geoip_data.pl exited non-zero -- GeoIP data may be incomplete."
    warn "Re-run manually: perl $_GEOIP_SCRIPT"
    warn "Or wait for the scheduled cron fetch after first boot."
  fi
fi

# -------------------------------------------------------------------------
# STEP 2: Threat intel seed file
# -------------------------------------------------------------------------
_INTEL_SRC="$PAYLOAD_DIR/etc/pf/intel.txt"
_INTEL_DST="$BASE/db/pf/intel.txt"

print_section "Threat intel seed file"

if [ ! -f "$_INTEL_SRC" ]; then
  warn "intel.txt not found in payload: $_INTEL_SRC"
  warn "<blocklist> PF table will start empty until pfblock.sh runs."
else
  cp "$_INTEL_SRC" "$_INTEL_DST"
  chown www:www "$_INTEL_DST"
  chmod 0644 "$_INTEL_DST"
  ok "intel.txt deployed: $_INTEL_DST (www:www 0644)"
  info "  $(wc -l < "$_INTEL_DST" | tr -d ' ') entries in seed blocklist."
fi

ok "Phase 9a complete."

# =============================================================================
# PHASE 10: Final Report
# =============================================================================
print_header "Phase 10: Final Installation Report"

echo ""
echo "  +----------------------------------------------------------+"
echo "  |          TANGENT NETWORKS INSTALLER SUMMARY              |"
echo "  +----------------------------------------------------------+"
echo ""

if [ "$PKG_ERR_COUNT" -eq 0 ]; then
  ok "Packages:    All installed and verified"
else
  err "Packages:    $PKG_ERR_COUNT failure(s)"
fi

if [ -f "$AUTH_DB" ] && [ -s "$AUTH_DB" ]; then
  ok "AuthDB:      Initialised ($AUTH_DB)"
else
  err "AuthDB:      NOT initialised"
fi

for _key in session.key hmac.key; do
  if [ -f "$KEYS_DIR/$_key" ] && [ -s "$KEYS_DIR/$_key" ]; then
    ok "Key:         $KEYS_DIR/$_key ($(stat -f "%Lp" "$KEYS_DIR/$_key"))"
  else
    err "Key:         $KEYS_DIR/$_key MISSING"
  fi
done

echo ""
echo "  Service Smoke Test Results:"
echo "  ===================================================="
printf '%s' "$SMOKE_RESULTS" | while IFS=: read -r _s _r _d; do
  [ -z "$_s" ] && continue
  if [ "$_r" = "PASS" ]; then
    printf "  ${GREEN}[PASS]${NC} %-20s %s\n" "$_s" "$_d"
  else
    printf "  ${RED}[FAIL]${NC} %-20s %s\n" "$_s" "$_d"
  fi
done
echo "  ===================================================="

_pass_smoke=$(printf '%s' "$SMOKE_RESULTS" | grep -c ":PASS:" 2> /dev/null || true)
printf "  Smoke tests: %d passed, %d failed\n" "${_pass_smoke:-0}" "$SMOKE_ERR_COUNT"

if [ "$REBOOT_REQUIRED" -eq 1 ]; then
  echo ""
  warn "REBOOT REQUIRED -- errata patches were applied."
  warn "Run: shutdown -r now"
fi

echo ""
echo "  Log file:     $LOGFILE"
echo "  Phase state:  $PHASE_STATE_FILE"
echo "  Rollback ref: $ROLLBACK_DIR"
echo ""

# =============================================================================
# WRITE STATUS FILE
# =============================================================================
if [ "$PKG_ERR_COUNT" -eq 0 ] && [ -f "$AUTH_DB" ] && [ -s "$AUTH_DB" ]; then
  INSTALL_COMPLETE=1
  echo "SUCCESS" > "$STATUS_OK"
  echo "$(date)" >> "$STATUS_OK"
  [ "$SMOKE_ERR_COUNT" -gt 0 ] && echo "SMOKE_WARNINGS=$SMOKE_ERR_COUNT" >> "$STATUS_OK"
  ok "Status written: $STATUS_OK"
  ok "Installation complete."
  rm -f "$PHASE_STATE_FILE" "$_STATE_PKG_ERR" "$_STATE_SMOKE" "$_STATE_RESOLVED"
else
  err "Installation incomplete -- STATUS_OK not written."
  err "Review errors above and in $LOGFILE"
  echo ""
  echo "  ============================================================"
  echo "  INSTALLATION INCOMPLETE"
  echo "  All packages are still installed on the system."
  echo "  You can troubleshoot from this console or another session."
  echo ""
  echo "  Options:"
  echo "    r = roll back (remove packages, restore configs)"
  echo "    w = leave everything in place and exit (resume later)"
  echo "  ============================================================"
  printf "  Choice (r/w) [w]: "
  read -r _final_choice < /dev/tty
  case "$_final_choice" in
    r | R | rollback | ROLLBACK)
      print_header "ROLLBACK -- Removing packages installed this run"
      warn "Rolling back by operator request."

      if [ -f "$ROLLBACK_DIR/pkg-list-before.txt" ] && [ -n "$PKGS_INSTALLED_THIS_RUN" ]; then
        print_section "Removing installed packages"
        for _rb_pkg in $PKGS_INSTALLED_THIS_RUN; do
          _rb_stem=$(echo "$_rb_pkg" | sed -E 's/-[0-9].*//')
          if pkg_info -a 2> /dev/null | awk -v s="$_rb_stem" '$1 ~ "^" s "-[0-9]" {found=1; exit} END {exit !found}'; then
            info "pkg_delete: $_rb_pkg"
            pkg_delete -Iv "$_rb_pkg" 2>&1 | tee -a "$LOGFILE" || true
          fi
        done
      fi

      if [ -d "$ROLLBACK_DIR/etc" ]; then
        print_section "Restoring /etc configs"
        find "$ROLLBACK_DIR/etc" -type f | while read -r _bak; do
          _rel="${_bak#$ROLLBACK_DIR}"
          [ -f "$_bak" ] && {
            cp "$_bak" "$_rel"
            ok "Restored: $_rel"
          }
        done
      fi

      if [ -f "$ROLLBACK_DIR/sbin-manifest.txt" ]; then
        print_section "Removing sbin files"
        while read -r _rbf; do rm -f "$_rbf" && ok "Removed: $_rbf"; done \
          < "$ROLLBACK_DIR/sbin-manifest.txt"
      fi

      if [ -f "$ROLLBACK_DIR/webroot-deployed" ]; then
        print_section "Removing webroot"
        rm -rf /var/www/htdocs/tn && ok "Webroot removed."
      fi

      if [ -f "$ROLLBACK_DIR/authdb-created" ]; then
        print_section "Removing authdb and keys"
        rm -f "$AUTH_DB" "$KEYS_DIR/session.key" "$KEYS_DIR/hmac.key"
        ok "AuthDB and keys removed."
      fi

      ok "Rollback complete. Artifacts preserved at: $ROLLBACK_DIR"
      ;;
    *)
      warn "Leaving all packages and files in place."
      warn "Phase state preserved at: $PHASE_STATE_FILE"
      warn "Re-run the installer to resume, or troubleshoot manually."
      warn "Log: $LOGFILE"
      warn "Rollback reference: $ROLLBACK_DIR"
      ;;
  esac
  exit 1
fi

# =============================================================================
# PHASE 11: pf.conf Syntax Check and Deploy
# =============================================================================
# DESIGN DECISION -- no pfctl -f (ruleset reload) here:
#
# Operators install this system over SSH, typically connected to EXT_IF.
# The deployed pf.conf blocks SSH on EXT_IF as a security baseline. Loading
# the new ruleset via pfctl -f would immediately drop the SSH session, kill
# the script mid-run, and leave the system without a confirmed exit status.
#
# Instead this phase:
#   1. Verifies the payload pf.conf passes pfctl -nf (syntax only, no load).
#   2. Backs up the live /etc/pf.conf to ROLLBACK_DIR.
#   3. Copies the payload to /etc/pf.conf (640 root:wheel).
#   4. Prints explicit operator instructions to load the ruleset manually
#      from the console (not over SSH) or after reconnecting on INT_IF.
#
# The script then exits 0 cleanly with the SSH session intact.
# =============================================================================
print_header "Phase 11: pf.conf Syntax Check and Deploy"

_PF_PAYLOAD="$PAYLOAD_DIR/etc/pf.conf"
_PF_LIVE="/etc/pf.conf"
_PF_ERRORS=0

# Step 1: Gate on full install success
if [ "$INSTALL_COMPLETE" -ne 1 ]; then
  err "pf.conf deploy SKIPPED -- installation did not complete cleanly."
  err "Resolve all errors above before allowing pf rules to be replaced."
  err "A ruleset deployed over a broken system may lock out all access."
  _PF_ERRORS=$((_PF_ERRORS + 1))
fi

# Step 2: Payload must exist
if [ "$_PF_ERRORS" -eq 0 ]; then
  if [ ! -f "$_PF_PAYLOAD" ]; then
    err "pf.conf not found in payload: $_PF_PAYLOAD"
    err "Ensure TN payload includes etc/pf.conf before running this script."
    _PF_ERRORS=$((_PF_ERRORS + 1))
  else
    ok "Payload pf.conf found: $_PF_PAYLOAD"
  fi
fi

# Step 3: Syntax check only -- pfctl -nf parses without loading into kernel
if [ "$_PF_ERRORS" -eq 0 ]; then
  info "Running pfctl -nf (syntax check only -- ruleset NOT loaded)..."
  _pf_syntax_out=$(pfctl -nf "$_PF_PAYLOAD" 2>&1)
  _pf_syntax_exit=$?
  if [ "$_pf_syntax_exit" -ne 0 ]; then
    err "pf.conf syntax check FAILED (pfctl exit $_pf_syntax_exit):"
    printf '%s\n' "$_pf_syntax_out" | while IFS= read -r _l; do err "  $_l"; done
    err "Live /etc/pf.conf has NOT been touched."
    _PF_ERRORS=$((_PF_ERRORS + 1))
  else
    ok "pf.conf syntax OK (pfctl -nf passed)"
    if [ -n "$_pf_syntax_out" ]; then
      printf '%s\n' "$_pf_syntax_out" | while IFS= read -r _l; do
        [ -n "$_l" ] && warn "  pfctl: $_l"
      done
    fi
  fi
fi

# Step 4: Backup live pf.conf
if [ "$_PF_ERRORS" -eq 0 ]; then
  mkdir -p "$ROLLBACK_DIR/etc"
  if [ -f "$_PF_LIVE" ]; then
    cp "$_PF_LIVE" "$ROLLBACK_DIR/etc/pf.conf.bak"
    ok "Backed up: $_PF_LIVE -> $ROLLBACK_DIR/etc/pf.conf.bak"
  else
    info "No existing $_PF_LIVE to back up (first install)."
  fi
fi

# Step 5: Deploy to /etc/pf.conf (no reload)
if [ "$_PF_ERRORS" -eq 0 ]; then
  cp "$_PF_PAYLOAD" "$_PF_LIVE"
  chmod 640 "$_PF_LIVE"
  chown root:wheel "$_PF_LIVE"
  ok "Deployed: $_PF_LIVE (640 root:wheel)"
fi

echo ""
if [ "$_PF_ERRORS" -eq 0 ]; then
  ok "Phase 11 complete: pf.conf deployed and syntax verified."
  phase_done "phase11"
  echo ""
  echo "  ============================================================"
  echo "  ACTION REQUIRED: Load pf Ruleset"
  echo "  ============================================================"
  echo ""
  warn "The new pf.conf has been deployed but NOT loaded."
  warn "Loading it over SSH will drop your session immediately."
  warn "The new ruleset blocks SSH on EXT_IF for security."
  echo ""
  echo "  To activate the ruleset safely, choose ONE of:"
  echo ""
  echo "  OPTION A -- Physical or serial console access:"
  echo "    pfctl -f /etc/pf.conf"
  echo ""
  echo "  OPTION B -- After reconnecting on INT_IF (LAN side):"
  echo "    ssh root@${INT_IP4:-<INT_IP4>}"
  echo "    pfctl -f /etc/pf.conf"
  echo ""
  echo "  OPTION C -- Schedule a deferred load (stays connected 60s):"
  echo "    echo 'pfctl -f /etc/pf.conf' | at now + 1 minute"
  echo "    (reconnect via LAN before the minute elapses)"
  echo ""
  echo "  Rollback if needed:"
  echo "    cp $ROLLBACK_DIR/etc/pf.conf.bak /etc/pf.conf"
  echo "    pfctl -f /etc/pf.conf"
  echo "  ============================================================"
  echo ""

  # CA cert -- same file as TLS cert (self-signed CA)
  TLS_CERT=$(awk '/certificate/ { print $2; exit }' /etc/httpd.conf | tr -d '"')
  CERT_BASENAME=$(basename "$TLS_CERT")
  cp "$TLS_CERT" "/var/www/htdocs/tn/certs/${CERT_BASENAME}"
  chown www:www "/var/www/htdocs/tn/certs/${CERT_BASENAME}"
  chmod 644 "/var/www/htdocs/tn/certs/${CERT_BASENAME}"
  ok "CA cert deployed to /var/www/htdocs/tn/certs/${CERT_BASENAME} (www:www 0644)"

  echo ""
  echo "  ============================================================"
  echo "  CA Certificate Installation"
  echo "  ============================================================"
  echo ""
  echo "  To trust the Tangent Networks CA on client devices, download"
  echo "  the certificate from:"
  echo ""
  echo "    http://${INT_IP4}/certs/${CERT_BASENAME}"
  echo ""
  echo "  On managed networks, deploy via GPO or MDM."
  echo "  ============================================================"
  echo ""

  ok "Installation complete. Log: $LOGFILE"
  exit 0
else
  err "Phase 11 FAILED: $_PF_ERRORS error(s) -- pf ruleset not changed."
  err "Review errors above. Re-run after fixing the installation or payload."
  exit 1
fi

exit 0
