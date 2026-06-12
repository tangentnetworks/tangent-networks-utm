#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# =============================================================================
# TN_CHROOT_SETUP.sh -- Tangent Networks Chroot Environment Setup
# =============================================================================
# Prepares the /var/www chroot environment for the TN web stack.
# Must be run as root on OpenBSD after TN_PKG_INSTALL.sh completes.
#
# Responsibilities:
#   00. Pre-flight   -- root check, source tree validation, .so version probing
#   01. Binaries     -- perl, ld.so, ldd, tail, date
#   02. Core perl5   -- /usr/libdata/perl5 (strict, warnings, POSIX, Fcntl ...)
#   03. site_perl    -- /usr/local/libdata/perl5 (DBI, DBD::SQLite, JSON::XS ...)
#                       excludes collectd-only XS: RRDs, Net::Oping, Collectd
#   04. Shared libs  -- ldd against perl binary + all XS .so from both trees
#                       (core and site_perl); versioned symlinks auto-created
#   04a. ld.so.hints -- ldconfig run inside chroot (fallback: copy host hints)
#                       fixes "Cannot load specified object" for XS modules
#   05. Timezone     -- /etc/localtime
#   06. Devices      -- /dev/null, /dev/random, /dev/urandom
#   07. Directories  -- runtime, log, db, keys, session, queue, sockets
#   08. Permissions  -- CGI scripts, config, maintenance scripts
#   09. Session keys -- verify / copy session.key and hmac.key
#   10. Perl sanity  -- chroot perl module load test covering all WebUI deps
#                       JSON::XS (full export) + JSON::PP () (no export, avoids
#                       prototype collision) mirrors actual pf_* CGI usage
#   11. TNAudit & TNWatch -- initialise monitoring databases and baselines
#                       TNAudit: init-db, create-baseline, status verification
#                       TNWatch: init-db, parse-all, test-email
#
# Run modes:
#   doas ksh TN_CHROOT_SETUP.sh           -- full setup (writes manifest on first run)
#   doas ksh TN_CHROOT_SETUP.sh --verify  -- check only, no changes
#
# Manifest (chroot-manifest.txt + chroot-manifest.sha256, next to this script):
#   First run  -- host is pristine; every host source path copied is recorded.
#                 SHA256 of the manifest is written to chroot-manifest.sha256
#                 (root:wheel 600).  Both files are then frozen.
#   Re-run     -- SHA256 of chroot-manifest.txt is verified against stored hash.
#                 Match: only manifest-listed host paths are copied to chroot.
#                 Mismatch: HARD STOP -- manifest may have been tampered with.
#   To rebuild  -- rm chroot-manifest.txt chroot-manifest.sha256, re-run on
#                 a clean host.
#
# VERSION: 4.2.0
# =============================================================================

set -uo pipefail
umask 022

# =============================================================================
# PATHS
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
LOGFILE="${LOG_DIR}/chroot-setup.log"
STATUS_OK="${HOME}/chroot-setup"
STATUS_FAIL="${HOME}/chroot-fail"

CHROOT="/var/www"
APP_ROOT="${CHROOT}/htdocs/tn"
MANIFEST="${SCRIPT_DIR}/chroot-manifest.txt"
MANIFEST_SHA="${SCRIPT_DIR}/chroot-manifest.sha256"
DATA_DIR="${APP_ROOT}/data"
SCRIPTS_DIR="${DATA_DIR}/scripts"

# Core OS Perl library -- strict, warnings, POSIX, Fcntl, File::* etc.
# This is the base OpenBSD distribution tree, separate from packages.
PERL5CORE_SRC="/usr/libdata/perl5"
PERL5CORE_DST="${CHROOT}/usr/libdata/perl5"

# Package-installed site_perl -- DBI, DBD::SQLite, JSON::XS, Crypt::* etc.
PERL5SITE_SRC="/usr/local/libdata/perl5"
PERL5SITE_DST="${CHROOT}/usr/local/libdata/perl5"

PERL_BIN="/usr/bin/perl"

# =============================================================================
# ARCHITECTURE
# =============================================================================
# Detect the perl architecture string at runtime (e.g. amd64-openbsd,
# aarch64-openbsd) so no path or label in this script is hardcoded to a
# specific architecture.  The string comes directly from perl itself and
# matches the subdirectory name used inside the perl5 library trees.
#
# Examples:
#   amd64-openbsd   (x86_64 hardware)
#   aarch64-openbsd (Apple Silicon, ARM servers, Raspberry Pi 4+)
#
# If perl is not yet available the script falls back to uname(1) and constructs
# the conventional OpenBSD arch string -- this covers the pre-Step-1 window.
if [ -x "$PERL_BIN" ]; then
  PERL_ARCH=$("$PERL_BIN" -MConfig -e 'print $Config{archname}')
else
  _uname_m=$(uname -m)
  case "$_uname_m" in
    x86_64) PERL_ARCH="amd64-openbsd" ;;
    aarch64) PERL_ARCH="aarch64-openbsd" ;;
    arm*) PERL_ARCH="arm-openbsd" ;;
    *) PERL_ARCH="${_uname_m}-openbsd" ;;
  esac
fi

mkdir -p "$LOG_DIR"

# =============================================================================
# MODE
# =============================================================================
VERIFY_ONLY=0
[ "${1:-}" = "--verify" ] && VERIFY_ONLY=1

# =============================================================================
# COLOUR
# =============================================================================
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  MAGENTA='\033[0;35m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  CYAN=''
  BOLD=''
  MAGENTA=''
  NC=''
fi

# =============================================================================
# LOGGING
# =============================================================================
printf "\n=== RUN %s MODE=%s ===\n" \
  "$(date '+%Y-%m-%d %H:%M:%S')" \
  "$([ "$VERIFY_ONLY" -eq 1 ] && echo VERIFY || echo SETUP)" \
  >> "$LOGFILE"

_log() {
  printf "[%s] [%-5s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" \
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
  echo "  ============================================================"
  printf "  ${BOLD}%s${NC}\n" "$1"
  echo "  ============================================================"
  _log "INFO" "=== $1 ==="
}

print_section() {
  echo ""
  printf "  ${CYAN}-- %s --${NC}\n" "$1"
  _log "INFO" "-- $1 --"
}

ERRORS=0
note_err() {
  err "$1"
  ERRORS=$((ERRORS + 1))
}

# =============================================================================
# MANIFEST
# =============================================================================
# chroot-manifest.txt  -- one absolute HOST source path per line, written once
#                         on first run while the host is pristine.
# chroot-manifest.sha256 -- SHA256 of the manifest file, written immediately
#                         after the manifest, root-owned 600.
#
# First run  (neither file exists):
#   find walks host source trees normally; every file copied is appended to
#   the manifest as its host source path.  After all steps complete,
#   _manifest_seal() computes SHA256 and writes chroot-manifest.sha256.
#
# Re-run     (both files exist):
#   _manifest_verify() recomputes SHA256 of chroot-manifest.txt and compares
#   it against chroot-manifest.sha256.  Match → proceed, reading manifest to
#   know exactly which host paths to copy.  Mismatch → hard stop; the manifest
#   may have been tampered with to smuggle new packages into the chroot.
#
# Tamper response: HARD STOP.  Operator must delete both files and re-run on
#   a clean host to establish a new baseline.
#
# To rebuild:  rm chroot-manifest.txt chroot-manifest.sha256  then re-run.

_manifest_seal() {
  # Write manifest + SHA256 file after a successful first run.
  # Both files are locked down to root:wheel 600.
  sort -u "$MANIFEST" -o "$MANIFEST"
  sha256 -q "$MANIFEST" > "$MANIFEST_SHA"
  chmod 600 "$MANIFEST" "$MANIFEST_SHA"
  chown root:wheel "$MANIFEST" "$MANIFEST_SHA"
  local _mc
  _mc=$(wc -l < "$MANIFEST" | tr -d ' ')
  ok "Manifest sealed: ${MANIFEST} (${_mc} host paths)"
  ok "Manifest SHA256: ${MANIFEST_SHA}"
}

_manifest_verify() {
  # Recompute SHA256 of manifest and compare against stored value.
  # Returns 0 on match, 1 on any mismatch or missing file.
  if [ ! -f "$MANIFEST" ]; then
    err "Manifest missing: ${MANIFEST}"
    return 1
  fi
  if [ ! -f "$MANIFEST_SHA" ]; then
    err "Manifest SHA256 missing: ${MANIFEST_SHA}"
    err "Cannot verify manifest integrity -- delete both files and re-run on clean host"
    return 1
  fi
  local _stored _actual
  _stored=$(cat "$MANIFEST_SHA")
  _actual=$(sha256 -q "$MANIFEST")
  if [ "$_actual" = "$_stored" ]; then
    local _mc
    _mc=$(wc -l < "$MANIFEST" | tr -d ' ')
    ok "Manifest verified (${_mc} host paths): SHA256 matches"
    return 0
  else
    err "MANIFEST INTEGRITY FAILURE"
    err "  Expected : ${_stored}"
    err "  Computed : ${_actual}"
    err "  The manifest may have been modified to introduce unauthorised packages."
    err "  To establish a new baseline: rm ${MANIFEST} ${MANIFEST_SHA}"
    err "  Then re-run this script on a clean host."
    return 1
  fi
}

# _copy_file HOST_SRC CHROOT_DST
# Incremental copy. On first run, appends HOST_SRC to manifest.
_copy_file() {
  local _src="$1" _dst="$2" _dd
  [ -f "$_src" ] || return 0
  _dd=$(dirname "$_dst")
  [ -d "$_dd" ] || mkdir -p "$_dd"
  if [ ! -f "$_dst" ] || ! cmp -s "$_src" "$_dst" 2> /dev/null; then
    cp -p "$_src" "$_dst"
  fi
  # Record host source path on first run only
  [ "${_MANIFEST_FIRST_RUN:-0}" -eq 1 ] && printf '%s\n' "$_src" >> "$MANIFEST"
}

# _copy_tree HOST_SRC CHROOT_DST
# First run:  walk host SRC with find; _copy_file records each host path.
# Re-run:     read manifest lines whose prefix matches HOST_SRC; derive
#             chroot dst mechanically as ${CHROOT}${host_path}; copy directly.
_copy_tree() {
  local _src="$1" _dst="$2" _f _d

  if [ "${_MANIFEST_FIRST_RUN:-0}" -eq 1 ]; then
    find "$_src" -print | while IFS= read -r _f; do
      _d="${CHROOT}${_f}"
      if [ -d "$_f" ]; then
        [ -d "$_d" ] || mkdir -p "$_d"
        continue
      fi
      [ -f "$_f" ] || continue
      _copy_file "$_f" "$_d"
    done
  else
    grep "^${_src}" "$MANIFEST" | while IFS= read -r _f; do
      [ -f "$_f" ] || {
        warn "Manifest entry missing on host: $_f"
        continue
      }
      _d="${CHROOT}${_f}"
      _copy_file "$_f" "$_d"
    done
  fi
}

# =============================================================================
# HELPERS
# =============================================================================

# _copy_tree and _copy_file are defined in the MANIFEST section above.

# _verify_tree SRC DST LABEL
# Fast manifest diff using stripped relative paths and grep -vFxf.
# Reports: missing files, extra files (drift/injection), XS .so byte diff.
_verify_tree() {
  local _src="$1" _dst="$2" _label="$3"
  local _tmp_s _tmp_d _missing _extra _mc _ec

  if [ ! -d "$_dst" ]; then
    note_err "${_label}: not present in chroot at $_dst"
    return
  fi

  _tmp_s=$(mktemp /tmp/tn_vt_src.XXXXXX)
  _tmp_d=$(mktemp /tmp/tn_vt_dst.XXXXXX)

  find "$_src" -print | sed "s|^${_src}||" | sort > "$_tmp_s"
  find "$_dst" -print | sed "s|^${_dst}||" | sort > "$_tmp_d"

  _src_count=$(wc -l < "$_tmp_s" | tr -d ' ')
  _dst_count=$(wc -l < "$_tmp_d" | tr -d ' ')
  info "${_label} -- source: ${_src_count} paths  chroot: ${_dst_count} paths"

  # Missing from chroot
  _missing=$(grep -vFxf "$_tmp_d" "$_tmp_s" | grep -v '^$' || true)
  if [ -n "$_missing" ]; then
    _mc=$(echo "$_missing" | wc -l | tr -d ' ')
    note_err "${_label}: ${_mc} file(s) missing from chroot"
    echo "$_missing" | while IFS= read -r _f; do err "  Missing: $_f"; done
  else
    ok "${_label}: no missing files"
  fi

  # Extra in chroot (drift / possible injection)
  _extra=$(grep -vFxf "$_tmp_s" "$_tmp_d" | grep -v '^$' || true)
  if [ -n "$_extra" ]; then
    _ec=$(echo "$_extra" | wc -l | tr -d ' ')
    note_err "${_label}: ${_ec} unexpected file(s) in chroot not in source baseline"
    echo "$_extra" | while IFS= read -r _f; do warn "  Extra: $_f"; done
  else
    ok "${_label}: no unexpected files (no drift)"
  fi

  rm -f "$_tmp_s" "$_tmp_d"

  # Check all XS .so files are present. Byte differences are expected after
  # pkg_add patches (HMAC, DBD::SQLite, Crypt::* etc.) -- report as stale,
  # not as a security event.  Re-run setup to resync.
  find "$_src" -name "*.so" | while IFS= read -r _sorc; do
    _rel="${_sorc#${_src}/}"
    _sdst="${_dst}/${_rel}"
    if [ ! -f "$_sdst" ]; then
      note_err "${_label} XS missing in chroot: $_rel"
    elif ! cmp -s "$_sorc" "$_sdst" 2> /dev/null; then
      warn "${_label} XS stale (patched on host, re-run setup to sync): $_rel"
    fi
  done
  ok "${_label}: XS .so presence check complete"
}

# =============================================================================
# STATUS WRITERS
# =============================================================================
write_status_ok() {
  local _core_pm _core_xs _site_pm _site_xs
  _core_pm=$(find "$PERL5CORE_DST" -name "*.pm" 2> /dev/null | wc -l | tr -d ' ')
  _core_xs=$(find "$PERL5CORE_DST" -name "*.so" 2> /dev/null | wc -l | tr -d ' ')
  _site_pm=$(find "$PERL5SITE_DST" -name "*.pm" 2> /dev/null | wc -l | tr -d ' ')
  _site_xs=$(find "$PERL5SITE_DST" -name "*.so" 2> /dev/null | wc -l | tr -d ' ')
  cat > "$STATUS_OK" << EOF
TN_CHROOT_SETUP.sh completed successfully
Date       : $(date)
Arch       : ${PERL_ARCH}
Chroot     : ${CHROOT}
Core perl5 : ${_core_pm} .pm,  ${_core_xs} XS .so
site_perl  : ${_site_pm} .pm,  ${_site_xs} XS .so
Log        : ${LOGFILE}
EOF
  ok "Status written: ${STATUS_OK}"
}

write_status_fail() {
  cat > "$STATUS_FAIL" << EOF
TN_CHROOT_SETUP.sh FAILED
Date     : $(date)
Chroot   : ${CHROOT}
Errors   : ${ERRORS}
Reason   : $1
Log      : ${LOGFILE}
EOF
  err "Failure status written: ${STATUS_FAIL}"
}

trap 'write_status_fail "unexpected exit at line ${LINENO}"' EXIT

# =============================================================================
# STEP 0: Pre-flight
# =============================================================================
print_header "TN_CHROOT_SETUP.sh v4.2.0"
info "Log: $LOGFILE"
info "Arch: $PERL_ARCH"
[ "$VERIFY_ONLY" -eq 1 ] && info "Mode: VERIFY ONLY -- no changes will be made"
echo ""

if [ "$(id -u)" -ne 0 ]; then
  note_err "Must run as root: doas ksh $0"
  trap - EXIT
  exit 1
fi

# Idempotency guard (setup mode only)
if [ "$VERIFY_ONLY" -eq 0 ] && [ -f "$STATUS_OK" ]; then
  warn "Previous successful setup detected:"
  cat "$STATUS_OK"
  echo ""
  printf "  ${MAGENTA}Re-run anyway? [y/N]: ${NC}"
  read -r _ans < /dev/tty
  case "$_ans" in
    [Yy]*) info "Re-running by operator request." ;;
    *)
      info "Already completed. Use --verify to check state."
      trap - EXIT
      exit 0
      ;;
  esac
fi

[ "$VERIFY_ONLY" -eq 0 ] && rm -f "$STATUS_OK" "$STATUS_FAIL"

# Manifest state determination
# Both files present → verify integrity before proceeding (re-run path)
# Neither present    → first run, will build baseline
# One missing        → inconsistent state, refuse to proceed
if [ "$VERIFY_ONLY" -eq 0 ]; then
  if [ -f "$MANIFEST" ] && [ -f "$MANIFEST_SHA" ]; then
    if ! _manifest_verify; then
      trap - EXIT
      exit 1
    fi
    _MANIFEST_FIRST_RUN=0
  elif [ ! -f "$MANIFEST" ] && [ ! -f "$MANIFEST_SHA" ]; then
    info "First run -- will copy from pristine host and seal manifest"
    _MANIFEST_FIRST_RUN=1
  else
    # One exists without the other -- inconsistent, refuse
    err "Manifest state is inconsistent:"
    [ -f "$MANIFEST" ] && err "  Present : ${MANIFEST}" \
      || err "  Missing : ${MANIFEST}"
    [ -f "$MANIFEST_SHA" ] && err "  Present : ${MANIFEST_SHA}" \
      || err "  Missing : ${MANIFEST_SHA}"
    err "Delete both files and re-run on a clean host to rebuild the baseline."
    trap - EXIT
    exit 1
  fi
fi

# Validate source trees and perl binary
for _src in "$PERL5CORE_SRC" "$PERL5SITE_SRC"; do
  if [ ! -d "$_src" ]; then
    note_err "Source tree not found: $_src"
  else
    ok "Source tree: $_src"
  fi
done

[ ! -x "$PERL_BIN" ] && note_err "Perl binary not found: $PERL_BIN" \
  || ok "Perl binary: $PERL_BIN"

[ "$ERRORS" -gt 0 ] && {
  trap - EXIT
  exit 1
}

# Detect shared library versions dynamically -- never hardcode .so versions
print_section "Detecting shared library versions"

_detect_lib() {
  local _var="$1" _glob="$2" _found
  _found=$(ls $_glob 2> /dev/null | head -1 | xargs basename 2> /dev/null || true)
  if [ -z "$_found" ]; then
    note_err "Could not detect library: $_glob"
    return 1
  fi
  eval "${_var}='${_found}'"
  ok "${_var}: ${_found}"
}

_detect_lib LIBPERL "/usr/lib/libperl.so.*.*"
_detect_lib LIBC "/usr/lib/libc.so.*.*"
_detect_lib LIBM "/usr/lib/libm.so.*.*"
_detect_lib LIBPTHREAD "/usr/lib/libpthread.so.*.*"
_detect_lib LIBUTIL "/usr/lib/libutil.so.*.*"
_detect_lib LIBZ "/usr/lib/libz.so.*.*"
_detect_lib LIBSQLITE "/usr/local/lib/libsqlite3.so.*.*"

[ "$ERRORS" -gt 0 ] && {
  trap - EXIT
  exit 1
}

# =============================================================================
# STEP 1: Binaries
# =============================================================================
print_header "Step 1: Binaries"

_install_bin() {
  local _src="$1" _dst="${CHROOT}${1}"
  if [ "$VERIFY_ONLY" -eq 1 ]; then
    [ -f "$_dst" ] \
      && ok "Present: $1" \
      || note_err "Missing from chroot: $1"
    return
  fi
  _copy_file "$_src" "$_dst" && ok "Copied/up to date: $1"
}

if [ "${_MANIFEST_FIRST_RUN:-0}" -eq 0 ] && [ "$VERIFY_ONLY" -eq 0 ]; then
  info "Re-run: refreshing binaries listed in manifest"
fi

for _b in \
  /bin/sh \
  /bin/cat \
  /usr/bin/perl \
  /usr/bin/ldd \
  /usr/bin/tail \
  /usr/libexec/ld.so \
  /bin/date; do
  _install_bin "$_b"
done

# =============================================================================
# STEP 2: Core Perl Library  (/usr/libdata/perl5)
# =============================================================================
print_header "Step 2: Core Perl Library (/usr/libdata/perl5)"
# Contains: strict, warnings, Carp, POSIX, Fcntl, File::*, Scalar::Util,
# List::Util, Encode, Time::*, Data::Dumper, CGI, and the full
# {PERL_ARCH}-specific XS subtree (POSIX.so, Fcntl.so, etc.).
# No exclusions -- this is base OS only, no package modules live here.

if [ "$VERIFY_ONLY" -eq 1 ]; then
  _verify_tree "$PERL5CORE_SRC" "$PERL5CORE_DST" "core perl5"
else
  print_section "Copying /usr/libdata/perl5 (incremental)"
  mkdir -p "${CHROOT}/usr/libdata"
  _copy_tree "$PERL5CORE_SRC" "$PERL5CORE_DST"
  _core_pm=$(find "$PERL5CORE_DST" -name "*.pm" 2> /dev/null | wc -l | tr -d ' ')
  _core_xs=$(find "$PERL5CORE_DST" -name "*.so" 2> /dev/null | wc -l | tr -d ' ')
  ok "Core perl5 complete: ${_core_pm} .pm,  ${_core_xs} XS .so"
fi

# =============================================================================
# STEP 3: site_perl  (/usr/local/libdata/perl5)
# =============================================================================
print_header "Step 3: site_perl (/usr/local/libdata/perl5)"
# site_perl is copied from an allowlist generated by TN_PERL_TRACER.pl,
# which runs automatically at the start of this step. It scans the live
# /var/www/htdocs/tn/cgi-bin against the host perl installation (populated
# by TN_PKG_INSTALL.sh) and produces tn_perl_allowlist.txt containing only
# the top-level module names actually needed by CGI scripts and their
# transitive dependencies. This replaces the previous denylist approach
# which excluded Collectd/RRDs/Net::Oping but still pulled in SpamAssassin
# and its ~6K file dependency tree.

_ALLOWLIST="${SCRIPT_DIR}/tn_perl_allowlist.txt"
_TRACER="${SCRIPT_DIR}/TN_PERL_TRACER.pl"

# Run the tracer unconditionally -- it scans /var/www/htdocs/tn/cgi-bin
# against the live host perl installation (which TN_PKG_INSTALL.sh just
# populated) and writes a fresh tn_perl_allowlist.txt. This ensures the
# allowlist always reflects what is actually installed, not a stale
# committed file that may have drifted from the current CGI set.
if [ ! -f "$_TRACER" ]; then
  die "TN_PERL_TRACER.pl not found at: $_TRACER"
fi

info "Running TN_PERL_TRACER.pl to generate allowlist..."
# ksh does not support PIPESTATUS -- capture exit code via a temp file
"$PERL_BIN" "$_TRACER" /var/www/htdocs/tn/cgi-bin /var/www/htdocs/tn/data/lib 2>&1 | tee -a "$LOGFILE"
# tee always exits 0; rerun a quick check via the allowlist existence test below

if [ ! -f "$_ALLOWLIST" ]; then
  die "TN_PERL_TRACER.pl ran but did not produce $_ALLOWLIST"
fi

ok "Allowlist generated: $_ALLOWLIST"
info "Allowlist entries: $(wc -l < "$_ALLOWLIST" | tr -d ' ')"

_tmp_site_list=$(mktemp /tmp/tn_perl5_site.XXXXXX)

# Build file list from allowlist — only copy trees that CGI scripts actually use
while IFS= read -r _top; do
  [ -z "$_top" ] && continue
  # Pure-perl top-level dir e.g. site_perl/CGI/
  _pm_dir="${PERL5SITE_SRC}/site_perl/${_top}"
  [ -d "$_pm_dir" ] && find "$_pm_dir" -print >> "$_tmp_site_list"
  _arch_dir="${PERL5SITE_SRC}/site_perl/${PERL_ARCH}/${_top}"
  [ -d "$_arch_dir" ] && find "$_arch_dir" -print >> "$_tmp_site_list"
  _arch_pm="${PERL5SITE_SRC}/site_perl/${PERL_ARCH}/${_top}.pm"
  [ -f "$_arch_pm" ] && echo "$_arch_pm" >> "$_tmp_site_list"
  _so_dir="${PERL5SITE_SRC}/site_perl/${PERL_ARCH}/auto/${_top}"
  [ -d "$_so_dir" ] && find "$_so_dir" -print >> "$_tmp_site_list"
  # Pure-perl single-file e.g. site_perl/CGI.pm
  _top_pm="${PERL5SITE_SRC}/site_perl/${_top}.pm"
  [ -f "$_top_pm" ] && echo "$_top_pm" >> "$_tmp_site_list"
done < "$_ALLOWLIST"

sort -u "$_tmp_site_list" -o "$_tmp_site_list"

_site_total=$(wc -l < "$_tmp_site_list" | tr -d ' ')
_site_pm=$(grep -c '\.pm$' "$_tmp_site_list" 2> /dev/null || true)
_site_xs=$(grep -c '\.so$' "$_tmp_site_list" 2> /dev/null || true)

info "Allowlist-filtered source: ${_site_total} paths  (${_site_pm} .pm,  ${_site_xs} XS .so)"

if [ "$VERIFY_ONLY" -eq 1 ]; then
  _verify_tree "$PERL5SITE_SRC" "$PERL5SITE_DST" "site_perl"
elif [ "${_MANIFEST_FIRST_RUN:-0}" -eq 0 ]; then
  # Re-run: _copy_tree reads the manifest -- find never runs on host
  print_section "Copying site_perl (from manifest)"
  mkdir -p "${CHROOT}/usr/local/libdata"
  _copy_tree "$PERL5SITE_SRC" "$PERL5SITE_DST"
  _site_pm_done=$(find "$PERL5SITE_DST" -name "*.pm" 2> /dev/null | wc -l | tr -d ' ')
  _site_xs_done=$(find "$PERL5SITE_DST" -name "*.so" 2> /dev/null | wc -l | tr -d ' ')
  ok "site_perl complete: ${_site_pm_done} .pm,  ${_site_xs_done} XS .so"
else
  # First run: walk host with find + exclusion filter, record to manifest via _copy_file
  print_section "Copying site_perl (first run, filtered find)"
  mkdir -p "${CHROOT}/usr/local/libdata"

  while IFS= read -r _src; do
    _rel="${_src#${PERL5SITE_SRC}}"
    _dst="${PERL5SITE_DST}${_rel}"

    if [ -d "$_src" ]; then
      [ -d "$_dst" ] || mkdir -p "$_dst"
      continue
    fi

    [ -f "$_src" ] || continue
    _copy_file "$_src" "$_dst"
  done < "$_tmp_site_list"

  rm -f "$_tmp_site_list"

  _site_pm_done=$(find "$PERL5SITE_DST" -name "*.pm" 2> /dev/null | wc -l | tr -d ' ')
  _site_xs_done=$(find "$PERL5SITE_DST" -name "*.so" 2> /dev/null | wc -l | tr -d ' ')
  ok "site_perl complete: ${_site_pm_done} .pm,  ${_site_xs_done} XS .so"
fi

# =============================================================================
# STEP 4: Shared Libraries
# =============================================================================
print_header "Step 4: Shared Libraries"
# ldd is run against:
#   - the perl binary itself
#   - all XS .so from core perl5  (POSIX.so, Fcntl.so, Encode.so ...)
#   - all XS .so from site_perl   (DBI.so, JSON/XS.so, Digest/SHA.so ...)
#
# IMPORTANT: site_perl XS .so files are read from PERL5SITE_DST (the
# already-filtered chroot copy), not from PERL5SITE_SRC. This guarantees
# that collectd-excluded modules cannot contribute any libraries to the
# ldd pass and therefore cannot pull librrd/libcairo/liboping into the chroot.

print_section "Building shared library list"

_tmp_ldd=$(mktemp /tmp/tn_ldd_raw.XXXXXX)
_tmp_needed=$(mktemp /tmp/tn_ldd_needed.XXXXXX)

if [ "$VERIFY_ONLY" -eq 1 ] || [ "${_MANIFEST_FIRST_RUN:-0}" -eq 1 ]; then
  # First run or verify: derive needed libs via ldd
  ldd "$PERL_BIN" >> "$_tmp_ldd" 2> /dev/null || true

  find "$PERL5CORE_SRC" -name "*.so" | while IFS= read -r _xs; do
    ldd "$_xs" >> "$_tmp_ldd" 2> /dev/null || true
  done

  [ -d "$PERL5SITE_DST" ] \
    && find "$PERL5SITE_DST" -name "*.so" | while IFS= read -r _xs; do
      ldd "$_xs" >> "$_tmp_ldd" 2> /dev/null || true
    done

  # Parse OpenBSD ldd format: path is always $NF; keep only lib dirs
  awk '
    $NF ~ "^/usr/lib/" || $NF ~ "^/usr/local/lib/" { print $NF }
  ' "$_tmp_ldd" | sort -u > "$_tmp_needed"

else
  # Re-run: extract lib host paths directly from manifest -- ldd never runs
  info "Re-run: reading shared library list from manifest"
  grep -E "^/usr/(local/)?lib/lib[^/]+\.so\.[0-9]" "$MANIFEST" \
    | sort -u > "$_tmp_needed"
fi

rm -f "$_tmp_ldd"

_needed=$(wc -l < "$_tmp_needed" | tr -d ' ')
info "Unique shared libraries: ${_needed}"
while IFS= read -r _sopath; do
  [ -z "$_sopath" ] && continue
  info "  Need: $_sopath"
done < "$_tmp_needed"

print_section "Copying / verifying shared libraries"

_lib_copied=0
_lib_skipped=0
_lib_missing=0

while IFS= read -r _sopath; do
  [ -z "$_sopath" ] && continue

  _sofile=$(basename "$_sopath")
  _sodir=$(dirname "$_sopath")

  case "$_sodir" in
    /usr/lib) _dst_dir="${CHROOT}/usr/lib" ;;
    /usr/local/lib) _dst_dir="${CHROOT}/usr/local/lib" ;;
    *) _dst_dir="${CHROOT}${_sodir}" ;;
  esac

  _dst="${_dst_dir}/${_sofile}"

  if [ ! -f "$_sopath" ]; then
    note_err "Source not found on host: $_sopath"
    _lib_missing=$((_lib_missing + 1))
    continue
  fi

  if [ "$VERIFY_ONLY" -eq 1 ]; then
    if [ ! -f "$_dst" ]; then
      note_err "Missing in chroot: $_sofile"
      _lib_missing=$((_lib_missing + 1))
    elif ! cmp -s "$_sopath" "$_dst" 2> /dev/null; then
      warn "Stale in chroot (patched on host, re-run setup to sync): $_sofile"
    else
      ok "OK: $_sofile"
      _lib_skipped=$((_lib_skipped + 1))
    fi
    continue
  fi

  [ -d "$_dst_dir" ] || mkdir -p "$_dst_dir"
  _copy_file "$_sopath" "$_dst"
  ok "Copied/up to date: $_sofile"
  _lib_copied=$((_lib_copied + 1))

  # Versioned symlinks: libfoo.so.X.Y --> libfoo.so.X --> libfoo.so
  _base1=$(echo "$_sofile" | sed 's/\.[0-9]*$//')
  _base2=$(echo "$_base1" | sed 's/\.[0-9]*$//')
  [ "$_base1" != "$_sofile" ] \
    && ln -sf "$_sofile" "${_dst_dir}/${_base1}" \
    && info "  Symlink: ${_base1} --> $_sofile"
  [ "$_base2" != "$_base1" ] && [ "$_base2" != "$_sofile" ] \
    && ln -sf "$_sofile" "${_dst_dir}/${_base2}" \
    && info "  Symlink: ${_base2} --> $_sofile"

done < "$_tmp_needed"

rm -f "$_tmp_needed"

[ "$VERIFY_ONLY" -eq 0 ] \
  && ok "Shared libs: ${_lib_copied} copied/updated, ${_lib_missing} missing"

# =============================================================================
# STEP 4a: Regenerate ld.so.hints inside chroot
# =============================================================================
print_header "Step 4a: Dynamic Linker Hints (ld.so.hints)"
# Without a valid /var/run/ld.so.hints inside the chroot, ld.so cannot
# locate shared libraries and XS modules (e.g. DBD::SQLite.so) fail to load
# even when the .so files are physically present.  ldconfig(8) reads the lib
# dirs we just populated and writes the hints file the dynamic linker needs.

if [ "$VERIFY_ONLY" -eq 1 ]; then
  if [ -f "${CHROOT}/var/run/ld.so.hints" ]; then
    ok "ld.so.hints present in chroot"
  else
    note_err "ld.so.hints missing from chroot (${CHROOT}/var/run/ld.so.hints)"
    note_err "  Fix: re-run setup (or run ldconfig -m manually inside chroot)"
  fi
else
  mkdir -p "${CHROOT}/var/run"
  if chroot "${CHROOT}" /sbin/ldconfig -m /usr/lib /usr/local/lib 2> /dev/null; then
    ok "ldconfig ran inside chroot -- ld.so.hints updated"
  else
    warn "ldconfig not available inside chroot -- copying host ld.so.hints"
    if [ -f /var/run/ld.so.hints ]; then
      cp /var/run/ld.so.hints "${CHROOT}/var/run/ld.so.hints"
      ok "Host ld.so.hints copied to chroot"
    else
      note_err "Host /var/run/ld.so.hints not found -- XS modules will fail to load"
    fi
  fi
fi

# =============================================================================
# STEP 5: Timezone
# =============================================================================
print_header "Step 5: Timezone"

[ "$VERIFY_ONLY" -eq 0 ] && mkdir -p "${CHROOT}/etc"

_tz_src=$(readlink /etc/localtime 2> /dev/null || echo /etc/localtime)
_tz_dst="${CHROOT}/etc/localtime"

if [ "$VERIFY_ONLY" -eq 1 ]; then
  if [ ! -f "$_tz_dst" ]; then
    note_err "Timezone missing from chroot"
  elif ! cmp -s "$_tz_src" "$_tz_dst" 2> /dev/null; then
    note_err "Timezone differs from host (re-run setup after timezone change)"
  else
    ok "Timezone up to date"
  fi
else
  if [ ! -f "$_tz_dst" ] || ! cmp -s "$_tz_src" "$_tz_dst" 2> /dev/null; then
    cp "$_tz_src" "$_tz_dst" && ok "Timezone copied: $_tz_dst"
  else
    ok "Timezone up to date"
  fi
fi

# =============================================================================
# STEP 6: Device Nodes
# =============================================================================
print_header "Step 6: Device Nodes"
# major/minor numbers are fixed across all OpenBSD systems:
#   null: c 2 2    random: c 45 0    urandom: c 45 2
# Without /dev/urandom the chroot has no entropy source -- HMAC key
# generation, Digest::SHA, and all OpenSSL operations will fail silently.

[ "$VERIFY_ONLY" -eq 0 ] && mkdir -p "${CHROOT}/dev"

for _spec in \
  "null:c:2:2:0666" \
  "random:c:45:0:0644" \
  "urandom:c:45:2:0644"; do
  _dev=$(echo "$_spec" | cut -d: -f1)
  _type=$(echo "$_spec" | cut -d: -f2)
  _maj=$(echo "$_spec" | cut -d: -f3)
  _min=$(echo "$_spec" | cut -d: -f4)
  _mode=$(echo "$_spec" | cut -d: -f5)
  _path="${CHROOT}/dev/${_dev}"

  if [ -c "$_path" ]; then
    ok "/dev/${_dev} present"
  elif [ "$VERIFY_ONLY" -eq 1 ]; then
    note_err "/dev/${_dev} missing -- crypto operations will fail"
  else
    mknod -m "$_mode" "$_path" "$_type" "$_maj" "$_min" \
      && ok "/dev/${_dev} created" \
      || note_err "/dev/${_dev} mknod failed"
  fi
done

# =============================================================================
# STEP 7: Runtime Directories
# =============================================================================
print_header "Step 7: Runtime Directories"

# Format: absolute_path:owner:group:mode
_DIRS="
${CHROOT}/tmp:root:wheel:1777
${DATA_DIR}/run:www:www:750
${DATA_DIR}/run/session:www:www:750
${DATA_DIR}/run/webui:www:www:750
${DATA_DIR}/session:www:www:750
${DATA_DIR}/tmp:www:www:750
${DATA_DIR}/queue:www:www:750
${DATA_DIR}/sockets:www:www:750
${DATA_DIR}/db:www:www:750
${DATA_DIR}/keys:root:www:750
${DATA_DIR}/logs:www:www:755
${DATA_DIR}/logs/waf:www:www:755
${DATA_DIR}/logs/csp:www:www:755
${DATA_DIR}/logs/httpd:www:www:755
"

echo "$_DIRS" | while IFS=: read -r _path _owner _group _mode; do
  [ -z "$_path" ] && continue
  _label=$(echo "$_path" | sed "s|${CHROOT}||")

  if [ "$VERIFY_ONLY" -eq 1 ]; then
    if [ ! -d "$_path" ]; then
      note_err "Missing directory: ${_label}"
    else
      _am=$(stat -f "%Lp" "$_path")
      _ao=$(stat -f "%Su:%Sg" "$_path")
      [ "$_am" = "$_mode" ] && [ "$_ao" = "${_owner}:${_group}" ] \
        && ok "${_label} (${_mode} ${_owner}:${_group})" \
        || note_err "${_label} wrong: got ${_am} ${_ao}, need ${_mode} ${_owner}:${_group}"
    fi
  else
    install -d -o "$_owner" -g "$_group" -m "$_mode" "$_path"
    ok "${_label} (${_mode} ${_owner}:${_group})"
  fi
done

# =============================================================================
# STEP 8: File Permissions
# =============================================================================
print_header "Step 8: File Permissions"

print_section "CGI scripts"
for _script in router.pl control.pl; do
  _path="${APP_ROOT}/cgi-bin/${_script}"
  if [ ! -f "$_path" ]; then
    info "$_script not yet deployed -- skipping"
    continue
  fi
  [ "$VERIFY_ONLY" -eq 0 ] && chmod 755 "$_path"
  _p=$(stat -f "%Lp" "$_path")
  [ "$_p" = "755" ] \
    && ok "$_script (755)" \
    || note_err "$_script: got $_p, need 755"
done

print_section "Config file"
_conf="${DATA_DIR}/config/security.conf"
if [ -f "$_conf" ]; then
  if [ "$VERIFY_ONLY" -eq 0 ]; then
    chown root:www "$_conf"
    chmod 640 "$_conf"
  fi
  _p=$(stat -f "%Lp" "$_conf")
  _o=$(stat -f "%Su:%Sg" "$_conf")
  [ "$_p" = "640" ] && [ "$_o" = "root:www" ] \
    && ok "security.conf (640 root:www)" \
    || note_err "security.conf: got $_p $_o, need 640 root:www"
else
  info "security.conf not yet present -- skipping"
fi

print_section "Maintenance scripts"
if [ -d "$SCRIPTS_DIR" ]; then
  [ "$VERIFY_ONLY" -eq 0 ] && chmod 700 "$SCRIPTS_DIR"/*.pl 2> /dev/null || true
  ok "data/scripts/*.pl set to 700"
fi

# =============================================================================
# STEP 9: Session Keys
# =============================================================================
print_header "Step 9: Session Keys"

_run_sess="${DATA_DIR}/run/session"
_keys_dir="${DATA_DIR}/keys"

for _keyfile in session.key hmac.key; do
  _src="${_run_sess}/${_keyfile}"
  _dst="${_keys_dir}/${_keyfile}"

  # run/session copy
  if [ -f "$_src" ]; then
    if [ "$VERIFY_ONLY" -eq 0 ]; then
      chown root:www "$_src"
      chmod 0440 "$_src"
    fi
    _p=$(stat -f "%Lp" "$_src")
    _o=$(stat -f "%Su:%Sg" "$_src")
    [ "$_p" = "440" ] && [ "$_o" = "root:www" ] \
      && ok "$_keyfile in run/session (0440 root:www)" \
      || note_err "$_keyfile in run/session: got $_p $_o, need 0440 root:www"
  else
    info "$_keyfile not in run/session -- run tn-init-db.pl first"
  fi

  # keys/ copy
  if [ -f "$_dst" ]; then
    if [ "$VERIFY_ONLY" -eq 0 ]; then
      chown root:www "$_dst"
      chmod 0440 "$_dst"
    fi
    _p=$(stat -f "%Lp" "$_dst")
    _o=$(stat -f "%Su:%Sg" "$_dst")
    [ "$_p" = "440" ] && [ "$_o" = "root:www" ] \
      && ok "$_keyfile in data/keys (0440 root:www)" \
      || note_err "$_keyfile in data/keys: got $_p $_o, need 0440 root:www"
  elif [ -f "$_src" ] && [ "$VERIFY_ONLY" -eq 0 ]; then
    cp "$_src" "$_dst"
    chown root:www "$_dst"
    chmod 0440 "$_dst"
    ok "$_keyfile copied to data/keys"
  else
    info "$_keyfile not in data/keys -- populated after tn-init-db.pl"
  fi
done

# =============================================================================
# STEP 10: Perl Module Load Test (inside chroot)
# =============================================================================
print_header "Step 10: Perl Module Load Test"
# Uses chroot(8) directly to test the actual chroot filesystem layout.
# Covers all modules confirmed by check_deps.pl as required by the WebUI.

if [ ! -x "${CHROOT}/usr/bin/perl" ]; then
  warn "Skipping: ${CHROOT}/usr/bin/perl not present (Step 1 may have failed)"
else
  _result=$(chroot "$CHROOT" /usr/bin/perl -e \
    'use strict;
     use warnings;
     use CGI;
     use Cwd;
     use Crypt::PBKDF2;
     use DBD::SQLite;
     use DBI;
     use Data::Dumper;
     use Digest::SHA;
     use Fcntl;
     use File::Basename;
     use File::Copy;
     use File::Path;
     use Getopt::Long;
     use JSON;
     use JSON::PP ();
     use JSON::XS;
     use List::Util;
     use MIME::Base64;
     use POSIX;
     use Scalar::Util;
     use Time::HiRes;
     use Time::Local;
     print "OK"' 2>&1 || true)

  if [ "$_result" = "OK" ]; then
    ok "All WebUI modules load correctly inside chroot"
  else
    note_err "Module load test failed:"
    echo "$_result" | while IFS= read -r _line; do
      err "  $_line"
    done
  fi
fi

# =============================================================================
# STEP 11: TNAudit and TNWatch Initialisation
# =============================================================================
# Initialise monitoring system databases and establish baselines.
# This runs after all chroot files are in place -- cron jobs will start
# monitoring immediately after reboot.
#
# TNAudit:  File integrity monitoring baseline
# TNWatch:  Log event database priming and email verification
# =============================================================================
print_header "Step 11: TNAudit and TNWatch Initialisation"

print_section "TNAudit"
if [ ! -x /usr/local/sbin/TNAudit.pl ]; then
  warn "TNAudit.pl not found -- run TNAudit.pl --init-db and --create-baseline manually after install"
elif [ "$VERIFY_ONLY" -eq 1 ]; then
  # In verify mode, just check if baseline exists
  if /usr/local/sbin/TNAudit.pl --status --json > /dev/null 2>&1; then
    ok "TNAudit baseline present"
  else
    note_err "TNAudit not initialised -- run --init-db and --create-baseline"
  fi
else
  # Initialise or migrate the database schema
  if /usr/local/sbin/TNAudit.pl --init-db 2>&1; then
    ok "TNAudit database initialised"
  else
    note_err "TNAudit --init-db failed"
  fi

  # Take the initial file integrity baseline against the freshly
  # deployed system -- this is the known-good snapshot all future
  # audits compare against
  if /usr/local/sbin/TNAudit.pl --create-baseline 2>&1; then
    ok "TNAudit baseline recorded"
  else
    note_err "TNAudit --create-baseline failed"
  fi

  # Display status to verify the baseline was captured correctly
  if /usr/local/sbin/TNAudit.pl --status --json | jq . 2>&1; then
    ok "TNAudit status verified"
  else
    note_err "TNAudit --status check failed"
  fi
fi

print_section "TNWatch"
if [ ! -x /usr/local/sbin/TNWatch.pl ]; then
  warn "TNWatch.pl not found -- run TNWatch.pl --init-db manually after install"
elif [ "$VERIFY_ONLY" -eq 1 ]; then
  # In verify mode, just check if database exists
  if /usr/local/sbin/TNWatch.pl --status > /dev/null 2>&1; then
    ok "TNWatch database present"
  else
    note_err "TNWatch not initialised -- run --init-db"
  fi
else
  # Initialise or migrate the database schema
  if /usr/local/sbin/TNWatch.pl --init-db 2>&1; then
    ok "TNWatch database initialised"
  else
    note_err "TNWatch --init-db failed"
  fi

  # Generate services.json by running monitor.pl
  # This populates the service state file that TNWatch needs to parse
  if /usr/local/sbin/monitor.pl 2>&1; then
    ok "services.json generated via monitor.pl"
  else
    warn "monitor.pl failed -- services.json may be incomplete"
  fi

  # Prime the parse offsets so cron does not flood the DB with
  # historical log data on first run
  if /usr/local/sbin/TNWatch.pl --parse-all 2>&1; then
    ok "TNWatch initial parse complete"
  else
    note_err "TNWatch --parse-all failed"
  fi

  # Verify email notification mechanism is working
  if /usr/local/sbin/TNWatch.pl --test-email 2>&1; then
    ok "TNWatch email test sent"
  else
    note_err "TNWatch --test-email failed"
  fi
fi

# =============================================================================
# STEP 12: LIVE ENDPOINT TEST
# Hit the CSRF endpoint as a final end-to-end validation:
#   host -> httpd -> slowcgi -> chroot -> perl -> TN modules -> HMAC key
# Reads INT_IP4 from /etc/tn-interfaces (same source of truth as everything
# else). Token is obfuscated in output -- first 8 chars shown, rest masked.
# =============================================================================

print_header "Step 12: Live Endpoint Test"

_int_ip4=""
if [ -f /etc/tn-interfaces ]; then
  _int_ip4=$(grep '^INT_IP4=' /etc/tn-interfaces | cut -d'"' -f2)
fi

if [ -z "$_int_ip4" ]; then
  warn "INT_IP4 not found in /etc/tn-interfaces -- skipping live test"
else
  info "Testing CSRF endpoint at https://${_int_ip4}/cgi-bin/control.pl/api/csrf"
  _csrf_response=$(curl -sk --max-time 10 "https://${_int_ip4}/cgi-bin/control.pl/api/csrf" 2> /dev/null || true)

  if [ -z "$_csrf_response" ]; then
    note_err "Live endpoint test: no response from https://${_int_ip4}"
  else
    _csrf_success=$(printf '%s' "$_csrf_response" | grep -o '"success":[0-9]' | grep -o '[0-9]$' || true)
    _csrf_token=$(printf '%s' "$_csrf_response" | grep -o '"token":"[a-f0-9]*"' | cut -d'"' -f4 || true)

    if [ "$_csrf_success" = "1" ] && [ -n "$_csrf_token" ]; then
      # Obfuscate: show first 8 hex chars, mask the rest
      _token_head=$(printf '%s' "$_csrf_token" | cut -c1-8)
      _token_len=$(printf '%s' "$_csrf_token" | wc -c | tr -d ' ')
      _token_tail_len=$((_token_len - 8))
      _token_masked="${_token_head}$(printf '%*s' "$_token_tail_len" '' | tr ' ' '*')"
      ok "Live endpoint responding: CSRF token received [${_token_masked}]"
      ok "Full stack verified: httpd -> slowcgi -> chroot -> perl -> HMAC"
    else
      note_err "Live endpoint test: unexpected response: ${_csrf_response}"
    fi
  fi
fi

# =============================================================================
# POST-DEPLOYMENT INDEXING
# =============================================================================

print_header "Updating locate database"

if [ -x "/usr/libexec/locate.updatedb" ]; then
  _LOCATE_RC="/etc/locate.rc"
  _LOCATE_BAK="${_LOCATE_RC}.bak"
  _pruned=0

  if [ -f "$_LOCATE_RC" ] && ! grep -qF "$SCRIPT_DIR" "$_LOCATE_RC"; then
    cp "$_LOCATE_RC" "$_LOCATE_BAK" \
      && sed -i "s|^\(PRUNEPATHS=\".*\)\"|\1 ${SCRIPT_DIR}\"|" "$_LOCATE_RC" \
      && _pruned=1
  fi

  if /usr/libexec/locate.updatedb; then
    ok "locate database updated"
  else
    note_err "locate.updatedb failed"
  fi

  # Restore original regardless of outcome -- prune only needed during run
  [ "$_pruned" -eq 1 ] && mv "$_LOCATE_BAK" "$_LOCATE_RC"
else
  info "/usr/libexec/locate.updatedb not found -- skipping"
fi

# =============================================================================
# SUMMARY
# =============================================================================
print_header "Summary"
echo ""
printf "  Mode    : %s\n" \
  "$([ "$VERIFY_ONLY" -eq 1 ] && echo 'VERIFY' || echo 'SETUP')"
printf "  Errors  : %d\n" "$ERRORS"
printf "  Log     : %s\n" "$LOGFILE"
echo ""

if [ "$ERRORS" -eq 0 ]; then
  [ "$VERIFY_ONLY" -eq 1 ] \
    && printf "  ${GREEN}[OK]${NC}   Chroot environment verified successfully.\n\n" \
    || printf "  ${GREEN}[OK]${NC}   Chroot environment configured successfully.\n\n"
  if [ "$VERIFY_ONLY" -eq 0 ]; then
    if [ "${_MANIFEST_FIRST_RUN:-0}" -eq 1 ]; then
      _manifest_seal
    else
      _mc=$(wc -l < "$MANIFEST" | tr -d ' ')
      ok "Manifest used as gate (re-run): ${_mc} host paths"
    fi
    # Read LAN IP from tn-interfaces for post-install instructions
    _int_ip4=""
    [ -f /etc/tn-interfaces ] \
      && _int_ip4=$(grep '^INT_IP4=' /etc/tn-interfaces | cut -d'"' -f2)

    printf "\n"
    printf "  ============================================================\n"
    printf "  ${BOLD}Installation complete.${NC}\n"
    printf "  ============================================================\n"
    printf "\n"
    printf "  To register the web UI and access the dashboard, visit:\n"
    printf "\n"
    printf "    ${CYAN}https://${_int_ip4:-<LAN_IP>}/register.html${NC}\n"
    printf "\n"
    printf "  from a device on the LAN (${_int_ip4:-<LAN_IP>} network).\n"
    printf "\n"
    write_status_ok
  fi
  trap - EXIT
  exit 0
else
  printf "  ${RED}[FAIL]${NC} %d error(s) -- review output above and %s\n\n" \
    "$ERRORS" "$LOGFILE"
  [ "$VERIFY_ONLY" -eq 0 ] && write_status_fail "$ERRORS error(s) during setup"
  trap - EXIT
  exit 1
fi
