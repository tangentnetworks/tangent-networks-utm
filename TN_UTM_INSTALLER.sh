#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# =============================================================================
# TN_UTM_INSTALLER.sh -- Tangent Networks UTM Master Orchestrator
# =============================================================================
#
# AUTHOR:   Tangent Networks
# VERSION:  1.1.0
# PLATFORM: OpenBSD (pdksh / /bin/ksh)
#
# PURPOSE:
#   Top-level orchestrator for the Tangent Networks UTM installation sequence.
#   Stages 1, 2, 4 are dot-sourced in a subshell so interactive prompts reach
#   the terminal without any /dev/tty attachment (unreliable on OpenBSD ttyv).
#   Stage 3 is executed as a child process (see EXECUTION STRATEGY below).
#
# USAGE:
#   doas ksh TN_UTM_INSTALLER.sh
#
#   Must be run as root from the directory that contains all four child
#   scripts.  The installer will refuse to start otherwise.
#
# INSTALLATION SEQUENCE:
#   Stage 1 -- TN_NET_SET.sh
#              HAL probe, firmware update, WAN/LAN selection, subnet
#              assignment, MTU/MSS derivation, hostname files, connectivity
#              tests, SSL CA + server certificate generation, oinkcode.
#              Writes: /etc/tn-interfaces (single source of truth for all
#              subsequent stages), /etc/hostname.*, /etc/mygate.
#              Interactive: yes (24 stages of operator prompts).
#              Runner: run_stage_source (dot-sourced subshell)
#
#   [GUARD]  Operator reviews /etc/tn-interfaces before token expansion.
#
#   Stage 2 -- TN_SUBSTITUTE.sh
#              Expands all %%TOKEN%% placeholders in payload/ using values
#              from /etc/tn-interfaces.  Also sets live hostname, rebuilds
#              SRI hashes for web assets, and verifies no tokens remain.
#              Writes: payload/ files in-place; renames *.template files.
#              Interactive: no (--dry-run flag available for rehearsal).
#              Runner: run_stage_source (dot-sourced subshell)
#
#   Stage 3 -- TN_PKG_INSTALL.sh
#              syspatch, pkg_add (mirror + version-resolved + custom),
#              payload deploy (sbin, etc, webroot), config merges
#              (sysctl, logging, httpd, crontab), AuthDB initialisation,
#              service smoke tests for all UTM daemons, pf.conf deploy.
#              Writes: /usr/local/sbin/*, /etc/*, /var/www/htdocs/tn/*,
#                      /root/packages-setup (success sentinel).
#              Interactive: yes (phase_error retry prompts, DNS confirm,
#                               rollback choice on failure).
#              Runner: run_stage_exec (child process -- see below)
#
#   [GUARD]  Operator reviews smoke test results before chroot is built.
#
#   Stage 4 -- TN_CHROOT_SETUP.sh
#              Populates /var/www chroot with perl binary, core perl5 and
#              site_perl libraries (collectd XS excluded), shared libs via
#              ldd, ld.so.hints, timezone, device nodes, runtime dirs,
#              file permissions, session keys, and a live perl module test.
#              Writes: /var/www/usr/*, /var/www/dev/*, /var/www/etc/*,
#                      chroot-manifest.txt + chroot-manifest.sha256.
#              Interactive: yes (idempotency re-run confirmation).
#              Runner: run_stage_source (dot-sourced subshell)
#
# LOGGING:
#   Each child script writes its own operational log under logs/:
#     logs/network-setup.log   (TN_NET_SET.sh)
#     logs/substitute.log      (TN_SUBSTITUTE.sh)
#     logs/pkg-install.log     (TN_PKG_INSTALL.sh)
#     logs/chroot-setup.log    (TN_CHROOT_SETUP.sh)
#
#   This script logs orchestration events only (stage start/finish, guard
#   confirmations, abort reasons) to:
#     logs/utm_installer_<YYYYMMDD_HHMMSS>.log
#
# EXECUTION STRATEGY:
#   Two runners are used depending on each script's internal shell options.
#
#   run_stage_source -- dot-source inside a subshell
#     Used for: TN_NET_SET.sh, TN_SUBSTITUTE.sh, TN_CHROOT_SETUP.sh
#     These scripts use "set -e" only.  Dot-sourcing shares the parent's
#     stdin/stdout/stderr (no tty detachment) while the subshell boundary
#     isolates each script's trap registrations and set flags so they
#     cannot bleed into the next stage.
#     $0 inside a dot-sourced script resolves to the master's name, so
#     "cd $SCRIPT_DIR" is done before sourcing to keep all dirname-relative
#     path operations (logs/, payload/, packages/) correct.
#     exit 0/1 inside the sourced script terminates the subshell only;
#     the parent reads the exit code via $? as normal.
#
#   run_stage_exec -- execute as a child process via ksh
#     Used for: TN_PKG_INSTALL.sh only
#     TN_PKG_INSTALL.sh declares "set -uo pipefail" at the top.  If
#     dot-sourced, pipefail becomes active in the subshell and interacts
#     badly with the pkg_add | tee pipelines inside pkg_run(): the pipeline
#     exit code is evaluated under pipefail semantics, causing the subshell
#     to terminate silently mid-phase with no error message -- observed
#     symptom is output stopping after the last pkg_add line with no
#     subsequent smoke tests or chroot setup.
#     Running it as "ksh ./TN_PKG_INSTALL.sh" gives it a fully independent
#     process with its own pipefail scope.  stdin/stdout/stderr are still
#     inherited from the master so all interactive prompts (phase_error
#     retry, DNS confirm, rollback choice) reach the terminal normally.
#     The explicit "ksh" invocation also bypasses any +x permission issues.
#
# GUARDS:
#   Two operator confirmation pauses are placed after interactive stages:
#     After stage 1: /etc/tn-interfaces exists and can be reviewed before
#                    TN_SUBSTITUTE.sh consumes it for token expansion.
#     After stage 3: smoke test results are visible before the chroot
#                    is built from the freshly installed packages.
#   Guards are post-stage (not pre-stage) so there is always something
#   concrete for the operator to inspect before confirming.
#
# DEPENDENCIES:
#   All four child scripts must be present and readable in the same
#   directory as this script.  No other external tools are required by
#   the orchestrator itself.
#
# RESUMING A FAILED INSTALL:
#   This script has no checkpoint system of its own.  On failure, re-run
#   the specific child script directly from the same directory:
#     doas ksh TN_NET_SET.sh
#     doas ksh TN_SUBSTITUTE.sh
#     doas ksh TN_PKG_INSTALL.sh    (has its own phase checkpoint system)
#     doas ksh TN_CHROOT_SETUP.sh   (idempotent, safe to re-run)
#
#   TN_PERL_TRACER.pl is not run directly -- it is invoked automatically
#   by TN_CHROOT_SETUP.sh at Stage 4 Step 3.  It scans the live CGI tree
#   at /var/www/htdocs/tn/cgi-bin and generates tn_perl_allowlist.txt
#   which controls which site_perl modules are copied into the chroot.
#   Re-running TN_CHROOT_SETUP.sh alone will re-run the tracer.
#
# TOPOLOGY CONSTRAINT (v5.x / v6.x):
#   This installer targets the Dual-LAN, single-WAN UTM topology.
#   Multi-WAN, VLAN multi-tenancy, N+1 LAN scaling, and CARP/HA are
#   dormant in the child scripts and gated for release 8.0.
#
# =============================================================================

set -eu

SCRIPT_DIR=$(dirname "$0")
MASTER_LOG="${SCRIPT_DIR}/logs/utm_installer_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "${SCRIPT_DIR}/logs"

# =============================================================================
# LOGGING (orchestration events only)
# =============================================================================
log() {
    printf "[%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$MASTER_LOG"
}

die() {
    log "ABORT: $*"
    exit 1
}

# =============================================================================
# GUARD -- operator confirmation between stages
# Placed AFTER a stage completes so the operator can review its output
# before the next stage consumes it.
# =============================================================================
guard() {
    log "GUARD: $1"
    printf "\n>>> %s\n    Press Enter to continue or Ctrl-C to abort: " "$1"
    read _confirm_
    log "GUARD passed."
}

# =============================================================================
# run_stage_source -- dot-source in a subshell
# For scripts that use "set -e" only (stages 1, 2, 4).
# See EXECUTION STRATEGY in the header for full rationale.
# =============================================================================
run_stage_source() {
    local _num="$1" _label="$2" _script="$3"
    log "=== STAGE ${_num}: ${_label} (sourced) ==="
    local _path="${SCRIPT_DIR}/${_script}"
    [ -f "$_path" ] || die "${_script}: not found (${_path})"
    [ -r "$_path" ] || die "${_script}: not readable"
    (cd "$SCRIPT_DIR" && . "./${_script}")
    [ $? -eq 0 ] || die "${_script} failed -- halted at stage ${_num}"
    log "Stage ${_num} complete."
}

# =============================================================================
# run_stage_exec -- execute as a child process via ksh
# For TN_PKG_INSTALL.sh only, which uses "set -uo pipefail".
# See EXECUTION STRATEGY in the header for full rationale.
# =============================================================================
run_stage_exec() {
    local _num="$1" _label="$2" _script="$3"
    log "=== STAGE ${_num}: ${_label} (exec) ==="
    local _path="${SCRIPT_DIR}/${_script}"
    [ -f "$_path" ] || die "${_script}: not found (${_path})"
    [ -r "$_path" ] || die "${_script}: not readable"
    (cd "$SCRIPT_DIR" && ksh "./${_script}")
    [ $? -eq 0 ] || die "${_script} failed -- halted at stage ${_num}"
    log "Stage ${_num} complete."
}

# =============================================================================
# PRE-FLIGHT
# =============================================================================
log "TN_UTM_INSTALLER started."
log "Master log: ${MASTER_LOG}"

[ "$(id -u)" -ne 0 ] && die "Must run as root: doas ksh $0"
[ "$(uname -s)" = "OpenBSD" ] || die "OpenBSD only"

for _s in TN_NET_SET.sh TN_SUBSTITUTE.sh TN_PKG_INSTALL.sh TN_CHROOT_SETUP.sh; do
    [ -f "${SCRIPT_DIR}/${_s}" ] || die "Child script missing: ${_s}"
    [ -r "${SCRIPT_DIR}/${_s}" ] || die "Child script not readable: ${_s}"
done

# TN_PERL_TRACER.pl is invoked by TN_CHROOT_SETUP.sh at Stage 4 Step 3.
# Verify it is present now so a missing file is caught before Stage 1
# rather than failing four stages in.
[ -f "${SCRIPT_DIR}/TN_PERL_TRACER.pl" ] || die "TN_PERL_TRACER.pl: not found (required by TN_CHROOT_SETUP.sh Stage 4)"
[ -r "${SCRIPT_DIR}/TN_PERL_TRACER.pl" ] || die "TN_PERL_TRACER.pl: not readable"

log "Pre-flight passed. All child scripts and tools present."

# =============================================================================
# INSTALLATION SEQUENCE
# =============================================================================
run_stage_source 1 "Network configuration" TN_NET_SET.sh
guard "Network configured. Review /etc/tn-interfaces before token expansion."

run_stage_source 2 "Token substitution"    TN_SUBSTITUTE.sh

run_stage_exec   3 "Package installation"  TN_PKG_INSTALL.sh
guard "Packages installed. Review smoke test results before building chroot."

run_stage_exec	 4 "Chroot setup"          TN_CHROOT_SETUP.sh

_int_ip4=""
[ -f /etc/tn-interfaces ] && \
    _int_ip4=$(grep '^INT_IP4=' /etc/tn-interfaces | cut -d'"' -f2)

# Cert notice -- only if installation succeeded
if [ "${_install_exit:-0}" -eq 0 ]; then
    _tls_cert=""
    if [ -f /etc/httpd.conf ]; then
        _tls_cert=$(awk '/certificate/ { gsub(/"/, "", $2); print $2; exit }' /etc/httpd.conf)
    else
        [ -f /etc/tn-interfaces ] && \
            _tls_cert=$(grep '^TLS_CERT=' /etc/tn-interfaces | cut -d'"' -f2)
    fi
    _cert_basename=$(basename "${_tls_cert:-tan.localdomain.crt}")

    printf "\n"
    printf "  ============================================================\n"
    printf "  CA Certificate Installation\n"
    printf "  ============================================================\n"
    printf "\n"
    printf "  To trust the Tangent Networks CA on client devices, download\n"
    printf "  the certificate from:\n"
    printf "\n"
    printf "    http://%s/certs/%s\n" "${_int_ip4:-<LAN_IP>}" "$_cert_basename"
    printf "\n"
    printf "  On managed networks, deploy via GPO or MDM.\n"
    printf "  ============================================================\n"
    printf "\n"
fi

printf "\n"
printf "  ============================================================\n"
printf "  Installation complete.\n"
printf "  ============================================================\n"
printf "\n"
printf "  To register the web UI and access the dashboard, visit:\n"
printf "\n"
printf "    https://${_int_ip4:-<LAN_IP>}/register.html\n"
printf "\n"
printf "  from a device on the LAN (${_int_ip4:-<LAN_IP>} network).\n"
printf "\n"
log "All stages complete. Installation successful."
# =============================================================================
# DONE
# =============================================================================
log "All stages complete. Installation successful."
printf "\n  Installation complete.\n  Individual logs: %s/logs/\n  Master log:      %s\n\n" \
    "$SCRIPT_DIR" "$MASTER_LOG"
