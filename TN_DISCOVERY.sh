#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ============================================================================
# TN System Discovery - Map Actual File Locations
# ============================================================================
# Scans a working TN installation to discover:
#   1. Where files actually live (/etc vs /usr/local/etc)
#   2. What contains interface references
#   3. Directory structure reality
#   4. Package vs custom file ownership
#
# This eliminates guesswork and provides FACTS for payload organization.
#
# USAGE:
#   doas ksh 05_discover_system.sh [--source /path] [--output report.txt]
#
# AUTHOR: Tangent Networks
# VERSION: 1.1.0
# ============================================================================

set -e

VERSION="1.1.0"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SOURCE_ROOT="/"
OUTPUT_FILE="/tmp/tn_system_discovery_${TIMESTAMP}.txt"

# Colors (standard ANSI escape codes)
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

print_header() {
    echo ""
    printf "${BLUE}============================================================${NC}\n"
    printf "${BLUE}  %s${NC}\n" "$1"
    printf "${BLUE}============================================================${NC}\n"
}
ok()   { printf "  ${GREEN}[+]${NC} %s\n" "$1"; }
warn() { printf "  ${YELLOW}[!]${NC} %s\n" "$1"; }
info() { printf "  ${CYAN}[i]${NC} %s\n" "$1"; }
err()  { printf "  ${RED}[!]${NC} %s\n" "$1"; }

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --source)
            SOURCE_ROOT="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--source /path] [--output file.txt]"
            exit 1
            ;;
    esac
done

# ============================================================================
# Root / Privilege Check
# ============================================================================

if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root or with doas"
    info "Usage: doas ksh $(basename "$0")"
    info "Required to read all system files and run pkg_info"
    exit 1
fi
ok "Running with proper privileges"
echo ""

# ============================================================================
# Interface Configuration — Load First
# ============================================================================
# All grep patterns are derived from actual interface names here.
# Nothing is hardcoded. This must run before any scanning.

TN_INTERFACES="${SOURCE_ROOT}etc/tn-interfaces"

if [ -f "$TN_INTERFACES" ]; then
    # Source the file to get EXT_IF and INT_IF as shell variables
    # Strip any export keywords first for safe sourcing in ksh
    eval "$(grep -E '^(EXT_IF|INT_IF)=' "$TN_INTERFACES" | sed 's/^export //')"

    if [ -z "$EXT_IF" ] || [ -z "$INT_IF" ]; then
        err "/etc/tn-interfaces found but EXT_IF or INT_IF is empty"
        err "Check the file format — expected: EXT_IF=\"ifname\""
        exit 1
    fi
    ok "Loaded interfaces: EXT_IF=$EXT_IF  INT_IF=$INT_IF"
else
    # Attempt fallback detection from pf.conf
    warn "/etc/tn-interfaces not found — attempting fallback from pf.conf"
    PF_CONF="${SOURCE_ROOT}etc/pf.conf"
    if [ -f "$PF_CONF" ]; then
        EXT_IF=$(grep -E '^ext_if' "$PF_CONF" | head -1 | \
            sed 's/.*=[ \t]*"*\([a-z0-9]*\)"*.*/\1/')
        INT_IF=$(grep -E '^int_if' "$PF_CONF" | head -1 | \
            sed 's/.*=[ \t]*"*\([a-z0-9]*\)"*.*/\1/')
    fi

    if [ -z "$EXT_IF" ] || [ -z "$INT_IF" ]; then
        err "Could not determine EXT_IF / INT_IF from any source"
        err "Create /etc/tn-interfaces before running this script"
        exit 1
    fi
    warn "Fallback detected: EXT_IF=$EXT_IF  INT_IF=$INT_IF"
fi

# Build extended-regex pattern for grep -E
# Matches both live interface names AND template placeholders
IFACE_PATTERN="${EXT_IF}|${INT_IF}|%%EXT_IF%%|%%INT_IF%%"
ok "Interface grep pattern: $IFACE_PATTERN"
echo ""

# ============================================================================
# Utility Check — tree (no export -f, ksh-safe fallback)
# ============================================================================

_tree_is_fallback=0

if ! command -v tree >/dev/null 2>&1; then
    warn "'tree' not found"

    if [ -f /etc/openbsd-release ] && command -v pkg_add >/dev/null 2>&1; then
        info "OpenBSD detected — attempting automatic install..."

        if [ -z "$PKG_PATH" ]; then
            RELEASE=$(uname -r 2>/dev/null)
            ARCH=$(uname -m 2>/dev/null)
            if [ -n "$RELEASE" ] && [ -n "$ARCH" ]; then
                export PKG_PATH="https://cdn.openbsd.org/pub/OpenBSD/$RELEASE/packages/$ARCH/"
                info "Set PKG_PATH=$PKG_PATH"
            fi
        fi

        # Run pkg_add without set -e interference
        set +e
        pkg_add -I tree 2>/dev/null
        _pkg_rc=$?
        set -e

        if [ $_pkg_rc -eq 0 ] && command -v tree >/dev/null 2>&1; then
            ok "tree installed successfully"
        else
            warn "Automatic install failed — using fallback"
            _tree_is_fallback=1
        fi
    else
        warn "Not OpenBSD or no pkg_add — using fallback"
        _tree_is_fallback=1
    fi
fi

# ksh-safe fallback: named function, NOT export -f
do_tree() {
    _td="${1:-.}"
    _depth="${2:-99}"
    if [ "$_tree_is_fallback" -eq 1 ]; then
        find "$_td" -type d -maxdepth "$_depth" 2>/dev/null | sort | \
            sed "s|$_td||" | sed 's|[^/]*/|  |g'
    else
        tree -L "$_depth" -d "$_td" 2>/dev/null
    fi
}

# ============================================================================
# GDPR — Sanitize sensitive values before writing to report
# ============================================================================
# Oinkcode appears in snort/suricata rule URLs in config files.
# Replace it with [REDACTED] in all report output.
# Pattern: 32-char hex string typical of Snort oinkcode format.

sanitize() {
    sed 's/[0-9a-f]\{32\}/[REDACTED]/g' "$@"
}

print_header "TN System Discovery v${VERSION}"
echo ""
info "Scanning: $SOURCE_ROOT"
info "Output:   $OUTPUT_FILE"
echo ""

# Start report
cat > "$OUTPUT_FILE" << REPORT_HEADER
===========================================================
  TN SYSTEM DISCOVERY REPORT
===========================================================

Generated: $(date)
Source:    $SOURCE_ROOT
EXT_IF:    $EXT_IF
INT_IF:    $INT_IF

NOTE: Sensitive values (oinkcode etc.) are redacted in this report.

REPORT_HEADER

# ============================================================================
# Discovery 1: TN-Related Files in /etc
# ============================================================================
print_header "Discovery 1: Scanning /etc"

cat >> "$OUTPUT_FILE" << 'SECTION1'
===========================================================
SECTION 1: FILES IN /etc
===========================================================

SECTION1

info "Scanning ${SOURCE_ROOT}etc/ for TN files..."

set +e
find "${SOURCE_ROOT}etc" -type f \( \
    -name "*tangent*" -o \
    -name "*tn-*" -o \
    -name "TNAudit*" -o \
    -name "TNWatch*" -o \
    -name "pf.conf" -o \
    -name "rc.local" -o \
    -name "httpd.conf" -o \
    -name "sockd.conf" -o \
    -name "*e2guardian*" -o \
    -name "*snort*" -o \
    -name "*pmacct*" -o \
    -name "*clamav*" -o \
    -name "*collectd*" -o \
    -name "rad.conf" \
\) 2>/dev/null | sort | while read -r file; do
    rel_path=$(echo "$file" | sed "s|^${SOURCE_ROOT}||")
    size=$(ls -lh "$file" 2>/dev/null | awk '{print $5}')
    pkg_owner=$(pkg_info -E "$file" 2>/dev/null | head -1)
    [ -z "$pkg_owner" ] && pkg_owner="CUSTOM"

    if grep -qE "$IFACE_PATTERN" "$file" 2>/dev/null; then
        has_iface="[HAS-IFACE]"
    else
        has_iface=""
    fi

    {
        echo "  /$rel_path"
        echo "    Size:  $size"
        echo "    Owner: $pkg_owner"
        [ -n "$has_iface" ] && echo "    $has_iface"
        echo ""
    } | sanitize >> "$OUTPUT_FILE"
done
set -e

echo "" >> "$OUTPUT_FILE"
echo "DIRECTORIES IN /etc:" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

set +e
find "${SOURCE_ROOT}etc" -type d \( \
    -name "*tangent*" -o \
    -name "TNAudit" -o \
    -name "TNWatch" -o \
    -name "e2guardian" -o \
    -name "snort" -o \
    -name "pmacct" -o \
    -name "p3scan" -o \
    -name "pf" \
\) 2>/dev/null | sort | while read -r dir; do
    rel_path=$(echo "$dir" | sed "s|^${SOURCE_ROOT}||")
    file_count=$(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ')
    echo "  /$rel_path/ ($file_count files)" >> "$OUTPUT_FILE"
done
set -e

ok "Scanned /etc"

# ============================================================================
# Discovery 2: TN-Related Files in /usr/local/etc
# ============================================================================
print_header "Discovery 2: Scanning /usr/local/etc"

cat >> "$OUTPUT_FILE" << 'SECTION2'

===========================================================
SECTION 2: FILES IN /usr/local/etc
===========================================================

SECTION2

info "Scanning ${SOURCE_ROOT}usr/local/etc/ for TN files..."

if [ -d "${SOURCE_ROOT}usr/local/etc" ]; then
    set +e
    find "${SOURCE_ROOT}usr/local/etc" -type f 2>/dev/null | sort | while read -r file; do
        rel_path=$(echo "$file" | sed "s|^${SOURCE_ROOT}||")
        size=$(ls -lh "$file" 2>/dev/null | awk '{print $5}')
        pkg_owner=$(pkg_info -E "$file" 2>/dev/null | head -1)
        [ -z "$pkg_owner" ] && pkg_owner="CUSTOM"

        if grep -qE "$IFACE_PATTERN" "$file" 2>/dev/null; then
            has_iface="[HAS-IFACE]"
        else
            has_iface=""
        fi

        {
            echo "  /$rel_path"
            echo "    Size:  $size"
            echo "    Owner: $pkg_owner"
            [ -n "$has_iface" ] && echo "    $has_iface"
            echo ""
        } | sanitize >> "$OUTPUT_FILE"
    done
    set -e

    echo "" >> "$OUTPUT_FILE"
    echo "DIRECTORIES IN /usr/local/etc:" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    set +e
    find "${SOURCE_ROOT}usr/local/etc" -type d 2>/dev/null | \
        sed "s|^${SOURCE_ROOT}||" | sort | while read -r dir; do
        file_count=$(find "${SOURCE_ROOT}$dir" -type f 2>/dev/null | wc -l | tr -d ' ')
        echo "  /$dir/ ($file_count files)" >> "$OUTPUT_FILE"
    done
    set -e
fi

ok "Scanned /usr/local/etc"

# ============================================================================
# Discovery 3: TN Scripts in /usr/local/sbin
# ============================================================================
print_header "Discovery 3: Scanning /usr/local/sbin"

cat >> "$OUTPUT_FILE" << 'SECTION3'

===========================================================
SECTION 3: SCRIPTS IN /usr/local/sbin
===========================================================

SECTION3

info "Scanning ${SOURCE_ROOT}usr/local/sbin/ for TN scripts..."

if [ -d "${SOURCE_ROOT}usr/local/sbin" ]; then
    set +e
    find "${SOURCE_ROOT}usr/local/sbin" -type f \( -name "*.sh" -o -name "*.pl" \) 2>/dev/null | \
        sort | while read -r script; do
        basename_script=$(basename "$script")
        size=$(ls -lh "$script" 2>/dev/null | awk '{print $5}')

        if grep -qE "$IFACE_PATTERN" "$script" 2>/dev/null; then
            has_iface="[HAS-IFACE]"
        else
            has_iface=""
        fi

        echo "  $basename_script ($size) $has_iface" | sanitize >> "$OUTPUT_FILE"
    done
    set -e
fi

ok "Scanned /usr/local/sbin"

# ============================================================================
# Discovery 4: Web Application Structure
# ============================================================================
print_header "Discovery 4: Scanning /var/www/htdocs/tn"

cat >> "$OUTPUT_FILE" << 'SECTION4'

===========================================================
SECTION 4: WEB APPLICATION STRUCTURE
===========================================================

SECTION4

info "Scanning ${SOURCE_ROOT}var/www/htdocs/tn/ structure..."

if [ -d "${SOURCE_ROOT}var/www/htdocs/tn" ]; then
    echo "DIRECTORY STRUCTURE:" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    do_tree "${SOURCE_ROOT}var/www/htdocs/tn" 2 >> "$OUTPUT_FILE"

    echo "" >> "$OUTPUT_FILE"
    echo "FILES WITH INTERFACE REFERENCES:" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    set +e
    grep -rEl "$IFACE_PATTERN" \
        "${SOURCE_ROOT}var/www/htdocs/tn" 2>/dev/null | \
        sed "s|^${SOURCE_ROOT}var/www/htdocs/tn/||" | \
        while read -r file; do
            echo "  $file" >> "$OUTPUT_FILE"
        done
    set -e
fi

ok "Scanned web application"

# ============================================================================
# Discovery 5: Interface Detection
# ============================================================================
print_header "Discovery 5: Interface Detection"

cat >> "$OUTPUT_FILE" << 'SECTION5'

===========================================================
SECTION 5: INTERFACE CONFIGURATION
===========================================================

SECTION5

info "Recording interface configuration..."

if [ -f "$TN_INTERFACES" ]; then
    echo "CURRENT /etc/tn-interfaces:" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    sanitize "$TN_INTERFACES" | sed 's/^/  /' >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
fi

echo "DETECTED INTERFACES:" >> "$OUTPUT_FILE"
echo "  EXT_IF = $EXT_IF" >> "$OUTPUT_FILE"
echo "  INT_IF = $INT_IF" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

echo "AVAILABLE NETWORK INTERFACES:" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

if [ "$SOURCE_ROOT" = "/" ]; then
    ifconfig -a | grep "^[a-z]" | awk '{print "  " $1}' >> "$OUTPUT_FILE"
else
    echo "  (Cannot detect — not running on live system)" >> "$OUTPUT_FILE"
fi

ok "Recorded interfaces"

# ============================================================================
# Discovery 6: Package vs Custom File Analysis
# ============================================================================
print_header "Discovery 6: Package Ownership Analysis"

cat >> "$OUTPUT_FILE" << 'SECTION6'

===========================================================
SECTION 6: PACKAGE vs CUSTOM FILES
===========================================================

SECTION6

info "Analyzing package ownership..."

echo "CUSTOM FILES (not owned by packages):" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

echo "In /etc:" >> "$OUTPUT_FILE"
set +e
find "${SOURCE_ROOT}etc" -type f \( \
    -name "*tangent*" -o \
    -name "TNAudit*" -o \
    -name "TNWatch*" -o \
    -name "tn-*" \
\) 2>/dev/null | while read -r file; do
    pkg_owner=$(pkg_info -E "$file" 2>/dev/null)
    if [ -z "$pkg_owner" ]; then
        rel_path=$(echo "$file" | sed "s|^${SOURCE_ROOT}||")
        echo "  /$rel_path" >> "$OUTPUT_FILE"
    fi
done
set -e

echo "" >> "$OUTPUT_FILE"
echo "In /usr/local/etc:" >> "$OUTPUT_FILE"

if [ -d "${SOURCE_ROOT}usr/local/etc" ]; then
    set +e
    find "${SOURCE_ROOT}usr/local/etc" -type f 2>/dev/null | while read -r file; do
        pkg_owner=$(pkg_info -E "$file" 2>/dev/null)
        if [ -z "$pkg_owner" ]; then
            rel_path=$(echo "$file" | sed "s|^${SOURCE_ROOT}||")
            echo "  /$rel_path" >> "$OUTPUT_FILE"
        fi
    done
    set -e
fi

echo "" >> "$OUTPUT_FILE"
echo "PACKAGE-PROVIDED FILES:" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "Packages with TN-related files:" >> "$OUTPUT_FILE"

set +e
find "${SOURCE_ROOT}etc" "${SOURCE_ROOT}usr/local/etc" -type f 2>/dev/null | \
    while read -r file; do
        pkg_info -E "$file" 2>/dev/null
    done | sort -u | while read -r pkg; do
        [ -n "$pkg" ] && echo "  - $pkg" >> "$OUTPUT_FILE"
    done
set -e

ok "Analyzed package ownership"

# ============================================================================
# Discovery 7: Payload Organization Recommendations
# ============================================================================
print_header "Discovery 7: Generating Recommendations"

cat >> "$OUTPUT_FILE" << 'SECTION7'

===========================================================
SECTION 7: PAYLOAD ORGANIZATION RECOMMENDATIONS
===========================================================

Based on the actual system scan, here's how payload/ should be organized:

SECTION7

info "Analyzing and generating recommendations..."

{
    echo "payload/"
    echo "|-- etc/"
    echo "|   |-- (System configs that go to /etc)"
} >> "$OUTPUT_FILE"

set +e
if [ -d "${SOURCE_ROOT}etc" ]; then
    find "${SOURCE_ROOT}etc" -maxdepth 1 -type f \( \
        -name "pf.conf" -o \
        -name "rc.local" -o \
        -name "rc.conf.local" -o \
        -name "httpd.conf" -o \
        -name "syslog.conf" -o \
        -name "fstab" \
    \) 2>/dev/null | while read -r file; do
        echo "|   |-- $(basename "$file")" >> "$OUTPUT_FILE"
    done

    find "${SOURCE_ROOT}etc" -maxdepth 1 -type d \( \
        -name "pf" -o \
        -name "pmacct" -o \
        -name "snort" -o \
        -name "e2guardian" -o \
        -name "p3scan" -o \
        -name "mail" -o \
        -name "TNAudit" -o \
        -name "TNWatch" \
    \) 2>/dev/null | while read -r dir; do
        echo "|   \`-- $(basename "$dir")/" >> "$OUTPUT_FILE"
    done
fi
set -e

{
    echo "|"
    echo "|-- usr-local-etc/"
    echo "|   |-- (Package configs that go to /usr/local/etc)"
} >> "$OUTPUT_FILE"

set +e
if [ -d "${SOURCE_ROOT}usr/local/etc" ]; then
    find "${SOURCE_ROOT}usr/local/etc" -maxdepth 1 -type d 2>/dev/null | \
        sed "s|^${SOURCE_ROOT}usr/local/etc/||" | \
        grep -v "^$" | sort | while read -r subdir; do
        echo "|   \`-- $subdir/" >> "$OUTPUT_FILE"
    done
fi
set -e

{
    echo "|"
    echo "\`-- var-www-htdocs-tn/"
    echo "    \`-- (Web application files)"
} >> "$OUTPUT_FILE"

ok "Generated recommendations"

# ============================================================================
# Summary
# ============================================================================
print_header "Discovery Complete"

cat >> "$OUTPUT_FILE" << 'FOOTER'

===========================================================
END OF REPORT
===========================================================

NEXT STEPS:
1. Review this report to understand actual file locations
2. Update payload/ structure to match reality
3. Re-run sync script with correct mappings
4. Test installer on clean VM

NOTE: Any 32-character hex strings (oinkcode etc.) have been
      redacted from this report for GDPR compliance.

FOOTER

echo "" >> "$OUTPUT_FILE"
echo "Report saved to: $OUTPUT_FILE" >> "$OUTPUT_FILE"

ok "Report generated: $OUTPUT_FILE"
echo ""
info "Review the report to see ACTUAL file locations"
echo ""

# ============================================================================
# Quick Summary (terminal only — no hanging find loops)
# ============================================================================
print_header "Quick Summary"
echo ""

ok "Interfaces: EXT_IF=$EXT_IF  INT_IF=$INT_IF"

# Scoped grep — only directories we care about, not all of /usr/local
set +e
iface_files=$(grep -rEl "$IFACE_PATTERN" \
    "${SOURCE_ROOT}etc" \
    "${SOURCE_ROOT}usr/local/etc" \
    "${SOURCE_ROOT}var/www/htdocs/tn" \
    2>/dev/null | wc -l | tr -d ' ')
set -e

ok "Files referencing $EXT_IF or $INT_IF: $iface_files"

# TNAudit location
if [ -d "${SOURCE_ROOT}etc/TNAudit" ]; then
    ok "TNAudit: /etc/TNAudit (CUSTOM)"
elif [ -d "${SOURCE_ROOT}usr/local/etc/TNAudit" ]; then
    ok "TNAudit: /usr/local/etc/TNAudit"
else
    warn "TNAudit directory not found"
fi

# TNWatch location
if [ -d "${SOURCE_ROOT}etc/TNWatch" ]; then
    ok "TNWatch: /etc/TNWatch (CUSTOM)"
elif [ -d "${SOURCE_ROOT}usr/local/etc/TNWatch" ]; then
    ok "TNWatch: /usr/local/etc/TNWatch"
else
    warn "TNWatch directory not found"
fi

echo ""
info "Full report: $OUTPUT_FILE"
echo ""
