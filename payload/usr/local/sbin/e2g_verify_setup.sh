#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# E2Guardian Multi-Filter Verification Script
# Version: 1.0
# Date: 2025-11-14
# Purpose: Verify E2Guardian multi-filter installation and configuration

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Print functions
print_pass() {
  echo "${GREEN}✓ PASS${NC}: $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

print_fail() {
  echo "${RED}✗ FAIL${NC}: $1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

print_warn() {
  echo "${YELLOW}⚠ WARN${NC}: $1"
  WARN_COUNT=$((WARN_COUNT + 1))
}

print_info() {
  echo "${BLUE}ℹ INFO${NC}: $1"
}

print_header() {
  echo ""
  echo "=============================================="
  echo "$1"
  echo "=============================================="
  echo ""
}

# Start verification
print_header "E2Guardian Multi-Filter Verification"
print_info "This script will verify your E2Guardian installation"
echo ""

# Check if running as root
if [ "$(id -u)" -eq 0 ]; then
  print_pass "Running as root"
else
  print_warn "Not running as root - some checks may fail"
fi

# Test 1: Check E2Guardian installation
print_header "Test 1: E2Guardian Installation"

if command -v e2guardian > /dev/null 2>&1; then
  E2G_VERSION=$(e2guardian -v 2>&1 | head -1)
  print_pass "E2Guardian found: $E2G_VERSION"
else
  print_fail "E2Guardian not found"
  print_info "Install with: pkg_add e2guardian"
fi

# Test 2: Check required tools
print_header "Test 2: Required Tools"

for cmd in curl grep sed awk sort tar ksh; do
  if command -v $cmd > /dev/null 2>&1; then
    print_pass "$cmd found"
  else
    print_fail "$cmd not found"
  fi
done

# Test 3: Check directory structure
print_header "Test 3: Directory Structure"

# Work directories
for filter_type in adult childsafe user; do
  if [ -d "/etc/feeds/${filter_type}" ]; then
    print_pass "Work directory exists: /etc/feeds/${filter_type}"

    # Check subdirectories
    for subdir in hostfiles domains ads mix new_feeds; do
      if [ -d "/etc/feeds/${filter_type}/${subdir}" ]; then
        print_pass "  Subdirectory: ${subdir}"
      else
        print_fail "  Missing subdirectory: ${subdir}"
      fi
    done
  else
    print_fail "Work directory missing: /etc/feeds/${filter_type}"
  fi
done

# Check porn directories
if [ -d "/etc/feeds/childsafe/porn" ]; then
  print_pass "Childsafe porn directory exists"
else
  print_fail "Childsafe porn directory missing"
fi

if [ -d "/etc/feeds/user/porn" ]; then
  print_pass "User porn directory exists"
else
  print_fail "User porn directory missing"
fi

# Output directories
for filter_type in adult childsafe webuser; do
  dir="/etc/e2guardian/lists/blacklists/${filter_type}"
  if [ -d "$dir" ]; then
    print_pass "Output directory exists: $dir"
  else
    print_fail "Output directory missing: $dir"
  fi
done

# Feed configuration directory
if [ -d "/etc/e2guardian/feeds" ]; then
  print_pass "Feed config directory exists"
else
  print_fail "Feed config directory missing"
fi

# Log directory
if [ -d "/var/www/htdocs/tn/data/logs/cron" ]; then
  print_pass "Log directory exists"
else
  print_warn "Log directory missing: /var/www/htdocs/tn/data/logs/cron"
fi

# Test 4: Check filter scripts
print_header "Test 4: Filter Scripts"

for script in e2g_adult_filter.sh e2g_childsafe_filter.sh e2g_user_filter.sh; do
  script_path="/usr/local/sbin/${script}"

  if [ -f "$script_path" ]; then
    print_pass "Script exists: $script"

    # Check if executable
    if [ -x "$script_path" ]; then
      print_pass "  Script is executable"
    else
      print_fail "  Script is not executable"
    fi

    # Check for bashisms
    if grep -q '\^\^' "$script_path"; then
      print_fail "  Script contains bashisms (^^)"
    else
      print_pass "  No bashisms detected"
    fi

    # Check for FILTER_TYPE_UPPER
    if grep -q 'FILTER_TYPE_UPPER=' "$script_path"; then
      print_pass "  Uses FILTER_TYPE_UPPER (ksh compatible)"
    else
      print_warn "  May not use FILTER_TYPE_UPPER"
    fi

    # Check for double -Q
    q_count=$(grep -c "e2guardian.*-Q" "$script_path" 2> /dev/null || echo "0")
    if [ "$q_count" -eq 0 ]; then
      print_pass "  No -Q flags found (good performance)"
    else
      print_fail "  Found $q_count -Q flags (performance issue)"
    fi

  else
    print_fail "Script missing: $script"
  fi
done

# Test 5: Check configuration files
print_header "Test 5: Configuration Files"

for conf in e2guardianf1.conf.a e2guardianf1.conf.c e2guardianf1.conf.u; do
  conf_path="/etc/e2guardian/${conf}"

  if [ -f "$conf_path" ]; then
    print_pass "Config template exists: $conf"

    # Extract filter type from extension
    case "$conf" in
      *.a) filter_dir="adult" ;;
      *.c) filter_dir="childsafe" ;;
      *.u) filter_dir="webuser" ;;
    esac

    # Check if paths point to correct directories
    if grep -q "path=/etc/e2guardian/lists/blacklists/${filter_dir}/domains" "$conf_path"; then
      print_pass "  Points to correct domains path"
    else
      print_fail "  Incorrect domains path"
    fi

    if grep -q "path=/etc/e2guardian/lists/blacklists/${filter_dir}/urls" "$conf_path"; then
      print_pass "  Points to correct URLs path"
    else
      print_fail "  Incorrect URLs path"
    fi

  else
    print_fail "Config template missing: $conf"
  fi
done

# Check story file
if [ -f "/etc/e2guardian/e2guardianf1.story" ]; then
  print_pass "Story file exists"
else
  print_warn "Story file missing: e2guardianf1.story"
fi

# Test 6: Check feed configurations
print_header "Test 6: Feed Configurations"

# Adult filter feeds
if [ -f "/etc/e2guardian/feeds/general.txt" ]; then
  print_pass "Adult filter feed config exists"

  feed_count=$(grep -v "^#" /etc/e2guardian/feeds/general.txt | grep -v "^$" | wc -l | tr -d ' ')
  if [ "$feed_count" -gt 0 ]; then
    print_pass "  Contains $feed_count feed(s)"
  else
    print_warn "  No feeds configured"
  fi
else
  print_fail "Adult filter feed config missing: /etc/e2guardian/feeds/general.txt"
fi

# Childsafe filter feeds
if [ -f "/etc/e2guardian/feeds/childsafe.txt" ]; then
  print_pass "Childsafe filter feed config exists"

  feed_count=$(grep -v "^#" /etc/e2guardian/feeds/childsafe.txt | grep -v "^$" | wc -l | tr -d ' ')
  if [ "$feed_count" -gt 0 ]; then
    print_pass "  Contains $feed_count feed(s)"
  else
    print_warn "  No feeds configured"
  fi
else
  print_fail "Childsafe filter feed config missing: /etc/e2guardian/feeds/childsafe.txt"
fi

# User filter feeds
user_feed_path="/var/www/htdocs/tn/data/services/queue/e2gfilters/userlist/userfeeds.txt"
if [ -f "$user_feed_path" ]; then
  print_pass "User filter feed config exists"
else
  print_warn "User filter feed config missing (web UI managed)"
fi

# Test 7: Check phrase lists
print_header "Test 7: Phrase List Files"

# Adult filter
if [ -f "/etc/e2guardian/lists/blacklists/adult/spam_phrases" ]; then
  print_pass "Adult spam_phrases exists"
else
  print_fail "Adult spam_phrases missing"
fi

# Childsafe filter
for phrase_file in bad_words profanity spam_phrases regexlist; do
  if [ -f "/etc/e2guardian/lists/blacklists/childsafe/${phrase_file}" ]; then
    print_pass "Childsafe ${phrase_file} exists"
  else
    print_fail "Childsafe ${phrase_file} missing"
  fi
done

# User filter
if [ -f "/etc/e2guardian/lists/blacklists/webuser/spam_phrases" ]; then
  print_pass "User spam_phrases exists"
else
  print_fail "User spam_phrases missing"
fi

# Test 8: Check permissions
print_header "Test 8: File Permissions"

# Check script permissions
for script in e2g_adult_filter.sh e2g_childsafe_filter.sh e2g_user_filter.sh; do
  script_path="/usr/local/sbin/${script}"
  if [ -f "$script_path" ]; then
    perms=$(ls -l "$script_path" | awk '{print $1}')
    if [ "$perms" = "-rwxr-xr-x" ] || [ "$perms" = "-rwxr-x---" ]; then
      print_pass "Correct permissions on $script"
    else
      print_warn "Unusual permissions on $script: $perms"
    fi
  fi
done

# Check directory permissions
for dir in /etc/feeds/adult /etc/feeds/childsafe /etc/feeds/user; do
  if [ -d "$dir" ]; then
    perms=$(ls -ld "$dir" | awk '{print $1}')
    if echo "$perms" | grep -q "^drwx"; then
      print_pass "Directory accessible: $dir"
    else
      print_warn "Unusual permissions on $dir: $perms"
    fi
  fi
done

# Test 9: Check for path conflicts
print_header "Test 9: Path Conflict Detection"

# Check if scripts still reference old 'custom' path
conflict_found=0

for script in /usr/local/sbin/e2g_*_filter.sh; do
  if [ -f "$script" ]; then
    if grep -q '/etc/e2guardian/lists/blacklists/custom/' "$script"; then
      print_fail "$(basename $script) still references old 'custom' path"
      conflict_found=1
    fi
  fi
done

if [ $conflict_found -eq 0 ]; then
  print_pass "No path conflicts detected"
fi

# Test 10: Check E2Guardian status
print_header "Test 10: E2Guardian Service Status"

if pgrep e2guardian > /dev/null; then
  PID=$(pgrep e2guardian | head -1)
  print_pass "E2Guardian is running (PID: $PID)"

  # Check if listening on expected port
  if netstat -an | grep -q "8080.*LISTEN"; then
    print_pass "E2Guardian listening on port 8080"
  else
    print_warn "E2Guardian may not be listening on port 8080"
  fi
else
  print_warn "E2Guardian is not running"
  print_info "Start with: rcctl start e2guardian"
fi

# Test 11: Check for existing filter data
print_header "Test 11: Existing Filter Data"

for filter_type in adult childsafe webuser; do
  domains_file="/etc/e2guardian/lists/blacklists/${filter_type}/domains"
  urls_file="/etc/e2guardian/lists/blacklists/${filter_type}/urls"

  if [ -f "$domains_file" ]; then
    domain_count=$(wc -l < "$domains_file" 2> /dev/null || echo "0")
    if [ "$domain_count" -gt 0 ]; then
      print_pass "${filter_type} filter: $domain_count domains"
    else
      print_warn "${filter_type} filter: No domains yet (run filter script)"
    fi
  else
    print_warn "${filter_type} domains file doesn't exist yet"
  fi

  if [ -f "$urls_file" ]; then
    url_count=$(wc -l < "$urls_file" 2> /dev/null || echo "0")
    if [ "$url_count" -gt 0 ]; then
      print_pass "${filter_type} filter: $url_count URLs"
    else
      print_info "${filter_type} filter: No URLs yet"
    fi
  fi
done

# Test 12: Check active filter configuration
print_header "Test 12: Active Filter Configuration"

if [ -f "/etc/e2guardian/e2guardianf1.conf" ]; then
  print_pass "Active filter config exists"

  # Try to determine which filter is active
  if diff -q /etc/e2guardian/e2guardianf1.conf /etc/e2guardian/e2guardianf1.conf.a > /dev/null 2>&1; then
    print_pass "Active filter: ADULT"
  elif diff -q /etc/e2guardian/e2guardianf1.conf /etc/e2guardian/e2guardianf1.conf.c > /dev/null 2>&1; then
    print_pass "Active filter: CHILDSAFE"
  elif diff -q /etc/e2guardian/e2guardianf1.conf /etc/e2guardian/e2guardianf1.conf.u > /dev/null 2>&1; then
    print_pass "Active filter: USER"
  else
    print_warn "Active filter: CUSTOM (not matching any template)"
  fi
else
  print_warn "No active filter config found"
  print_info "Run a filter script to activate one"
fi

# Test 13: Check cron configuration
print_header "Test 13: Cron Configuration"

if [ -f "/etc/crontab" ]; then
  if grep -q "e2g.*filter\.sh" /etc/crontab; then
    active_cron=$(grep "e2g.*filter\.sh" /etc/crontab | head -1)
    print_pass "Cron job configured:"
    echo "  $active_cron"
  else
    print_warn "No e2guardian filter cron job found"
    print_info "Run a filter script to configure cron"
  fi
else
  print_warn "/etc/crontab not found"
fi

# Test 14: Check logs
print_header "Test 14: Log Files"

log_dir="/var/www/htdocs/tn/data/logs/cron"
if [ -d "$log_dir" ]; then
  log_count=$(find "$log_dir" -name "e2guardian-*.log" -o -name "e2g_user_filter-*.log" | wc -l | tr -d ' ')

  if [ "$log_count" -gt 0 ]; then
    print_pass "Found $log_count log file(s)"

    # Show most recent log
    latest_log=$(ls -t "$log_dir"/e2guardian-*.log "$log_dir"/e2g_user_filter-*.log 2> /dev/null | head -1)
    if [ -n "$latest_log" ]; then
      print_info "Most recent log: $(basename "$latest_log")"
    fi
  else
    print_warn "No log files found (scripts haven't run yet)"
  fi
else
  print_warn "Log directory doesn't exist"
fi

# Summary
print_header "Verification Summary"

echo "Test Results:"
echo "  ${GREEN}Passed${NC}:  $PASS_COUNT"
echo "  ${YELLOW}Warnings${NC}: $WARN_COUNT"
echo "  ${RED}Failed${NC}:  $FAIL_COUNT"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
  print_pass "All critical tests passed!"
  echo ""
  echo "Your E2Guardian multi-filter system is properly configured."
  echo ""
  print_info "Next steps:"
  echo "  1. Review feed configurations:"
  echo "     vi /etc/e2guardian/feeds/general.txt"
  echo "     vi /etc/e2guardian/feeds/childsafe.txt"
  echo ""
  echo "  2. Run a filter script to download feeds:"
  echo "     /usr/local/sbin/e2g_adult_filter.sh"
  echo ""
  echo "  3. Monitor the logs:"
  echo "     tail -f /var/www/htdocs/tn/data/logs/cron/e2guardian-adult-*.log"
  echo ""
  exit 0
else
  print_fail "Some tests failed!"
  echo ""
  echo "Please review the failures above and:"
  echo "  1. Run the setup script if directories are missing:"
  echo "     ./setup_e2guardian_multifilter.sh"
  echo ""
  echo "  2. Check file permissions"
  echo "  3. Verify all required files are present"
  echo "  4. Consult the README.md for detailed setup instructions"
  echo ""
  exit 1
fi
