#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_mirror_sync.sh
# Mirror system files to WebUI queue (runs once on boot)
#
# MIRRORED FILES:
#   - pf.conf           → Base config (for display)
#   - pf-addons.conf    → Anchor config (for display)
#   - blocklist         → For deduplication
#   - bogonranges       → For deduplication
#   - current           → Active PF rules (pfctl -sr output)

set -e

QUEUE_BASE="/var/www/htdocs/tn/data/services/queue/pf-rules"
MIRROR_DIR="$QUEUE_BASE/mirror"
CURRULES="$QUEUE_BASE/current"

# ============================================
# CREATE DIRECTORY STRUCTURE
# ============================================
for dir in mirror user-input validated staging validation-output triggers base-snapshot; do
  [ ! -d "$QUEUE_BASE/$dir" ] && mkdir -p "$QUEUE_BASE/$dir"
done

# ============================================
# SEED /etc/pf/pf-addons.conf (ONE-TIME)
# The anchor "addons" in pf.conf is already in place.
# pfctl -a addons -f requires the file to exist when pf_monitor
# first tries to back it up before writing. Create it empty if
# it has never been created by an apply action yet.
# ============================================
if [ ! -d /etc/pf ]; then
  mkdir -p /etc/pf
  chown root:wheel /etc/pf
  chmod 755 /etc/pf
fi

if [ ! -f /etc/pf/pf-addons.conf ]; then
  cat > /etc/pf/pf-addons.conf << 'EOF'
# pf-addons.conf - User-managed anchor rules
# Managed by pf_monitor.sh / pf_validator.pl via WebUI
# Do not edit manually - changes will be overwritten
# Generated: first-boot seed (empty)
EOF
  chown root:wheel /etc/pf/pf-addons.conf
  chmod 0640 /etc/pf/pf-addons.conf
fi

# ============================================
# MIRROR SYSTEM FILES (Read-Only Copies)
# ============================================

# Base PF configuration (for display in WebUI)
[ -f /etc/pf.conf ] && cp /etc/pf.conf "$MIRROR_DIR/pf.conf"

# Anchor config mirror (for display in WebUI)
if [ -f /etc/pf/pf-addons.conf ]; then
  cp /etc/pf/pf-addons.conf "$MIRROR_DIR/pf-addons.conf"
else
  touch "$MIRROR_DIR/pf-addons.conf"
fi

# DEDUPLICATION FILES (Perl checks against these)
if [ -f /etc/pf/blocklist ]; then
  cp /etc/pf/blocklist "$MIRROR_DIR/blocklist.txt"
else
  touch "$MIRROR_DIR/blocklist.txt"
fi

if [ -f /etc/pf/bogonranges ]; then
  cp /etc/pf/bogonranges "$MIRROR_DIR/bogonranges.txt"
else
  touch "$MIRROR_DIR/bogonranges.txt"
fi

# ============================================
# CAPTURE CURRENT ACTIVE PF RULES (pfctl -sr)
# ============================================
pfctl -sr > "$CURRULES" 2> /dev/null || touch "$CURRULES"
chown www:www "$CURRULES"
chmod 0640 "$CURRULES"

# ============================================
# CREATE BASE SNAPSHOT (For Fast Deduplication)
# ============================================
# Combine blocklist + bogonranges into single file for Perl
cat "$MIRROR_DIR/blocklist.txt" \
  "$MIRROR_DIR/bogonranges.txt" \
  2> /dev/null \
  | grep -v '^#' \
  | grep -v '^[[:space:]]*$' \
  | sort -u > "$QUEUE_BASE/base-snapshot/all-existing-ips.txt"

# ============================================
# SET PERMISSIONS
# ============================================
chown -R www:www "$QUEUE_BASE"
chmod -R 755 "$QUEUE_BASE"
chmod 644 "$MIRROR_DIR"/* 2> /dev/null || true
chmod 644 "$QUEUE_BASE/base-snapshot"/* 2> /dev/null || true

# Staging dir: root owns it, www group can read and write.
# pf_validator.pl (root) writes staging/pf-addons.conf.
# pf_write_rules.pl (www/CGI) writes staging/pf-addons-deletion.conf
# and pf_monitor.sh (root) writes staging/*.json outcome files.
chown root:www "$QUEUE_BASE/staging"
chmod 775 "$QUEUE_BASE/staging"

# Triggers dir: www writes trigger requests, root reads and clears them
chown root:www "$QUEUE_BASE/triggers"
chmod 775 "$QUEUE_BASE/triggers"

# ============================================
# INITIALIZE USER-INPUT QUEUE FILES (If Not Exists)
# Written by pf_write_input.pl (www), read by pf_validator.pl (root)
# ============================================
for f in ip-block.txt ip-pass.txt asn-block.txt feed-urls.txt custom-rules.txt; do
  if [ ! -f "$QUEUE_BASE/user-input/$f" ]; then
    touch "$QUEUE_BASE/user-input/$f"
    chown www:www "$QUEUE_BASE/user-input/$f"
    chmod 0644 "$QUEUE_BASE/user-input/$f"
  fi
done

if [ ! -f "$QUEUE_BASE/user-input/geoip-policy.json" ]; then
  touch "$QUEUE_BASE/user-input/geoip-policy.json"
  chown www:www "$QUEUE_BASE/user-input/geoip-policy.json"
  chmod 0644 "$QUEUE_BASE/user-input/geoip-policy.json"
fi

# ============================================
# INITIALIZE /etc/pf/user (Legacy path - kept for compatibility)
# ============================================
if [ ! -d /etc/pf/user ]; then
  mkdir -p /etc/pf/user
  touch /etc/pf/user/ip-block.txt
  touch /etc/pf/user/ip-pass.txt
  touch /etc/pf/user/asn-block.txt
  touch /etc/pf/user/geoip-block.txt
  touch /etc/pf/user/feed-block.txt
  chown root:www /etc/pf/user/*.txt
  chmod 664 /etc/pf/user/*.txt
fi

exit 0
