#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_add_anchor.sh
#
# Purpose: Add anchor hook to /etc/pf.conf (ONE-TIME SETUP)
# This modifies pf.conf to include user-managed rules via anchor

set -e

PF_CONF="/etc/pf.conf"
BACKUP_DIR="/var/backups"
ANCHOR_LINE='anchor "addons"'
LOG_FILE="/var/www/tmp/pf_add_anchor.log"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Ensure /var/www/tmp exists
if [ ! -d /var/www/tmp ]; then
  mkdir -p /var/www/tmp
  chown www:www /var/www/tmp
  chmod 755 /var/www/tmp
fi

# ============================================
# BACKUP EXISTING CONFIG
# ============================================
BACKUP_FILE="$BACKUP_DIR/pf.conf.$(date +%s).pre-anchor"
cp "$PF_CONF" "$BACKUP_FILE"
log "Backed up $PF_CONF to $BACKUP_FILE"

# ============================================
# CHECK IF ANCHOR ALREADY EXISTS
# ============================================
if grep -q "$ANCHOR_LINE" "$PF_CONF"; then
  log "Anchor hook already exists in pf.conf"
  exit 0
fi

# ============================================
# FIND INSERTION POINT (After blocklist blocks)
# ============================================
# We want to insert AFTER the existing block rules
# Looking for: block drop quick from <bogons>

INSERTION_LINE=$(grep -n "block drop quick from <bogons>" "$PF_CONF" | tail -1 | cut -d: -f1)

if [ -z "$INSERTION_LINE" ]; then
  log "ERROR: Could not find insertion point (bogons block rule)"
  exit 1
fi

# Insert after this line
INSERTION_LINE=$((INSERTION_LINE + 1))

log "Inserting anchor at line $INSERTION_LINE"

# ============================================
# INSERT ANCHOR HOOK
# ============================================
{
  head -n $((INSERTION_LINE - 1)) "$PF_CONF"
  echo ""
  echo "# ----------------------------------------------------------------------"
  echo "# USER-MANAGED RULES (Transient Anchor)"
  echo "# Loaded via: pfctl -a addons -f /etc/pf/pf-addons.conf"
  echo "# Reset via:  pfctl -a addons -F all"
  echo "# ----------------------------------------------------------------------"
  echo "$ANCHOR_LINE"
  echo ""
  tail -n +$INSERTION_LINE "$PF_CONF"
} > "$PF_CONF.new"

# ============================================
# VALIDATE NEW CONFIG
# ============================================
log "Validating new configuration..."

if pfctl -nf "$PF_CONF.new" > /dev/null 2>&1; then
  mv "$PF_CONF.new" "$PF_CONF"
  log "✓ Anchor added successfully to pf.conf"
  log "✓ Syntax validated"
  log ""
  log "IMPORTANT: Reload PF to activate:"
  log "  pfctl -f /etc/pf.conf"
  log ""
  log "Verify with:"
  log "  pfctl -sr | grep -A 2 'anchor \"addons\"'"
else
  log "✗ ERROR: New config failed syntax check!"
  log "  Keeping original pf.conf"
  log "  Failed config saved to: $PF_CONF.new"
  exit 1
fi

exit 0
