#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# ============================================================================
# TN_TEST_WAF.sh End-to-end asset tamper detection test
# Sources LAN IP from /etc/tn-interfaces and tests via HTTPS on LAN interface
# ============================================================================

INTERFACES_FILE="/etc/tn-interfaces"
ASSET="/assets/js/auth.js"
BACKUP="/tmp/auth.js.bak"
ASSET_PATH="/var/www/htdocs/tn/assets/js/auth.js"

# -- Source LAN IP --
if [ ! -f "$INTERFACES_FILE" ]; then
    echo "FAIL: $INTERFACES_FILE not found"
    exit 1
fi

. "$INTERFACES_FILE"

if [ -z "$INT_IP4" ]; then
    echo "FAIL: INT_IP4 not set in $INTERFACES_FILE"
    exit 1
fi

echo "[INFO] Testing against https://$INT_IP4$ASSET"

# -- Backup and corrupt --
cp "$ASSET_PATH" "$BACKUP" || { echo "FAIL: Cannot backup $ASSET_PATH"; exit 1; }
echo "//test" >> "$ASSET_PATH"
echo "[INFO] Asset corrupted -- expecting 500"

# -- Test corrupted --
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$INT_IP4$ASSET")
if [ "$STATUS" = "500" ]; then
    echo "  PASS: Got 500 on tampered asset -- SRI enforcement working"
else
    echo "  FAIL: Expected 500, got $STATUS -- SRI enforcement NOT working"
    echo "  CHECK: tail -10 /var/www/htdocs/tn/data/logs/waf/security.log"
fi

# -- Restore --
cp "$BACKUP" "$ASSET_PATH" || { echo "FAIL: Cannot restore $ASSET_PATH"; exit 1; }
echo "[INFO] Asset restored"

# -- Test clean --
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$INT_IP4$ASSET")
if [ "$STATUS" = "200" ]; then
    echo "  PASS: Got 200 on clean asset -- hashes match"
else
    echo "  FAIL: Expected 200, got $STATUS -- check TN_SUBSTITUTE.sh was run"
fi
