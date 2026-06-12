#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# Initialize integrity status cache with baseline data
# Run this AFTER creating baselines with create_integrity_baseline.sh

STATUS_DIR="/var/www/htdocs/tn/data/services/status/integrity"
MTREE_DIR="/etc/mtree"

echo "Initializing integrity status cache..."

# Ensure status directory exists
mkdir -p "$STATUS_DIR"
chmod 755 "$STATUS_DIR"
chown www:www "$STATUS_DIR"

if [ ! -d "$MTREE_DIR" ] || [ -z "$(ls -A $MTREE_DIR/tn_*.spec 2> /dev/null)" ]; then
  echo "ERROR: No mtree baselines found in $MTREE_DIR"
  echo "Run: /usr/local/sbin/create_integrity_baseline.sh"
  exit 1
fi

count=0
for spec in "$MTREE_DIR"/tn_*.spec; do
  [ -e "$spec" ] || continue

  # Extract check name from filename (tn_cgi.spec -> cgi)
  check_name=$(basename "$spec" .spec | sed 's/^tn_//')

  # Count files in baseline (lines starting with /)
  file_count=$(grep -c "^/" "$spec" 2> /dev/null || echo 0)

  # Create initial status
  cat > "$STATUS_DIR/$check_name" << EOF
{
  "status": "pending",
  "files": $file_count,
  "changes": 0,
  "last_check": null
}
EOF

  chmod 644 "$STATUS_DIR/$check_name"
  chown www:www "$STATUS_DIR/$check_name"

  echo "✓ Initialized: $check_name ($file_count files)"
  count=$((count + 1))
done

echo ""
echo "Status cache initialized: $count checks"
echo "Location: $STATUS_DIR"
echo ""
echo "Verify files are accessible:"
ls -la "$STATUS_DIR"
