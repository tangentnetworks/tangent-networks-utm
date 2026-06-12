#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# cleanup_stale_requests.sh
# Run this ONCE to clean up the backed-up request files

REQ_DIR="/var/www/htdocs/tn/data/services/queue/request"

echo "Cleaning stale request files from $REQ_DIR..."

count=0
for req in "$REQ_DIR"/*.txt; do
  [ -e "$req" ] || continue
  echo "  Removing: $req"
  rm -f "$req"
  count=$((count + 1))
done

echo "Removed $count stale request file(s)"
echo "Done!"
