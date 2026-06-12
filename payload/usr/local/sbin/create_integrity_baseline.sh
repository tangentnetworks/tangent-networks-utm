#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/create_integrity_baseline.sh
# Creates mtree baselines based on configuration file
# Supports directories, individual files, and incremental updates

set -euo pipefail

# Configuration
CONFIG_FILE="/var/www/htdocs/tn/data/config/integrity_checks.conf"
EXCLUDES_FILE="/var/www/htdocs/tn/data/config/integrity_excludes.conf"
MTREE_DIR="/etc/mtree"
LOG="/var/log/integrity_baseline.log"
FORCE=0

# Parse arguments
while getopts "f" opt; do
  case $opt in
    f) FORCE=1 ;;
    *)
      echo "Usage: $0 [-f]"
      exit 1
      ;;
  esac
done

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"
}

# Ensure mtree directory exists
if [ ! -d "$MTREE_DIR" ]; then
  mkdir -p "$MTREE_DIR"
  chmod 755 "$MTREE_DIR"
  log "Created $MTREE_DIR"
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
  log "ERROR: Config file not found: $CONFIG_FILE"
  exit 1
fi

log "=== Creating Integrity Baselines ==="
log "Config: $CONFIG_FILE"
log "Force rebuild: $FORCE"
log ""

# Create temporary exclude file combining global and per-check excludes
create_exclude_file() {
  local per_check_excludes="$1"
  local tmp_exclude="/tmp/mtree_exclude_$$"

  # Start with global excludes if file exists
  if [ -f "$EXCLUDES_FILE" ]; then
    grep -v '^#' "$EXCLUDES_FILE" | grep -v '^$' > "$tmp_exclude" 2> /dev/null || touch "$tmp_exclude"
  else
    touch "$tmp_exclude"
  fi

  # Add per-check excludes
  if [ -n "$per_check_excludes" ]; then
    echo "$per_check_excludes" | tr ',' '\n' >> "$tmp_exclude"
  fi

  echo "$tmp_exclude"
}

# Check if baseline needs update
needs_update() {
  local spec_file="$1"
  local target_path="$2"

  # Force rebuild
  if [ $FORCE -eq 1 ]; then
    return 0
  fi

  # Spec doesn't exist
  if [ ! -f "$spec_file" ]; then
    return 0
  fi

  # Check if any target files are newer than spec
  if [ -d "$target_path" ]; then
    # Directory - check if any file is newer
    if [ -n "$(find "$target_path" -type f -newer "$spec_file" 2> /dev/null | head -1)" ]; then
      return 0
    fi
  elif [ -f "$target_path" ]; then
    # Single file - check if newer
    if [ "$target_path" -nt "$spec_file" ]; then
      return 0
    fi
  fi

  return 1
}

# Process directory check
process_dir_check() {
  local check_name="$1"
  local display_name="$2"
  local path="$3"
  local excludes="$4"
  local spec_file="$MTREE_DIR/tn_${check_name}.spec"

  log "Processing directory: $display_name"
  log "  Path: $path"

  # Check if path exists
  if [ ! -d "$path" ]; then
    log "  WARNING: Directory not found, skipping"
    return 1
  fi

  # Check if update needed
  if ! needs_update "$spec_file" "$path"; then
    log "  SKIP: Baseline up to date"
    return 0
  fi

  # Count files before creating baseline
  local file_count=$(find "$path" -type f 2> /dev/null | wc -l)
  log "  Files: $file_count"

  # Create baseline (OpenBSD mtree doesn't support -X exclude flag)
  log "  Running mtree..."
  mtree -cx -K sha256digest,uid,gid,mode,time \
    -p "$path" \
    > "$spec_file"

  local mtree_exit=$?
  log "  mtree exit code: $mtree_exit"
  log "  spec file size: $(wc -c < "$spec_file" 2> /dev/null || echo 0) bytes"

  # Add metadata comment to spec
  # OpenBSD mtree format: files are lines without type=dir, not starting with # or ., not ..
  local actual_count=$(grep -vE '^(#|/set|\.\.|^$)' "$spec_file" 2> /dev/null | grep -v 'type=dir' | grep -vE '^\.' | wc -l | awk '{print $1}')
  log "  Counted: $actual_count file entries"
  {
    echo "# Baseline created: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Check: $check_name ($display_name)"
    echo "# Path: $path"
    echo "# Files monitored: $actual_count"
    echo "#"
    cat "$spec_file"
  } > "${spec_file}.tmp"
  mv "${spec_file}.tmp" "$spec_file"

  chmod 644 "$spec_file"
  log "  ✓ Created: tn_${check_name}.spec ($actual_count files)"

  return 0
}

# Process file check
process_file_check() {
  local check_name="$1"
  local display_name="$2"
  local filepath="$3"
  local spec_file="$MTREE_DIR/tn_${check_name}.spec"

  log "Processing file: $display_name"
  log "  Path: $filepath"

  # Check if file exists
  if [ ! -f "$filepath" ]; then
    log "  WARNING: File not found, skipping"
    return 1
  fi

  # Check if update needed
  if ! needs_update "$spec_file" "$filepath"; then
    log "  SKIP: Baseline up to date"
    return 0
  fi

  # Get directory and filename
  local dir=$(dirname "$filepath")
  local file=$(basename "$filepath")

  # Create baseline for single file
  {
    echo "# Baseline created: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Check: $check_name ($display_name)"
    echo "# File: $filepath"
    echo "#"
    mtree -cx -K sha256digest,uid,gid,mode,time -p "$dir" 2> /dev/null | grep "^\(#\|/[^/]*$file\)"
  } > "$spec_file"

  chmod 644 "$spec_file"
  log "  ✓ Created: tn_${check_name}.spec (1 file)"

  return 0
}

# Parse config and process each check
total=0
success=0
skipped=0
failed=0

while IFS='|' read -r type check_name display_name path description excludes; do
  # Skip comments and empty lines
  case "$type" in
    \#* | "") continue ;;
  esac

  total=$((total + 1))

  log ""

  case "$type" in
    dir)
      if process_dir_check "$check_name" "$display_name" "$path" "$excludes"; then
        success=$((success + 1))
      else
        if [ -d "$path" ]; then
          failed=$((failed + 1))
        else
          skipped=$((skipped + 1))
        fi
      fi
      ;;
    file)
      if process_file_check "$check_name" "$display_name" "$path"; then
        success=$((success + 1))
      else
        if [ -f "$path" ]; then
          failed=$((failed + 1))
        else
          skipped=$((skipped + 1))
        fi
      fi
      ;;
    *)
      log "ERROR: Unknown check type: $type"
      failed=$((failed + 1))
      ;;
  esac

done < "$CONFIG_FILE"

# Summary
log ""
log "=== Baseline Creation Summary ==="
log "Total checks:    $total"
log "Created/Updated: $success"
log "Skipped (up to date): $((total - success - failed - skipped))"
log "Skipped (missing):    $skipped"
log "Failed:          $failed"
log ""

if [ $success -gt 0 ]; then
  log "Created baselines:"
  ls -lh "$MTREE_DIR"/tn_*.spec 2> /dev/null | while read line; do
    log "  $line"
  done
  log ""

  # Update status cache for web interface
  log "Updating status cache for web interface..."
  STATUS_DIR="/var/www/htdocs/tn/data/services/status/integrity"
  mkdir -p "$STATUS_DIR"
  chmod 755 "$STATUS_DIR"
  chown www:www "$STATUS_DIR" 2> /dev/null

  cache_updated=0

  # Read config and count actual files in each directory
  while IFS='|' read -r type check_name display_name path description excludes; do
    # Skip comments and empty lines
    case "$type" in
      \#* | "") continue ;;
    esac

    # Only process if mtree spec exists
    spec="$MTREE_DIR/tn_${check_name}.spec"
    [ -f "$spec" ] || continue

    # Count actual files in the source directory/file
    file_count=0
    if [ "$type" = "dir" ] && [ -d "$path" ]; then
      # Count files in directory (recursive)
      file_count=$(find "$path" -type f 2> /dev/null | wc -l | awk '{print $1}')
    elif [ "$type" = "file" ] && [ -f "$path" ]; then
      # Single file
      file_count=1
    fi

    # Ensure it's a valid number
    case "$file_count" in
      '' | *[!0-9]*) file_count=0 ;;
    esac

    cat > "$STATUS_DIR/$check_name" << EOF
{
  "status": "pending",
  "files": $file_count,
  "changes": 0,
  "last_check": null
}
EOF

    chmod 644 "$STATUS_DIR/$check_name"
    chown www:www "$STATUS_DIR/$check_name" 2> /dev/null
    cache_updated=$((cache_updated + 1))
  done < "$CONFIG_FILE"

  log "Updated $cache_updated status cache files"
  log ""
fi

log "To verify integrity:"
log "  mtree < /etc/mtree/tn_<check_name>.spec"
log ""
log "Via web interface:"
log "  https://your-firewall/view/integrity"
log ""

if [ $failed -gt 0 ]; then
  log "WARNING: $failed check(s) failed"
  exit 1
fi

exit 0
