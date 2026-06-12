#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# /usr/local/sbin/pf_delete_block.sh
#
# PURPOSE:
#   Consume a delete request written by pf_active_rules.pl (www/CGI),
#   remove the corresponding logical block from pf-addons.conf,
#   flush and kill the associated PF table(s) from kernel memory,
#   clear the corresponding queue file entry, reload the anchor,
#   write the outcome, and trigger pf_anchor_sync.sh to refresh
#   active-addons.json for the WebUI.
#
# DELETE REQUEST FORMAT:
#   /var/www/htdocs/tn/data/services/queue/pf-rules/delete-requests/<timestamp>.json
#   {
#     "type":    "ip_block|ip_pass|asn_block|geoip|feed|custom",
#     "country": "VN",              (geoip only)
#     "feed_index": 1,              (feed only)
#     "rule":    "pass in quick...", (custom only)
#     "requested": 1234567890
#   }
#
# PRIVILEGE: runs as root (via pf_monitor.sh or its own runner)

set -e

# ============================================================
# CONFIGURATION
# ============================================================
QUEUE_BASE="/var/www/htdocs/tn/data/services/queue/pf-rules"
DELETE_DIR="$QUEUE_BASE/delete-requests"
OUTCOME_DIR="$QUEUE_BASE/delete-outcome"
USER_INPUT="$QUEUE_BASE/user-input"
ADDONS_CONF="/etc/pf/pf-addons.conf"
ANCHOR="addons"
LOG_FILE="/var/www/tmp/pf_delete_block.log"
SYNC_SCRIPT="/usr/local/sbin/pf_anchor_sync.sh"

# ============================================================
# LOGGING
# ============================================================
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [pf_delete_block] $*" >> "$LOG_FILE"
}

# ============================================================
# JSON HELPERS
# ============================================================
json_str() {
  printf '%s' "$1" \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g' \
    | tr -d '\000-\031'
}

write_outcome() {
  local req_file="$1"
  local success="$2"
  local message="$3"
  local base
  base=$(basename "$req_file" .json)
  local out="$OUTCOME_DIR/${base}.result.json"
  mkdir -p "$OUTCOME_DIR"
  msg_esc=$(json_str "$message")
  cat > "$out" << EOF
{
    "success": $success,
    "message": "$msg_esc",
    "timestamp": $(date +%s)
}
EOF
  chown www:www "$out"
  chmod 0644 "$out"
}

# ============================================================
# FIND OLDEST PENDING DELETE REQUEST
# ============================================================
mkdir -p "$DELETE_DIR" "$OUTCOME_DIR"

REQUEST_FILE=$(ls -t "$DELETE_DIR"/*.json 2> /dev/null | tail -1)

if [ -z "$REQUEST_FILE" ]; then
  exit 0 # Nothing to do
fi

log "Processing delete request: $REQUEST_FILE"

# ============================================================
# PARSE REQUEST -- minimal JSON extraction without jq
# ============================================================
TYPE=$(grep '"type"' "$REQUEST_FILE" | sed 's/.*"type"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
COUNTRY=$(grep '"country"' "$REQUEST_FILE" | sed 's/.*"country"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
FEED_IDX=$(grep '"feed_index"' "$REQUEST_FILE" | sed 's/.*"feed_index"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/')
RULE=$(grep '"rule"' "$REQUEST_FILE" | sed 's/.*"rule"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/' | sed 's/\\"/"/g')

# Remove request file immediately -- prevent double processing
rm -f "$REQUEST_FILE"

if [ -z "$TYPE" ]; then
  log "ERROR: could not parse type from request"
  write_outcome "$REQUEST_FILE" "false" "Could not parse request type"
  exit 1
fi

log "Delete type: $TYPE country=$COUNTRY feed_idx=$FEED_IDX"

# ============================================================
# HELPER: flush and kill a PF table from kernel memory
# ============================================================
flush_table() {
  local tbl="$1"
  pfctl -a "$ANCHOR" -t "$tbl" -T flush 2> /dev/null || true
  pfctl -a "$ANCHOR" -t "$tbl" -T kill 2> /dev/null || true
  log "Flushed and killed table: $tbl"
}

# ============================================================
# HELPER: remove a logical block section from pf-addons.conf
#
# Removes everything from a section marker comment up to (but
# not including) the next section marker or end-of-file marker.
# Uses a temp file + atomic rename.
# ============================================================
remove_section() {
  local marker="$1" # grep pattern matching the section header comment
  local tmp="${ADDONS_CONF}.tmp"

  awk -v pat="$marker" '
        /^# =+$/ && found { found=0 }
        found { next }
        $0 ~ pat { found=1; next }
        { print }
    ' "$ADDONS_CONF" > "$tmp" && mv "$tmp" "$ADDONS_CONF"

  log "Removed section matching: $marker"
}

# ============================================================
# HELPER: remove a specific table+rules block for a named table
# Used for GeoIP (per-country) and feeds (per-feed).
# Removes from "# GeoIP: CC" or "# Feed N:" comment through
# the last block/pass rule referencing that table.
# ============================================================
remove_table_block() {
  local tbl="$1" # e.g. geoip_vn or feed_001
  local tmp="${ADDONS_CONF}.tmp"

  # Remove all lines referencing the table, the table definition,
  # and its preceding comment line. We do a two-pass approach:
  # Pass 1: mark the start (comment line before table <tbl>)
  # Pass 2: remove from that mark through the last rule using <tbl>

  awk -v tbl="$tbl" '
    BEGIN { skip=0 }
    # Detect the comment line immediately before the table definition
    /^# (GeoIP|Feed)/ {
        # peek ahead -- if next non-blank line defines our table, mark for skip
        comment_line = $0
        getline next_line
        if (next_line ~ ("table <" tbl ">")) {
            skip = 1
            next
        } else {
            print comment_line
            print next_line
            next
        }
    }
    skip && /^(table|block|pass|match)/ && !($0 ~ tbl) {
        # We have left the block for this table
        skip = 0
        print
        next
    }
    skip { next }
    { print }
    ' "$ADDONS_CONF" > "$tmp" && mv "$tmp" "$ADDONS_CONF"

  log "Removed table block: $tbl"
}

# ============================================================
# HELPER: remove a single rule line from custom-rules.txt
# and from the CUSTOM PF RULES section of pf-addons.conf
# ============================================================
remove_custom_rule() {
  local rule="$1"
  local tmp

  # Remove from queue file
  local qfile="$USER_INPUT/custom-rules.txt"
  if [ -f "$qfile" ]; then
    tmp="${qfile}.tmp"
    grep -vxF "$rule" "$qfile" > "$tmp" && mv "$tmp" "$qfile" || true
    log "Removed custom rule from queue: $rule"
  fi

  # Remove from pf-addons.conf
  tmp="${ADDONS_CONF}.tmp"
  grep -vxF "$rule" "$ADDONS_CONF" > "$tmp" && mv "$tmp" "$ADDONS_CONF" || true
  log "Removed custom rule from conf: $rule"
}

# ============================================================
# HELPER: reload anchor after conf modification
# Tests first, aborts and logs on failure.
# ============================================================
reload_anchor() {
  # Trim blank lines left by section removal (cosmetic only)
  local tmp="${ADDONS_CONF}.tmp"
  sed '/^$/N;/^\n$/d' "$ADDONS_CONF" > "$tmp" && mv "$tmp" "$ADDONS_CONF" || true

  # If conf is now empty/whitespace-only, flush and zero it
  if ! grep -qE '^(table|block|pass|match)' "$ADDONS_CONF" 2> /dev/null; then
    log "Conf has no rules -- flushing anchor"
    pfctl -a "$ANCHOR" -F all 2> /dev/null || true
    : > "$ADDONS_CONF"
    return 0
  fi

  # Test
  local out
  out=$(pfctl -a "$ANCHOR" -nf "$ADDONS_CONF" 2>&1) || {
    log "ERROR: pfctl -nf failed after deletion: $out"
    return 1
  }
  if [ -n "$out" ]; then
    log "ERROR: pfctl -nf had output: $out"
    return 1
  fi

  # Load
  pfctl -a "$ANCHOR" -f "$ADDONS_CONF" 2> /dev/null || {
    log "ERROR: pfctl load failed"
    return 1
  }

  log "Anchor reloaded successfully"
  return 0
}

# ============================================================
# DISPATCH BY TYPE
# ============================================================
case "$TYPE" in

  ip_block)
    log "Deleting IP block section"
    flush_table "user_block_ips"
    remove_section "USER IP BLOCK LIST"
    : > "$USER_INPUT/ip-block.txt"
    reload_anchor || {
      write_outcome "$REQUEST_FILE" "false" "Reload failed after ip_block deletion"
      exit 1
    }
    write_outcome "$REQUEST_FILE" "true" "IP block list removed"
    ;;

  ip_pass)
    log "Deleting IP pass section"
    flush_table "user_pass_ips"
    remove_section "USER IP PASS LIST"
    : > "$USER_INPUT/ip-pass.txt"
    reload_anchor || {
      write_outcome "$REQUEST_FILE" "false" "Reload failed after ip_pass deletion"
      exit 1
    }
    write_outcome "$REQUEST_FILE" "true" "IP pass list removed"
    ;;

  asn_block)
    log "Deleting ASN block section"
    flush_table "user_asn_block"
    remove_section "USER ASN BLOCK LIST"
    : > "$USER_INPUT/asn-block.txt"
    reload_anchor || {
      write_outcome "$REQUEST_FILE" "false" "Reload failed after asn_block deletion"
      exit 1
    }
    write_outcome "$REQUEST_FILE" "true" "ASN block removed"
    ;;

  geoip)
    if [ -z "$COUNTRY" ]; then
      write_outcome "$REQUEST_FILE" "false" "Missing country code in request"
      exit 1
    fi
    CC_LOWER=$(echo "$COUNTRY" | tr '[:upper:]' '[:lower:]')
    TBL="geoip_${CC_LOWER}"
    log "Deleting GeoIP block: $COUNTRY (table $TBL)"

    flush_table "$TBL"
    remove_table_block "$TBL"

    # Remove country from geoip-policy.json
    GEOIP_JSON="$USER_INPUT/geoip-policy.json"
    if [ -f "$GEOIP_JSON" ] && [ -s "$GEOIP_JSON" ]; then
      # Remove the country code from the countries array using sed
      # Handles both "CC" and 'CC' with surrounding commas and whitespace
      sed -i "s/\"$COUNTRY\",\?[[:space:]]*//" "$GEOIP_JSON" 2> /dev/null || true
      sed -i "s/,\?[[:space:]]*\"$COUNTRY\"//" "$GEOIP_JSON" 2> /dev/null || true
      # If countries array is now empty, zero the file
      if ! grep -q '"[A-Z][A-Z]"' "$GEOIP_JSON" 2> /dev/null; then
        : > "$GEOIP_JSON"
        log "geoip-policy.json now empty -- zeroed"
      fi
    fi

    reload_anchor || {
      write_outcome "$REQUEST_FILE" "false" "Reload failed after geoip deletion ($COUNTRY)"
      exit 1
    }
    write_outcome "$REQUEST_FILE" "true" "GeoIP block for $COUNTRY removed"
    ;;

  feed)
    if [ -z "$FEED_IDX" ]; then
      write_outcome "$REQUEST_FILE" "false" "Missing feed_index in request"
      exit 1
    fi
    TBL=$(printf "feed_%03d" "$FEED_IDX")
    log "Deleting feed: index=$FEED_IDX table=$TBL"

    flush_table "$TBL"
    remove_table_block "$TBL"

    # Remove corresponding line from feed-urls.txt
    # The feed index in the conf corresponds to the Nth non-empty line
    FEED_FILE="$USER_INPUT/feed-urls.txt"
    if [ -f "$FEED_FILE" ]; then
      tmp="${FEED_FILE}.tmp"
      awk -v idx="$FEED_IDX" '
                /[^[:space:]]/ { count++; if (count != idx) print }
            ' "$FEED_FILE" > "$tmp" && mv "$tmp" "$FEED_FILE"
      log "Removed feed line $FEED_IDX from feed-urls.txt"
    fi

    reload_anchor || {
      write_outcome "$REQUEST_FILE" "false" "Reload failed after feed deletion"
      exit 1
    }
    write_outcome "$REQUEST_FILE" "true" "Feed $FEED_IDX removed"
    ;;

  custom)
    if [ -z "$RULE" ]; then
      write_outcome "$REQUEST_FILE" "false" "Missing rule in request"
      exit 1
    fi
    log "Deleting custom rule: $RULE"
    remove_custom_rule "$RULE"
    reload_anchor || {
      write_outcome "$REQUEST_FILE" "false" "Reload failed after custom rule deletion"
      exit 1
    }
    write_outcome "$REQUEST_FILE" "true" "Custom rule removed"
    ;;

  entry_delete)
    # Remove specific IPs/CIDRs from a table definition in pf-addons.conf.
    # Reads "entries" array and "table" from the request JSON.
    # Removes each entry from the table { ... } block in-place,
    # validates with pfctl -nf, then applies.
    #
    # Request fields:
    #   type:       "entry_delete"
    #   block_type: "ip_block|ip_pass|asn_block|geoip|feed"
    #   table:      "user_block_ips"
    #   entries:    ["1.2.3.4", "5.6.7.0/24", ...]
    ETABLE=$(grep '"table"' "$REQUEST_FILE" | sed 's/.*"table"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    ETYPE=$(grep '"block_type"' "$REQUEST_FILE" | sed 's/.*"block_type"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

    if [ -z "$ETABLE" ]; then
      log "ERROR: entry_delete missing table field"
      write_outcome "$REQUEST_FILE" "false" "Missing table in request"
      exit 1
    fi

    # Validate table name: alphanumeric + underscore only
    case "$ETABLE" in
      *[!a-zA-Z0-9_]* | "")
        log "ERROR: entry_delete invalid table name: $ETABLE"
        write_outcome "$REQUEST_FILE" "false" "Invalid table name"
        exit 1
        ;;
    esac

    log "entry_delete: table=$ETABLE type=$ETYPE"

    # Extract entries array from JSON.
    # The request format is:
    #   {"type":"entry_delete","block_type":"...","table":"...","entries":["1.2.3.4","5.6.7.0/24"],...}
    #
    # Strategy: extract the substring between "entries":[ and the closing ]
    # then pull each quoted value. This avoids matching other fields like
    # "table", "type", or the numeric "requested" timestamp.
    ENTRIES_RAW=$(sed 's/.*"entries":\[//' "$REQUEST_FILE" | sed 's/\].*//')
    ENTRIES=$(printf '%s' "$ENTRIES_RAW" \
      | grep -oE '"[0-9a-fA-F.:/ ]+"' \
      | sed 's/"//g' \
      | grep -E '^[0-9a-fA-F.:/ ]+$' \
      | grep -E '^[0-9a-fA-F]') # must start with hex/digit, not space

    if [ -z "$ENTRIES" ]; then
      log "ERROR: entry_delete no valid entries found in request"
      write_outcome "$REQUEST_FILE" "false" "No valid entries in request"
      exit 1
    fi

    ENTRY_COUNT=$(echo "$ENTRIES" | wc -l | tr -d ' ')
    log "entry_delete: removing $ENTRY_COUNT entries from <$ETABLE>"

    if [ ! -f "$ADDONS_CONF" ] || [ ! -s "$ADDONS_CONF" ]; then
      write_outcome "$REQUEST_FILE" "false" "pf-addons.conf absent or empty"
      exit 1
    fi

    # Remove each entry from the table definition in the conf.
    # The table block looks like:
    #   table <name> persist { \
    #       1.2.3.4, \
    #       5.6.7.0/24 \
    #   }
    # Strategy: use awk to identify when we are inside the target table's
    # brace block and skip lines that match any of our target entries.
    # After removal, rebuild continuation syntax (commas and backslashes).
    TMP="${ADDONS_CONF}.entry_del.$$"

    # Write entries to a temp file for awk to read
    ENTRIES_FILE="/tmp/pf_del_entries_$$.txt"
    echo "$ENTRIES" > "$ENTRIES_FILE"

    awk -v tbl="$ETABLE" -v efile="$ENTRIES_FILE" '
        BEGIN {
            # Load entries to delete into an associative array
            while ((getline line < efile) > 0) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                if (line != "") del[line] = 1
            }
            close(efile)
            in_tbl = 0
            # Buffer lines that are inside the table block
            buf_count = 0
        }

        # Detect start of our target table
        /table[[:space:]]+</ {
            # Check if this line names our table
            if ($0 ~ ("table[[:space:]]+<" tbl ">")) {
                in_tbl = 1
                buf_count = 0
                # Print the table header line as-is (we rebuild entries below)
                # Strip the existing opening brace content if entries follow on same line
                # Standard format: table <name> persist { \
                # We always print the header; entries go into the buffer
                tbl_header = $0
                # Remove any entries that appear on the same line as table header
                # (edge case -- validator always puts them on separate lines)
                print tbl_header
                next
            }
        }

        in_tbl {
            # Check for closing brace
            if ($0 ~ /^[[:space:]]*}/) {
                in_tbl = 0
                # Rebuild the kept entries with correct continuation syntax
                if (buf_count > 0) {
                    for (i = 1; i <= buf_count; i++) {
                        entry = buf[i]
                        # Strip trailing comma, backslash, whitespace
                        gsub(/[,\\[:space:]]+$/, "", entry)
                        gsub(/^[[:space:]]+/, "", entry)
                        if (i < buf_count) {
                            print "    " entry ", \\"
                        } else {
                            print "    " entry " \\"
                        }
                    }
                }
                print "}"
                next
            }

            # Extract the IP/CIDR value from this line
            line = $0
            gsub(/^[[:space:]]+/, "", line)   # trim leading
            gsub(/[,\\[:space:]]+$/, "", line) # trim trailing comma/backslash/space

            # Skip if this entry is in our delete set
            if (line in del) next

            # Keep it -- buffer for later rebuild
            buf_count++
            buf[buf_count] = line
            next
        }

        # Outside table block -- print as-is
        { print }
        ' "$ADDONS_CONF" > "$TMP"

    rm -f "$ENTRIES_FILE"

    if [ ! -s "$TMP" ]; then
      rm -f "$TMP"
      log "ERROR: entry_delete awk produced empty output"
      write_outcome "$REQUEST_FILE" "false" "Conf edit produced empty file"
      exit 1
    fi

    # Validate the edited conf before replacing
    PFCTL_OUT=$(pfctl -a addons -nf "$TMP" 2>&1)
    PFCTL_EXIT=$?

    if [ "$PFCTL_EXIT" -ne 0 ]; then
      rm -f "$TMP"
      log "ERROR: entry_delete pfctl -nf failed: $PFCTL_OUT"
      write_outcome "$REQUEST_FILE" "false" "pfctl validation failed after entry removal: $PFCTL_OUT"
      exit 1
    fi

    # Replace the live conf and apply
    mv "$TMP" "$ADDONS_CONF"
    chown root:wheel "$ADDONS_CONF"
    chmod 0640 "$ADDONS_CONF"

    # Also remove entries from the live kernel table immediately
    # (pfctl -f will rebuild it from conf anyway, but this makes it instant)
    echo "$ENTRIES" | while IFS= read -r entry; do
      [ -z "$entry" ] && continue
      pfctl -a "$ANCHOR" -t "$ETABLE" -T delete "$entry" 2> /dev/null || true
    done

    # Load updated conf into anchor
    pfctl -a "$ANCHOR" -f "$ADDONS_CONF" 2> /dev/null || {
      log "ERROR: entry_delete pfctl load failed"
      write_outcome "$REQUEST_FILE" "false" "pfctl load failed after entry removal"
      exit 1
    }

    log "entry_delete: $ENTRY_COUNT entries removed from <$ETABLE>, anchor reloaded"
    write_outcome "$REQUEST_FILE" "true" \
      "Removed $ENTRY_COUNT entr$([ "$ENTRY_COUNT" -eq 1 ] && echo 'y' || echo 'ies') from <$ETABLE>"
    ;;

  *)
    log "ERROR: unknown type: $TYPE"
    write_outcome "$REQUEST_FILE" "false" "Unknown deletion type: $TYPE"
    exit 1
    ;;
esac

# ============================================================
# REFRESH active-addons.json
# ============================================================
"$SYNC_SCRIPT" 2>&1 >> "$LOG_FILE" || true

# Update current rules snapshot
pfctl -sr > "$QUEUE_BASE/current" 2> /dev/null || true
chown www:www "$QUEUE_BASE/current" 2> /dev/null || true
chmod 0644 "$QUEUE_BASE/current" 2> /dev/null || true

log "Delete operation complete: type=$TYPE"
exit 0
