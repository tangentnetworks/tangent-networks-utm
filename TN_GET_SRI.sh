#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# Script: TN_GET_SRI.sh
# Description: Fully path-neutral SRI generator for OpenBSD ksh.
# Usage: ./TN_GET_SRI.sh /var/www/htdocs/tn/js
#

if [ $# -ne 1 ]; then
    echo "Usage: $0 /path/to/files"
    exit 1
fi

# Strip trailing slash if present
TARGET_PATH="${1%/}"

if [ ! -d "$TARGET_PATH" ]; then
    echo "Error: Directory '$TARGET_PATH' does not exist."
    exit 1
fi

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

DATA_OUTPUT="${SCRIPT_DIR}/sri_data.dat"

# Initialize the data file format
echo "get_sri_data() {" > "$DATA_OUTPUT"
echo "cat << 'EOF'" >> "$DATA_OUTPUT"

echo "=== Raw Script Tags (Path-Neutral) ==="

for file in "$TARGET_PATH"/*; do
    if [ ! -f "$file" ]; then
        continue
    fi

    filename=$(basename "$file")

    case "$filename" in
        *.js)
            # Compute hash using full path
            hash=$(openssl dgst -sha384 -binary "$file" | openssl base64 -A)
            full_sri="sha384-$hash"

            # 1. Force the relative/clamped path format in stdout
            echo "<script src=\"./assets/js/$filename\" defer integrity=\"$full_sri\" crossorigin=\"anonymous\"></script>"

            # 2. Keep the dat file working purely on filenames for mapping
            echo "${filename}|${full_sri}" >> "$DATA_OUTPUT"
            ;;
    esac
done

echo "EOF" >> "$DATA_OUTPUT"
echo "}" >> "$DATA_OUTPUT"

echo "======================================"
echo "Data format reference written to: $DATA_OUTPUT"
