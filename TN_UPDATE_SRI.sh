#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# Script: TN_UPDATE_SRI.sh
# Description: Fixed POSIX version for OpenBSD (Corrected -i syntax)
#

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

DATA_FILE="${SCRIPT_DIR}/sri_data.dat"

if [ ! -f "$DATA_FILE" ]; then
    echo "Error: Reference file $DATA_FILE not found. Run TN_GET_SRI.sh first."
    exit 1
fi

# Source the generated data maps
. "$DATA_FILE"

# Process /var/www/htdocs/tn/*.html files safely
for file in /var/www/htdocs/tn/*.html; do
    [ ! -f "$file" ] && continue
    echo "Processing: $file"
    
    get_sri_data | while IFS="|" read -r script hash; do
        [ -z "$script" ] && continue
        
        # OpenBSD: -i with no arguments modifies the target $file directly 
        sed -E -i "s|(src=\"[^\"]*${script}\"[^>]*integrity=\")[^\"]*\"|\1${hash}\"|g" "$file"
        sed -E -i "s|(integrity=\")[^\"]*\"([^>]*src=\"[^\"]*${script}\")|\1${hash}\"\2|g" "$file"
    done
done

# Process files in /var/www/htdocs/tn/view/ without extension
find /var/www/htdocs/tn/view -maxdepth 1 -type f | while IFS= read -r file; do
    [ ! -f "$file" ] && continue
    echo "Processing: $file"
    
    get_sri_data | while IFS="|" read -r script hash; do
        [ -z "$script" ] && continue
        
        # OpenBSD: -i with no arguments modifies the target $file directly
        sed -E -i "s|(src=\"[^\"]*${script}\"[^\>]*integrity=\")[^\"]*\"|\1${hash}\"|g" "$file"
        sed -E -i "s|(integrity=\")[^\"]*\"([^>]*src=\"[^\"]*${script}\")|\1${hash}\"\2|g" "$file"
    done
done

echo "SRI Automations complete and synchronized!"
