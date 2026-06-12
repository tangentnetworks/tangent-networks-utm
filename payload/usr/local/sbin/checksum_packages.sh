#!/bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# Prompt the user for the packages directory
echo -n "Enter the path to the packages directory: "
read PACKAGES_DIR

# Check if the directory exists
if [ ! -d "$PACKAGES_DIR" ]; then
  echo "Error: Directory '$PACKAGES_DIR' does not exist." >&2
  exit 1
fi

# Output file for SHA256 checksums
OUTPUT_FILE="$PACKAGES_DIR/SHA256"

# Clear or create the output file
> "$OUTPUT_FILE"

# Loop through all .tgz files in the directory
for file in "$PACKAGES_DIR"/*.tgz; do
  # Skip if no .tgz files are found
  [ -e "$file" ] || continue

  # Extract the filename without the path
  filename=$(basename "$file")

  # Calculate the SHA256 checksum
  checksum=$(sha256 -q "$file")

  # Write to the output file in the specified format
  echo "SHA256 ($filename) = $checksum" >> "$OUTPUT_FILE"
done

echo "SHA256 checksums written to $OUTPUT_FILE"
