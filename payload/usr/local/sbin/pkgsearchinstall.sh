#! /bin/ksh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

#
# Author:   Calum MacRae  (original concept)
# Maintainer: Tangent Networks
# Updated:  Oct 2025, for OpenBSD 7.8
#
# Summary:
#   Interactive wrapper for pkg_info(1) and pkg_add(1).
#   Lets the user search available packages and install one by index.
#   Written in base ksh for portability and clarity.
#

#---------------------------------------------
# Check arguments
#---------------------------------------------
if [[ $# -ne 1 ]]; then
  print "Usage: ${0##*/} <search-term>"
  exit 1
fi

term=$1

#---------------------------------------------
# Query the package database
#---------------------------------------------
print "Searching package database for '$term'..."
results=$(pkg_info -Q "$term" 2> /dev/null)

if [[ -z $results ]]; then
  print "No packages found matching '$term'."
  exit 1
fi

# Number the results for selection
nl=1
print
print "Matches:"
print "---------"
print "$results" | while IFS= read -r pkg; do
  printf "%3d) %s\n" "$nl" "$pkg"
  ((nl += 1))
done

total=$(print "$results" | wc -l | awk '{print $1}')
print
print "Found $total package(s). Enter a number to install, or 0 to quit."

#---------------------------------------------
# Interactive selection and installation
#---------------------------------------------
while :; do
  print -n "Selection: "
  read ans

  case $ans in
    [0-9]*)
      if ((ans == 0)); then
        print "Exiting without installing."
        exit 0
      elif ((ans > total)); then
        print "Please choose a number between 1 and $total."
      else
        selected=$(print "$results" | sed -n "${ans}p")
        print "\nInstalling $selected..."
        pkg_add -ivv "$selected" && print "\n$selected installed successfully."
        exit 0
      fi
      ;;
    *)
      print "Enter a valid number between 0 and $total."
      ;;
  esac
done
