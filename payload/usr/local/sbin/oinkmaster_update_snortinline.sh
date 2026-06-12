#!/bin/sh

# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

# Update Snort rules via Oinkmaster
# -o points to your rules directory
# -C points to your config file

/usr/local/bin/oinkmaster -o /etc/snort/rules -C /etc/oinkmaster.conf > /var/www/htdocs/tn/data/logs/snort/oinkmaster.log 2>&1
