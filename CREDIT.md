<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# CREDITS

## Prior Art and Third Party Contributions

### Soner Tari
https://github.com/sonertari

Developer of UTMFW, the OpenBSD UTM project that established the
foundational architecture from which this project draws inspiration.

### Direct Components Used

#### SSLproxy
SSL/TLS inspection proxy, patched for dual-stack IPv4/IPv6 operation.

#### Snort
Network intrusion detection and prevention system.
Patched for dual-stack operation.

This project is an independent reimplementation. The installer,
configuration pipeline, WebUI, log infrastructure, service
orchestration, and chroot architecture are original work.

Soner Tari's prior art provided the initial foundation. What has
been built on top of it has since evolved into a substantially
different system.

## Inspiration

The OpenBSD project and its developers, whose uncompromising
commitment to correctness, security, and simplicity made this
platform worth building on.

To the pf, httpd, and pledge/unveil teams in particular:
the right constraints make better software.

The open source community, mailing lists, man pages, and the quiet
generosity of people who document what they learned so others do not
have to suffer the same failures twice.
