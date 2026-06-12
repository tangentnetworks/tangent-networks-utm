# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

COMMENT=       transparent SSL/TLS proxy to divert decrypted traffic
GH_ACCOUNT=    sonertari
GH_PROJECT=    SSLproxy
GH_TAGNAME=    v0.9.9

CATEGORIES=    tangentnetworks
HOMEPAGE=      https://github.com/sonertari/SSLproxy
MAINTAINER=    Tangent Networks <tangent.net@zohomail.in>

# SSLproxy: BSD, khash.h (header-based library): MIT
PERMIT_PACKAGE= Yes

WANTLIB += c crypto event_core event_extra event_openssl event_pthreads
WANTLIB += pthread ssl

MASTER_SITES=   https://github.com/sonertari/SSLproxy/

LIB_DEPENDS=    devel/libevent2
BUILD_DEPENDS=  net/libnet/1.1 \
                databases/sqlite3
RUN_DEPENDS=    devel/libevent2 \
                net/libnet/1.1 \
                databases/sqlite3

NO_TEST=        Yes

MAKE_FLAGS=     MANDIR=man PREFIX=${TRUEPREFIX}

USE_GMAKE=      Yes

MAKE_FILE=      GNUmakefile

.include <bsd.port.mk>
