# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

COMMENT=                Automatically block IP addresses from snort alerts

DISTNAME=               snortsentry-v8.1.7
PKGNAME=                snortsentry-8.1.7
CATEGORIES=             net security tangentnetworks

DIST_TUPLE=             gitlab tangentnetworks snortsentry v8.1.7 .

HOMEPAGE=               https://gitlab.com/tangentnetworks/snortsentry
MASTER_SITES=           ${HOMEPAGE}/-/archive/v${V}/

MAINTAINER=             David Peter, Tangent Networks <tangent.net@zohomail.in>

PERMIT_PACKAGE=         Yes

NO_BUILD=               Yes

RUN_DEPENDS=            net/p5-Net-IP \
                        converters/p5-JSON-XS

DOCFILES=               README
DOCDIR=                 ${PREFIX}/share/doc/snortsentry
EXAMPLEDIR=             ${PREFIX}/share/examples/snortsentry



WRKSRC=                 ${WRKDIR}/snortsentry-v8.1.7-29082cf7afe0113cc349de5cd9eaa1bf178f4ad2

do-install:
	${INSTALL_SCRIPT} ${WRKSRC}/snortsentry ${DESTDIR}${TRUEPREFIX}/sbin/
	${INSTALL_MAN}    ${WRKSRC}/snortsentry.8 ${DESTDIR}${TRUEPREFIX}/man/man8/
	${INSTALL_DATA_DIR} ${DESTDIR}${TRUEPREFIX}/share/examples/snortsentry
	${INSTALL_DATA} ${WRKSRC}/snortsentry.conf ${DESTDIR}${TRUEPREFIX}/share/examples/snortsentry/
	${INSTALL_DATA_DIR} ${DESTDIR}${TRUEPREFIX}/share/doc/snortsentry/
	${INSTALL_DATA} ${WRKSRC}/README ${DESTDIR}${TRUEPREFIX}/share/doc/snortsentry/

.include <bsd.port.mk>

