# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

COMMENT=                content scanning transparent POP3 proxy
DISTNAME=               p3scan-2.3.2
CATEGORIES=             tangentnetworks

HOMEPAGE=               https://sourceforge.net/projects/p3scan/
MASTER_SITES=           ${MASTER_SITE_SOURCEFORGE:=p3scan/}
SITES +=                https://downloads.sourceforge.net/project/p3scan/p3scan%20%28stable%29/p3scan-2.3.2/

MAINTAINER=             Tangent Networks <tangent.net@zohomail.in>

# GPL
PERMIT_PACKAGE= Yes

WANTLIB=                c crypto ssl
BUILD_DEPENDS=          devel/pcre

SEPARATE_BUILD=         No
CONFIGURE_STYLE=        No

DATADIR=                /var/spool/p3scan
P3SCANUSER=             _p3scan:_p3scan
SUBST_VARS=             DATADIR P3SCANUSER

FAKE_FLAGS+=            rel_group=_p3scan rel_user=_p3scan

pre-configure:
	@perl -pi -e 's,!!LOCALBASE!!,${LOCALBASE},g' ${WRKSRC}/p3scan.conf ${WRKSRC}/p3scan.h
	@gunzip ${WRKSRC}/p3scan.8.gz
	@gunzip ${WRKSRC}/p3scan_readme.8.gz

.include <bsd.port.mk>

