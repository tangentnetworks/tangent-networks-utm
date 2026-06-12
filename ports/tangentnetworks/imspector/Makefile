# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause

COMMENT=		instant messaging transparent proxy
DISTNAME=		imspector-0.9
PKGNAME=		${DISTNAME}
CATEGORIES=		tangentnetworks

HOMEPAGE=		http://www.imspector.org
#SITES+=			https://mirror2.openwrt.org/sources/imspector-0.7.tar.gz
SITES=			https://mirror2.openwrt.org/sources/
	
MAINTAINER=		Soner Tari <sonertari@gmail.com>

# GPL
PERMIT_PACKAGE=	Yes

WANTLIB+=		${COMPILER_LIBCXX} c m
CONFIGURE_STYLE=	No
BUILD_DEPENDS=		databases/sqlite3

FAKE_FLAGS+=		rel_group=_imspector rel_user=_imspector

.include <bsd.port.mk>
