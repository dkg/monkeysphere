# New ports collection makefile for:   oneko
# Date created:        5 December 1994
# Whom:                asami
#
# $FreeBSD$
#

PORTNAME=      monkeysphere
PORTVERSION=   0.14
CATEGORIES=    security
MASTER_SITES=  http://archive.monkeysphere.info/debian/pool/monkeysphere/m/monkeysphere/
# hack for debian orig tarballs
DISTFILES=      ${PORTNAME}_${DISTVERSION}.orig.tar.gz

# comment this out to test the port
IGNORE=			this port is not finished yet

MAINTAINER=    anarcat@anarcat.ath.cx
COMMENT=       use the OpenPGP web of trust to verify ssh connections

LIB_DEPENDS=	gnutls.26:${PORTSDIR}/security/gnutls
RUN_DEPENDS=    base64:${PORTSDIR}/converters/base64 \
		gpg:${PORTSDIR}/security/gnupg \
		nc:${PORTSDIR}/net/netcat \
		bash:${PORTSDIR}/shells/bash

MAN1=		monkeysphere.1 openpgp2ssh.1 monkeysphere-ssh-proxycommand.1
MAN5=		monkeysphere.5
MAN8=		monkeysphere-server.8
MANCOMPRESSED= yes
USE_GMAKE=     yes

.include <bsd.port.mk>
