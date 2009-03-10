# New ports collection makefile for:   monkeysphere
# Date created:        2008-09-11 23:38:27-0400
# Whom:                Daniel Kahn Gillmor <dkg@fifthhorseman.net>
#
# $FreeBSD$
#

PORTNAME=      monkeysphere
PORTVERSION=   0.24
CATEGORIES=    security
MASTER_SITES=  http://archive.monkeysphere.info/debian/pool/monkeysphere/m/monkeysphere/
# hack for debian orig tarballs
DISTFILES=      ${PORTNAME}_${DISTVERSION}.orig.tar.gz

MAINTAINER=    dkg@fifthhorseman.net
COMMENT=       use the OpenPGP web of trust to verify ssh connections

RUN_DEPENDS=    gpg:${PORTSDIR}/security/gnupg1 \
		lockfile:${PORTSDIR}/mail/procmail \
		bash:${PORTSDIR}/shells/bash \
		${SITE_PERL}/${PERL_ARCH}/Crypt/OpenSSL/RSA.pm:${PORTSDIR}/security/p5-Crypt-OpenSSL-RSA \
		${SITE_PERL}/${PERL_ARCH}/Digest/SHA1.pm:${PORTSDIR}/security/p5-Digest-SHA1

MAN1=		monkeysphere.1 openpgp2ssh.1 pem2openpgp.1
MAN7=		monkeysphere.7
MAN8=		monkeysphere-host.8 monkeysphere-authentication.8
MANCOMPRESSED= yes

MAKE_ARGS= ETCPREFIX=${PREFIX} MANPREFIX=${PREFIX}/man ETCSUFFIX=.sample

# get rid of cruft after the patching:
post-patch:
	find . -iname '*.orig' -delete

post-install:
	@if [ ! -f ${PREFIX}/etc/monkeysphere/monkeysphere.conf ]; then \
		${CP} -p ${PREFIX}/etc/monkeysphere/monkeysphere.conf.sample ${PREFIX}/etc/monkeysphere/monkeysphere.conf ; \
	fi
	@if [ ! -f ${PREFIX}/etc/monkeysphere/monkeysphere-host.conf ]; then \
		${CP} -p ${PREFIX}/etc/monkeysphere/monkeysphere-host.conf.sample ${PREFIX}/etc/monkeysphere/monkeysphere-host.conf ; \
	fi
	@if [ ! -f ${PREFIX}/etc/monkeysphere/monkeysphere-authentication.conf ]; then \
		${CP} -p ${PREFIX}/etc/monkeysphere/monkeysphere-authentication.conf.sample ${PREFIX}/etc/monkeysphere/monkeysphere-authentication.conf ; \
	fi
.if !defined(PACKAGE_BUILDING)
	@${SETENV} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL
.endif

post-deinstall:
	@${SETENV} ${SH} ${PKGDEINSTALL} ${PKGNAME} POST-DEINSTALL

.include <bsd.port.mk>
