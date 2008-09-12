# New ports collection makefile for:   monkeysphere
# Date created:        2008-09-11 23:38:27-0400
# Whom:                Daniel Kahn Gillmor <dkg@fifthhorseman.net>
#
# $FreeBSD$
#

PORTNAME=      monkeysphere
PORTVERSION=   0.16~pre
CATEGORIES=    security
MASTER_SITES=  http://archive.monkeysphere.info/debian/pool/monkeysphere/m/monkeysphere/
# hack for debian orig tarballs
DISTFILES=      ${PORTNAME}_${DISTVERSION}.orig.tar.gz

# comment this out to test the port
IGNORE=			this port is not finished yet

MAINTAINER=    dkg@fifthhorseman.net
COMMENT=       use the OpenPGP web of trust to verify ssh connections

LIB_DEPENDS=	gnutls.26:${PORTSDIR}/security/gnutls
RUN_DEPENDS=    base64:${PORTSDIR}/converters/base64 \
		gpg:${PORTSDIR}/security/gnupg \
		lockfile:${PORTSDIR}/mail/procmail \
		getopt:${PORTSDIR}/misc/getopt \
		bash:${PORTSDIR}/shells/bash

MAN1=		monkeysphere.1 openpgp2ssh.1 monkeysphere-ssh-proxycommand.1
MAN7=		monkeysphere.7
MAN8=		monkeysphere-server.8
MANCOMPRESSED= yes

MAKE_ARGS= ETCPREFIX=/usr/local MANPREFIX=/usr/local/man ETCSUFFIX=.sample

# get rid of cruft after the patching:
post-patch:
	find . -iname '*.orig' -delete

post-install:
	@if [ ! -f ${PREFIX}/etc/monkeysphere/monkeysphere.conf ]; then \
		${CP} -p ${PREFIX}/etc/monkeysphere/monkeysphere.conf.sample ${PREFIX}/etc/monkeysphere/monkeysphere.conf ; \
	fi
	@if [ ! -f ${PREFIX}/etc/monkeysphere/monkeysphere-server.conf ]; then \
		${CP} -p ${PREFIX}/etc/monkeysphere/monkeysphere-server.conf.sample ${PREFIX}/etc/monkeysphere/monkeysphere-server.conf ; \
	fi

.include <bsd.port.mk>
