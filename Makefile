#!/usr/bin/make -f

# Makefile for monkeysphere

# (c) 2008 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
# Licensed under GPL v3 or later

MONKEYSPHERE_VERSION = `head -n1 packaging/debian/changelog | sed 's/.*(\([^-]*\)-.*/\1/'`

# these defaults are for debian.  porters should probably adjust them
# before calling make install
ETCPREFIX ?= 
ETCSUFFIX ?= 
PREFIX ?= /usr
MANPREFIX ?= $(PREFIX)/share/man

all: keytrans

keytrans:
	$(MAKE) -C src/keytrans

tarball: clean
	rm -rf monkeysphere-$(MONKEYSPHERE_VERSION)
	mkdir -p monkeysphere-$(MONKEYSPHERE_VERSION)/doc
	ln -s ../../website/getting-started-user.mdwn ../../website/getting-started-admin.mdwn ../../doc/TODO ../../doc/MonkeySpec monkeysphere-$(MONKEYSPHERE_VERSION)/doc
	ln -s ../COPYING ../etc ../Makefile ../man ../src ../tests monkeysphere-$(MONKEYSPHERE_VERSION)
	tar -ch --exclude='*~' monkeysphere-$(MONKEYSPHERE_VERSION) | gzip -n > monkeysphere_$(MONKEYSPHERE_VERSION).orig.tar.gz
	rm -rf monkeysphere-$(MONKEYSPHERE_VERSION)

debian-package: tarball
	tar xzf monkeysphere_$(MONKEYSPHERE_VERSION).orig.tar.gz
	cp -a packaging/debian monkeysphere-$(MONKEYSPHERE_VERSION)
	(cd monkeysphere-$(MONKEYSPHERE_VERSION) && debuild -uc -us)
	rm -rf monkeysphere-$(MONKEYSPHERE_VERSION)

# don't explicitly depend on the tarball, since our tarball
# (re)generation is not idempotent even when no source changes.
freebsd-distinfo: 
	./utils/build-freebsd-distinfo

clean:
	$(MAKE) -C src/keytrans clean
	# clean up old monkeysphere packages lying around as well.
	rm -f monkeysphere_*

# this target is to be called from the tarball, not from the git
# working dir!
install: all installman
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/share/monkeysphere
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
	mkdir -p $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere
	install src/monkeysphere src/monkeysphere-ssh-proxycommand src/keytrans/openpgp2ssh $(DESTDIR)$(PREFIX)/bin
	install src/monkeysphere-server $(DESTDIR)$(PREFIX)/sbin
	install -m 0644 src/common $(DESTDIR)$(PREFIX)/share/monkeysphere
	install doc/* $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
	install -m 0644 etc/gnupg-host.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/gnupg-host.conf$(ETCSUFFIX)
	install -m 0644 etc/gnupg-authentication.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/gnupg-authentication.conf$(ETCSUFFIX)
	install -m 0644 etc/monkeysphere.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/monkeysphere.conf$(ETCSUFFIX)
	install -m 0644 etc/monkeysphere-server.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/monkeysphere-server.conf$(ETCSUFFIX)

installman:
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1 $(DESTDIR)$(MANPREFIX)/man7 $(DESTDIR)$(MANPREFIX)/man8
	gzip -n man/*/*
	install man/man1/* $(DESTDIR)$(MANPREFIX)/man1
	install man/man7/* $(DESTDIR)$(MANPREFIX)/man7
	install man/man8/* $(DESTDIR)$(MANPREFIX)/man8
	gzip -d man/*/*

releasenote:
	./utils/build-releasenote

.PHONY: all tarball debian-package freebsd-distinfo clean install installman releasenote
