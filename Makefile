#!/usr/bin/make -f

# Makefile for monkeysphere

# (c) 2008-2009 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
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
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/sbin
	mkdir -p $(DESTDIR)$(PREFIX)/share/monkeysphere/m $(DESTDIR)$(PREFIX)/share/monkeysphere/mh $(DESTDIR)$(PREFIX)/share/monkeysphere/ma $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions
	mkdir -p $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
	install src/monkeysphere src/keytrans/openpgp2ssh src/keytrans/pem2openpgp $(DESTDIR)$(PREFIX)/bin
	install src/monkeysphere-host src/monkeysphere-authentication $(DESTDIR)$(PREFIX)/sbin
	install -m 0644 src/share/common $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0744 src/transitions/* $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions
	install -m 0644 src/share/m/* $(DESTDIR)$(PREFIX)/share/monkeysphere/m
	install -m 0644 src/share/mh/* $(DESTDIR)$(PREFIX)/share/monkeysphere/mh
	install -m 0644 src/share/ma/* $(DESTDIR)$(PREFIX)/share/monkeysphere/ma
	install doc/* $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
	install -m 0644 etc/monkeysphere.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/monkeysphere.conf$(ETCSUFFIX)
	install -m 0644 etc/monkeysphere-host.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/monkeysphere-host.conf$(ETCSUFFIX)
	install -m 0644 etc/monkeysphere-authentication.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/monkeysphere-authentication.conf$(ETCSUFFIX)

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
