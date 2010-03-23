#!/usr/bin/make -f

# Makefile for monkeysphere

# © 2008-2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
# Licensed under GPL v3 or later

MONKEYSPHERE_VERSION = `head -n1 Changelog | sed 's/.*(\([^-]*\)).*/\1/'`

# these defaults are for debian.  porters should probably adjust them
# before calling make install
ETCPREFIX ?= 
ETCSUFFIX ?= 
PREFIX ?= /usr
MANPREFIX ?= $(PREFIX)/share/man

# nothing actually needs to be built now.
all: 

debian-package:
	git buildpackage -uc -us

# don't explicitly depend on the tarball, since our tarball
# (re)generation is not idempotent even when no source changes.
freebsd-distinfo: 
	./utils/build-freebsd-distinfo

macports-portfile:
	./utils/build-macports-portfile

clean:
	# clean up old monkeysphere packages lying around as well.
	rm -f monkeysphere_*

# this target is to be called from the tarball, not from the git
# working dir!
install: all installman
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/sbin
	mkdir -p $(DESTDIR)$(PREFIX)/share/monkeysphere/m $(DESTDIR)$(PREFIX)/share/monkeysphere/mh $(DESTDIR)$(PREFIX)/share/monkeysphere/ma $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions
	mkdir -p $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
	printf "Monkeysphere %s\n" $(MONKEYSPHERE_VERSION) > $(DESTDIR)$(PREFIX)/share/monkeysphere/VERSION
	install src/monkeysphere $(DESTDIR)$(PREFIX)/bin
	install src/monkeysphere-host src/monkeysphere-authentication $(DESTDIR)$(PREFIX)/sbin
	install -m 0644 src/share/common $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0644 src/share/defaultenv $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0755 src/share/checkperms $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0755 src/share/keytrans $(DESTDIR)$(PREFIX)/share/monkeysphere
	ln -s ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/pem2openpgp
	ln -s ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/openpgp2ssh
	install -m 0744 src/transitions/* $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions
	install -m 0644 src/transitions/README.txt $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions
	install -m 0644 src/share/m/* $(DESTDIR)$(PREFIX)/share/monkeysphere/m
	install -m 0644 src/share/mh/* $(DESTDIR)$(PREFIX)/share/monkeysphere/mh
	install -m 0644 src/share/ma/* $(DESTDIR)$(PREFIX)/share/monkeysphere/ma
	install Changelog $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
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

test: test-keytrans test-basic

test-basic:
	MONKEYSPHERE_TEST_NO_EXAMINE=true ./tests/basic

test-keytrans:
	MONKEYSPHERE_TEST_NO_EXAMINE=true ./tests/keytrans

.PHONY: all tarball debian-package freebsd-distinfo clean install installman releasenote test
