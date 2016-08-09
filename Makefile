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
LOCALSTATEDIR ?= /var/lib

CFLAGS +=  $(shell libassuan-config --cflags --libs)
CFLAGS +=  $(shell libgcrypt-config --cflags --libs)
CFLAGS += --pedantic -Wall -Werror -std=c99

all: src/agent-transfer/agent-transfer

src/agent-transfer/agent-transfer: src/agent-transfer/main.c src/agent-transfer/ssh-agent-proto.h
	gcc -o $@ $(CFLAGS) $(LDFLAGS) $<

debian-package:
	git buildpackage -uc -us

# don't explicitly depend on the tarball, since our tarball
# (re)generation is not idempotent even when no source changes.
freebsd-distinfo: 
	./utils/build-freebsd-distinfo

macports-portfile:
	./utils/build-macports-portfile

clean:
	rm -f src/agent-transfer/agent-transfer
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
	sed -i 's:__SYSSHAREDIR_PREFIX__:$(PREFIX):' $(DESTDIR)$(PREFIX)/bin/monkeysphere
	install src/monkeysphere-host $(DESTDIR)$(PREFIX)/sbin
	sed -i 's:__SYSSHAREDIR_PREFIX__:$(PREFIX):' $(DESTDIR)$(PREFIX)/sbin/monkeysphere-host
	install src/monkeysphere-authentication $(DESTDIR)$(PREFIX)/sbin
	sed -i 's:__SYSSHAREDIR_PREFIX__:$(PREFIX):' $(DESTDIR)$(PREFIX)/sbin/monkeysphere-authentication
	install src/monkeysphere-authentication-keys-for-user $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0644 src/share/common $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0644 src/share/defaultenv $(DESTDIR)$(PREFIX)/share/monkeysphere
	sed -i 's:__SYSCONFDIR_PREFIX__:$(ETCPREFIX):' $(DESTDIR)$(PREFIX)/share/monkeysphere/defaultenv
	sed -i 's:__SYSDATADIR_PREFIX__:$(LOCALSTATEDIR):' $(DESTDIR)$(PREFIX)/share/monkeysphere/defaultenv
	install -m 0755 src/share/checkperms $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0755 src/share/keytrans $(DESTDIR)$(PREFIX)/share/monkeysphere
	ln -sf ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/pem2openpgp
	ln -sf ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/openpgp2ssh
	ln -sf ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/openpgp2pem
	ln -sf ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/openpgp2spki
	install -m 0755 src/agent-transfer/agent-transfer $(DESTDIR)$(PREFIX)/bin
	install -m 0744 src/transitions/* $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions
	sed -i 's:__SYSSHAREDIR_PREFIX__:$(PREFIX):' $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions/0.23
	sed -i 's:__SYSSHAREDIR_PREFIX__:$(PREFIX):' $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions/0.28
	install -m 0644 src/transitions/README.txt $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions
	install -m 0644 src/share/m/* $(DESTDIR)$(PREFIX)/share/monkeysphere/m
	install -m 0644 src/share/mh/* $(DESTDIR)$(PREFIX)/share/monkeysphere/mh
	install -m 0644 src/share/ma/* $(DESTDIR)$(PREFIX)/share/monkeysphere/ma
	install -m 0644 Changelog $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
	install -d $(DESTDIR)$(PREFIX)/share/doc/monkeysphere/examples
	install -m 0644 examples/* $(DESTDIR)$(PREFIX)/share/doc/monkeysphere/examples
	install -m 0644 etc/monkeysphere.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/monkeysphere.conf$(ETCSUFFIX)
	install -m 0644 etc/monkeysphere-host.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/monkeysphere-host.conf$(ETCSUFFIX)
	install -m 0644 etc/monkeysphere-authentication.conf $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere/monkeysphere-authentication.conf$(ETCSUFFIX)

installman:
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1 $(DESTDIR)$(MANPREFIX)/man7 $(DESTDIR)$(MANPREFIX)/man8
	gzip -n man/*/*
	install man/man1/* $(DESTDIR)$(MANPREFIX)/man1
	install man/man7/* $(DESTDIR)$(MANPREFIX)/man7
	install man/man8/* $(DESTDIR)$(MANPREFIX)/man8
	ln -s openpgp2ssh.1.gz $(DESTDIR)$(MANPREFIX)/man1/openpgp2pem.1.gz
	ln -s openpgp2ssh.1.gz $(DESTDIR)$(MANPREFIX)/man1/openpgp2spki.1.gz
	gzip -d man/*/*
	gzip -d $(DESTDIR)$(MANPREFIX)/man1/monkeysphere.1.gz
	sed -i 's:__SYSCONFDIR_PREFIX__:$(ETCPREFIX):' $(DESTDIR)$(MANPREFIX)/man1/monkeysphere.1
	gzip -n $(DESTDIR)$(MANPREFIX)/man1/monkeysphere.1
	gzip -d $(DESTDIR)$(MANPREFIX)/man8/monkeysphere-host.8.gz
	sed -i 's:__SYSCONFDIR_PREFIX__:$(ETCPREFIX):' $(DESTDIR)$(MANPREFIX)/man8/monkeysphere-host.8
	sed -i 's:__SYSDATADIR_PREFIX__:$(LOCALSTATEDIR):' $(DESTDIR)$(MANPREFIX)/man8/monkeysphere-host.8
	gzip -n $(DESTDIR)$(MANPREFIX)/man8/monkeysphere-host.8
	gzip -d $(DESTDIR)$(MANPREFIX)/man8/monkeysphere-authentication.8.gz
	sed -i 's:__SYSCONFDIR_PREFIX__:$(ETCPREFIX):' $(DESTDIR)$(MANPREFIX)/man8/monkeysphere-authentication.8
	sed -i 's:__SYSDATADIR_PREFIX__:$(LOCALSTATEDIR):' $(DESTDIR)$(MANPREFIX)/man8/monkeysphere-authentication.8
	gzip -n $(DESTDIR)$(MANPREFIX)/man8/monkeysphere-authentication.8

# this target depends on you having the monkeysphere-docs
# repo checked out as a peer of your monkeysphere repo.
releasenote:
	../monkeysphere-docs/utils/build-releasenote

test: test-keytrans test-basic

check: test

test-basic: src/agent-transfer/agent-transfer
	MONKEYSPHERE_TEST_NO_EXAMINE=true ./tests/basic

test-keytrans: src/agent-transfer/agent-transfer
	MONKEYSPHERE_TEST_NO_EXAMINE=true ./tests/keytrans

.PHONY: all tarball debian-package freebsd-distinfo clean install installman releasenote test check
