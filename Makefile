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

CFLAGS += $(shell libassuan-config --cflags)
CFLAGS += $(shell libgcrypt-config --cflags)
CFLAGS += --pedantic -Wall -Werror -std=c99
LIBS += $(shell libassuan-config --libs)
LIBS += $(shell libgcrypt-config --libs)

REPLACEMENTS = src/monkeysphere src/monkeysphere-host		\
src/monkeysphere-authentication src/share/defaultenv $(wildcard	\
src/transitions/*)

REPLACED_COMPRESSED_MANPAGES = $(addsuffix .gz,$(addprefix replaced/,$(wildcard man/*/*)))

all: src/agent-transfer/agent-transfer $(addprefix replaced/,$(REPLACEMENTS)) $(REPLACED_COMPRESSED_MANPAGES)

src/agent-transfer/agent-transfer: src/agent-transfer/main.c src/agent-transfer/ssh-agent-proto.h
	gcc -o $@ $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LIBS)

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
	rm -rf replaced/
	# clean up old monkeysphere packages lying around as well.
	rm -f monkeysphere_*

replaced/%: %
	mkdir -p $(dir $@)
	sed < $< > $@ \
	-e 's:__SYSSHAREDIR_PREFIX__:$(PREFIX):' \
	-e 's:__SYSCONFDIR_PREFIX__:$(ETCPREFIX):' \
	-e 's:__SYSDATADIR_PREFIX__:$(LOCALSTATEDIR):'

replaced/%.gz: replaced/%
	gzip -n $<

# this target is to be called from the tarball, not from the git
# working dir!
install: all installman
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/sbin
	mkdir -p $(DESTDIR)$(PREFIX)/share/monkeysphere/m $(DESTDIR)$(PREFIX)/share/monkeysphere/mh $(DESTDIR)$(PREFIX)/share/monkeysphere/ma $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions
	mkdir -p $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
	printf "Monkeysphere %s\n" $(MONKEYSPHERE_VERSION) > $(DESTDIR)$(PREFIX)/share/monkeysphere/VERSION
	install replaced/src/monkeysphere $(DESTDIR)$(PREFIX)/bin
	install replaced/src/monkeysphere-host $(DESTDIR)$(PREFIX)/sbin
	install replaced/src/monkeysphere-authentication $(DESTDIR)$(PREFIX)/sbin
	install src/monkeysphere-authentication-keys-for-user $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0644 src/share/common $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0644 replaced/src/share/defaultenv $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0755 src/share/checkperms $(DESTDIR)$(PREFIX)/share/monkeysphere
	install -m 0755 src/share/keytrans $(DESTDIR)$(PREFIX)/share/monkeysphere
	ln -sf ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/pem2openpgp
	ln -sf ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/openpgp2ssh
	ln -sf ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/openpgp2pem
	ln -sf ../share/monkeysphere/keytrans $(DESTDIR)$(PREFIX)/bin/openpgp2spki
	install -m 0755 src/agent-transfer/agent-transfer $(DESTDIR)$(PREFIX)/bin
	install -m 0744 replaced/src/transitions/* $(DESTDIR)$(PREFIX)/share/monkeysphere/transitions
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

installman: $(REPLACED_COMPRESSED_MANPAGES)
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1 $(DESTDIR)$(MANPREFIX)/man7 $(DESTDIR)$(MANPREFIX)/man8
	install replaced/man/man1/* $(DESTDIR)$(MANPREFIX)/man1
	install replaced/man/man7/* $(DESTDIR)$(MANPREFIX)/man7
	install replaced/man/man8/* $(DESTDIR)$(MANPREFIX)/man8
	ln -sf openpgp2ssh.1.gz $(DESTDIR)$(MANPREFIX)/man1/openpgp2pem.1.gz
	ln -sf openpgp2ssh.1.gz $(DESTDIR)$(MANPREFIX)/man1/openpgp2spki.1.gz

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
