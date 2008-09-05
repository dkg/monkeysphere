MONKEYSPHERE_VERSION = `head -n1 debian/changelog | sed 's/.*(\([^-]*\)-.*/\1/'`

# these defaults are for debian.  porters should probably adjust them
# before calling make install
ETCPREFIX ?= 
PREFIX ?= /usr

all: keytrans

keytrans:
	$(MAKE) -C src/keytrans

tarball: clean
	rm -rf monkeysphere-$(MONKEYSPHERE_VERSION)
	mkdir -p monkeysphere-$(MONKEYSPHERE_VERSION)/doc
	ln -s ../../website/getting-started-user.mdwn ../../website/getting-started-admin.mdwn ../../doc/TODO ../../doc/MonkeySpec monkeysphere-$(MONKEYSPHERE_VERSION)/doc
	ln -s ../COPYING ../etc ../Makefile ../man ../src  monkeysphere-$(MONKEYSPHERE_VERSION)
	tar -ch monkeysphere-$(MONKEYSPHERE_VERSION) | gzip -n > monkeysphere_$(MONKEYSPHERE_VERSION).orig.tar.gz
	rm -rf monkeysphere-$(MONKEYSPHERE_VERSION)

debian-package: tarball
	tar xzf monkeysphere_$(MONKEYSPHERE_VERSION).orig.tar.gz
	cp -a debian monkeysphere-$(MONKEYSPHERE_VERSION)
	(cd monkeysphere-$(MONKEYSPHERE_VERSION) && debuild -uc -us)
	rm -rf monkeysphere-$(MONKEYSPHERE_VERSION)

clean:
	$(MAKE) -C src/keytrans clean
	# clean up old monkeysphere packages lying around as well.
	rm -f monkeysphere_*

# this target is to be called from the tarball, not from the git
# working dir!
install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/share/monkeysphere
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1 $(DESTDIR)$(PREFIX)/share/man/man7 $(DESTDIR)$(PREFIX)/share/man/man8
	mkdir -p $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
	mkdir -p $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere
	install src/monkeysphere src/monkeysphere-ssh-proxycommand src/keytrans/openpgp2ssh $(DESTDIR)/$(PREFIX)/bin
	install src/monkeysphere-server $(DESTDIR)/$(PREFIX)/sbin
	install -m 0644 src/common $(DESTDIR)/$(PREFIX)/share/monkeysphere
	install doc/* $(DESTDIR)$(PREFIX)/share/doc/monkeysphere
	install man/man1/* $(DESTDIR)$(PREFIX)/share/man/man1
	install man/man7/* $(DESTDIR)$(PREFIX)/share/man/man7
	install man/man8/* $(DESTDIR)$(PREFIX)/share/man/man8
	install -m 0644 etc/* $(DESTDIR)$(ETCPREFIX)/etc/monkeysphere

releasenote:
	./utils/build-releasenote

.PHONY: all clean tarball debian-package install releasenote
