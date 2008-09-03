MONKEYSPHERE_VERSION=`head -n1 debian/changelog | sed 's/.*(\([^-]*\)-.*/\1/'`

all: keytrans

keytrans:
	$(MAKE) -C src/keytrans

tarball: clean
	rm -rf monkeysphere-$(MONKEYSPHERE_VERSION)
	mkdir -p monkeysphere-$(MONKEYSPHERE_VERSION)/doc
	ln -s ../../website/getting-started-user.mdwn ../../website/getting-started-admin.mdwn ../../doc/TODO ../../doc/MonkeySpec monkeysphere-$(MONKEYSPHERE_VERSION)/doc
	ln -s ../COPYING ../etc ../Makefile ../man ../src  monkeysphere-$(MONKEYSPHERE_VERSION)
	tar -ch monkeysphere-$(MONKEYSPHERE_VERSION) | gzip -n > monkeysphere_$(MONKEYSPHERE_VERSION).tar.gz
	rm -rf monkeysphere-$(MONKEYSPHERE_VERSION)

debian-package: 
	debuild -uc -us

clean:
	$(MAKE) -C src/keytrans clean
	# clean up old monkeysphere packages lying around as well.
	rm -f monkeysphere_*

.PHONY: all clean tarball debian-package
