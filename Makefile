all: keytrans

keytrans:
	$(MAKE) -C src/keytrans

release: clean
	tar c COPYING doc etc Makefile man src | gzip -n > ../monkeysphere_`head -n1 debian/changelog | sed 's/.*(\([^-]*\)-.*/\1/'`.orig.tar.gz

clean:
	$(MAKE) -C src/keytrans clean

.PHONY: all clean release
