all: keytrans

keytrans:
	$(MAKE) -C src/keytrans

clean:
	$(MAKE) -C src/keytrans clean

.PHONY: all clean
