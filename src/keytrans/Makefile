all: openpgp2ssh

openpgp2ssh: openpgp2ssh.c gnutls-helpers.o
	gcc -g -Wall --pedantic -o openpgp2ssh openpgp2ssh.c `libgnutls-config --libs --cflags` -lgnutls-extra gnutls-helpers.o

%.o: %.c
	gcc -g -Wall --pedantic -o $@ -c $<

clean: 
	rm -f openpgp2ssh *.o

.PHONY: clean all
