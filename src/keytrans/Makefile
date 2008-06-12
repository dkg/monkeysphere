all: openpgp2ssh

openpgp2ssh: openpgp2ssh.c gnutls-helpers.o
	gcc -g -Wall --pedantic -o openpgp2ssh openpgp2ssh.c `libgnutls-config --libs --cflags` -lgnutls-extra gnutls-helpers.o

%.o: %.c
	gcc -g -Wall --pedantic -o $@ -c $<

clean: 
	rm -f openpgp2ssh gpg2ssh ssh2gpg *.o

# deprecated:
gpg2ssh: gpg2ssh.c gnutls-helpers.o
	gcc -g -Wall --pedantic -o gpg2ssh gpg2ssh.c `libgnutls-config --libs --cflags` -lgnutls-extra gnutls-helpers.o

ssh2gpg: ssh2gpg.c gnutls-helpers.o
	gcc -g -Wall --pedantic -o ssh2gpg ssh2gpg.c `libgnutls-config --libs --cflags` -lgnutls-extra gnutls-helpers.o

.PHONY: clean all
