monkeysphere: main.c gnutls-helpers.o
	gcc -g -Wall --pedantic -o monkeysphere main.c `libgnutls-config --libs --cflags` -lgnutls-extra gnutls-helpers.o

gpg2ssh: gpg2ssh.c gnutls-helpers.o
	gcc -g -Wall --pedantic -o gpg2ssh gpg2ssh.c `libgnutls-config --libs --cflags` -lgnutls-extra gnutls-helpers.o

%.o: %.c
	gcc -g -Wall --pedantic -o $@ -c $<

clean: 
	rm -f monkeysphere *.o

.PHONY: clean
