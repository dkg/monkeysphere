CFLAGS=`libgnutls-config --libs --cflags` -g -Wall --pedantic
CC=gcc

all: openpgp2ssh

openpgp2ssh: openpgp2ssh.c gnutls-helpers.o
	$(CC) $(CFLAGS) -o openpgp2ssh openpgp2ssh.c gnutls-helpers.o

.c.o: 
	$(CC) $(CFLAGS) -c $<

clean: 
	rm -f openpgp2ssh *.o

.PHONY: clean all
