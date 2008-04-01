monkeysphere: main.c
	gcc -g -Wall --pedantic -o monkeysphere main.c `libgnutls-config --libs --cflags` -lgnutls-extra

clean: 
	rm -f monkeysphere

.PHONY: clean
