CFLAGS =  $(shell libassuan-config --cflags --libs)
CFLAGS += --pedantic -Wall -Werror 

all: agent-extraction

agent-extraction: main.c
	gcc -o $@ $(CFLAGS) $<

clean:
	rm -f agent-extraction

.PHONY: clean all
