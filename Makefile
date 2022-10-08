TARGET=

DEBUG ?= 1

CC=gcc -std=gnu99 -D_DEFAULT_SOURCE -D_GNU_SOURCE
LINKER=$(CC)

CFLAGS = -Wall -Iinclude -g -D_DEBUG
OPTIMIZE = -O0

LIBS = -lm -lpthread -lcurl
LIBS += $(shell pkg-config --cflags --libs libsoup-2.4 gtk+-3.0)

all: tests/test_imap_client bin/imap_client

bin/imap_client: src/imap_client.c
	$(CC) 

tests/test_imap_client : tests/test_imap_client.c
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

