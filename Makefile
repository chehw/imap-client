TARGETS = bin/imap_client

DEBUG ?= 1
OPTIMIZE ?= -O2

CC=gcc -std=gnu99 -D_DEFAULT_SOURCE -D_GNU_SOURCE
LINKER=$(CC)
CFLAGS = -Wall -Iinclude -Iutils -Isrc -pthread
LIBS = -lm -lpthread -lcurl -ljson-c -ldb

ifeq ($(DEBUG),1)
CFLAGS += -g -D_DEBUG
OPTIMIZE = -O0
endif

CFLAGS += $(shell pkg-config --cflags gtk+-3.0 gnutls webkit2gtk-4.0)
LIBS += $(shell pkg-config --libs gtk+-3.0 gnutls webkit2gtk-4.0)


LDFLAGS = $(CFLAGS) $(OPTIMIZE)

SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=obj/%.o)

UTILS_SOURCES := $(wildcard utils/*.c)
UTILS_OBJECTS := $(UTILS_SOURCES:utils/%.c=utils/%.o)


all: do_init bin/imap_client

bin/imap_client: $(OBJECTS) $(UTILS_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJECTS): obj/%.o : src/%.c
	$(CC) -o $@ -c $< $(CFLAGS)
	
$(UTILS_OBJECTS): utils/%.o : utils/%.c
	$(CC) -o $@ -c $< $(CFLAGS)


.PHONY: do_init clean
do_init:
	[ -d obj ] || mkdir obj
	
clean:
	rm -f $(TARGETS) $(OBJECTS) $(UTILS_OBJECTS)
