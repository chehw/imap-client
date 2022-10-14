#!/bin/bash

target=${1-"mail_db"}
target=$(basename ${target})
target=${target/.[ch]/}

case "$target" in
	mail_db|bdb_context)
		gcc -std=gnu99 -g -Wall -I../include -I../src -pthread -D_DEBUG \
			-DTEST_MAIL_DB_ -D_STAND_ALONE \
			-o test_mail_db \
			../src/mail_db.c \
			-lm -lpthread -ljson-c -ldb
		;;
	shell)
		gcc -std=gnu99 -g -Wall -I../include -I../src \
			-o shell shell.c \
			-lm -lpthread -ljson-c -lcurl \
			$(pkg-config --cflags --libs gtk+-3.0)
		;;
	utils|crypto)
		gcc -std=gnu99 -g -Wall -D_DEBUG \
			-I../include -I../src -I../utils \
			-DTEST_UTILS_ -D_STAND_ALONE \
			-o test_utills ../utils/utils.c \
			-lm -lpthread \
			$(pkg-config --cflags --libs gnutls)
		;;
		
	imap_client|app|imap_buffer)
		gcc -std=gnu99 -g -Wall -D_DEBUG -D_DEFAULT_SOURCE -D_GNU_SOURCE \
			-DTEST_IMAP_CLIENT_ -D_STAND_ALONE \
			-I../include -I../src -I../utils \
			-o test_imap_client \
			../src/imap_client.c ../src/imap_buffer.c ../src/app.c \
			../src/mail_db.c ../src/shell.c ../src/bdb_context.c \
			../utils/utils.c ../utils/crypto.c \
			-lm -lpthread -ljson-c -ldb \
			$(pkg-config --cflags --libs gnutls gtk+-3.0 webkit2gtk-4.0)
		;;
		
		
	*)
		echo "build nothing."
		exit 1
		;;
esac
exit 0
