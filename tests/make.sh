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
		
	*)
		echo "build nothing."
		exit 1
		;;
esac
exit 0
