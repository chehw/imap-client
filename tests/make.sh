#!/bin/bash

target=${1-"mail_db"}
target=$(basename ${target})
target=${target/.[ch]/}

case "$target" in
	#~ mail_db|bdb_context)
		#~ gcc -std=gnu99 -g -Wall -I../include -I../src -pthread -D_DEBUG \
			#~ -DTEST_MAIL_DB_ -D_STAND_ALONE \
			#~ -o test_mail_db \
			#~ ../src/mail_db.c \
			#~ -lm -lpthread -ljson-c -ldb
		#~ ;;
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
			../src/load-mails.c \
			-lm -lpthread -ljson-c -ldb \
			$(pkg-config --cflags --libs gnutls gtk+-3.0 webkit2gtk-4.0)
		;;
		
	text-utils)
		gcc -std=gnu99 -g -Wall -D_DEBUG \
			-I../include -I../src -I../utils \
			-DTEST_TEXT_UTILS_ -D_STAND_ALONE \
			-o test_text-utils ../src/text-utils.c \
			../utils/regex-utils.c ../utils/base64.c \
			-lm -lpthread -lpcre2-8
		;;
	
	load-mails|mail_db|bdb_context)
		echo "target ==> load-mails"
		gcc -std=gnu99 -g -Wall -D_DEBUG -D_DEFAULT_SOURCE -D_GNU_SOURCE \
			-DTEST_LOAD_MAILS_ -D_STAND_ALONE \
			-I../include -I../src -I../utils \
			-o test_load-mails ../src/load-mails.c \
			../src/imap_client.c ../src/imap_buffer.c ../src/app.c \
			../src/mail_db.c ../src/shell.c ../src/bdb_context.c \
			../utils/utils.c ../utils/crypto.c \
			-lm -lpthread -ljson-c -ldb \
			$(pkg-config --cflags --libs gnutls gtk+-3.0 webkit2gtk-4.0)
		;;
	
	base64)
		gcc -std=gnu99 -g -Wall -D_DEBUG \
			-DTEST_BASE64_ -D_STAND_ALONE \
			-I ../utils \
			-o test_base64 \
			../utils/base64.c \
			-lm -lpthread 
		;;
	jwt_json-c)
		gcc -std=gnu99 -g -Wall -D_DEBUG \
			-DTEST_JWT_JSON_C_ -D_STAND_ALONE \
			-I ../utils \
			-o test_jwt_json-c \
			../utils/jwt_json-c.c ../utils/base64.c \
			-lm -lpthread -lgnutls -ljson-c -lcurl
		;;
		
	gcloud-utils)
		gcc -std=gnu99 -g -Wall -D_DEBUG \
			-DTEST_GCLOUD_UTILS_ -D_STAND_ALONE \
			-I ../utils \
			-o test_gcloud-utils \
			../utils/gcloud-utils.c \
			../utils/jwt_json-c.c ../utils/base64.c \
			-lm -lpthread -lgnutls -ljson-c -lcurl
		;;
		
	regex-utils)
		gcc -std=gnu99 -g -Wall -D_DEBUG \
			-DTEST_REGEX_UTILS_ -D_STAND_ALONE \
			-I ../utils \
			-o test_regex-utils \
			../utils/regex-utils.c \
			-lm -lpthread -lpcre2-8
		;;
		
	test_fetch_mail)
		gcc -std=gnu99 -g -Wall -D_DEBUG \
			-DTEST_REGEX_UTILS_ -D_STAND_ALONE \
			-I../utils -I ../include -I../src\
			-o test_fetch_mail-utils \
			../tests/test_fetch_mail.c \
			../src/imap_client.c ../src/imap_buffer.c \
			../utils/utils.c ../utils/crypto.c \
			-lm -lpthread -lpcre2-8 -ljson-c -lgnutls
		;;
		
	*)
		echo "build nothing."
		exit 1
		;;
esac
exit 0
