/*
 * test_fetch_mail.c
 * 
 * Copyright 2022 chehw <hongwei.che@gmail.com>
 * 
 * The MIT License (MIT)
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "imap_client.h"
#include "mail_db.h"
#include "mail_utils.h"
#include "regex-utils.h"

#include <json-c/json.h>
#include <stdint.h>

static int fetch_mail_headers(struct imap_client_context *imap, int64_t uid)
{
	int rc = 0;
	json_object *jresult = NULL;
	
	rc = imap->send_command(imap, "SELECT INBOX", NULL, NULL);
	assert(0 == rc);
	
	char command[1024] = "";
	snprintf(command, sizeof(command), "UID FETCH %ld", (long)uid);
	
	
	rc = imap->send_command(imap, command, "BODYSTRUCTURE", &jresult);
	assert(0 == rc);
	
	fprintf(stderr, "body structure: %s\n", 
		json_object_to_json_string_ext(jresult, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE));
	json_object_put(jresult);
	
	return 0;
}

static int fetch_mail_body(struct imap_client_context *imap, int64_t uid)
{
	int rc = 0;
	json_object *jresult = NULL;
	
	rc = imap->send_command(imap, "SELECT INBOX", NULL, NULL);
	assert(0 == rc);
	
	char command[1024] = "";
	snprintf(command, sizeof(command), "UID FETCH %ld", (long)uid);
	
	
	rc = imap->send_command(imap, command, "RFC822.HEADER", &jresult);
	assert(0 == rc);
	
	fprintf(stderr, "body structure: %s\n", 
		json_object_to_json_string_ext(jresult, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE));
	json_object_put(jresult);
	return 0;
}

int main(int argc, char **argv)
{
	struct imap_credentials cred[1];
	memset(cred, 0, sizeof(cred));
	int rc = 0;
	if(NULL == imap_credentials_load(cred, NULL, NULL)) return -1;
	
	struct imap_client_context *imap = imap_client_context_init(NULL, NULL);
	assert(imap);
	
	rc = imap->connect(imap, cred);
	assert(0 == rc);
	
	rc = imap->query_capabilities(imap, NULL);
	rc = imap->authenticate(imap, NULL, NULL);
	assert(0 == rc);
	
	int64_t uid = 1;
	if(argc > 1) uid = atol(argv[1]);
	assert(uid > 0);
	
	rc = fetch_mail_headers(imap, uid);
	assert(0 == rc);
	
	rc = fetch_mail_body(imap, uid);
	
	return 0;
}

