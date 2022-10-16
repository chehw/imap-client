/*
 * load-mails.c
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

#include <gtk/gtk.h>
#include "imap_client.h"
#include "mail_db.h"
#include "utils.h"
#include "app.h"

#include <endian.h>


#if defined(TEST_LOAD_MAILS_) && defined(_STAND_ALONE)

static struct app_context g_app[1];

static int test_load_mails(struct app_context *app, struct imap_client_context *imap, struct mail_db_context *mail_db);
int main(int argc, char **argv)
{
	gtk_init(&argc, &argv);
	
	int rc = 0;
	struct app_context *app = app_context_init(g_app, argc, argv, NULL);
	assert(app && app->priv);
	
	debug_printf("== work_dir: %s\n"
		"== app_name: %s\n", 
		app->work_dir, app->app_name);
		
	rc = app->init(app, NULL);
	assert(0 == rc);
	
	struct imap_client_context * imap = app_get_imap_client(app);
	struct mail_db_context *mail_db = app_get_mail_db(app);
	assert(imap && mail_db);
	
	struct imap_credentials *cred = imap_credentials_load(NULL, NULL, NULL);
	rc = imap->connect(imap, cred);
	assert(0 == rc);
	
	rc = imap->query_capabilities(imap, NULL);
	assert(0 == rc);
	
	rc = imap->authenticate(imap, NULL, NULL);
	assert(0 == rc);
	
	rc = test_load_mails(app, imap, mail_db);
	
	imap_credentials_clear(cred);
	free(cred);
	app_context_cleanup(app);
	return rc;
}

#define JSON_OUTPUT_FORMAT (JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE)

static ssize_t query_mail_exists(json_object *jmessages, ssize_t *p_uidnext, ssize_t *p_recent)
{
	ssize_t num_exists = 0;
	ssize_t num_recent = 0;
	ssize_t uid_next = -1;
	int num_messages = json_object_array_length(jmessages);
	
	for(int i = 0; i < num_messages; ++i) {
		json_object *jmessage = json_object_array_get_idx(jmessages, i);
		if(NULL == jmessage) continue;
		const char * message = json_object_get_string(jmessage);
		if(NULL == message) continue;

		assert(*message++ == '*');
		
		char line[1024] = "";
		strncpy(line, message, sizeof(line));
		char *p = line;
		char *p_end = line + strlen(line);
		
		p = trim_right(trim_left(p, p_end), p_end);
		
		char *key = p;
		p = strchr(p, ' ');
		assert(p);
		*p++ = '\0';
		
		if(strcasecmp(key, "FLAGS") == 0) {
			debug_printf("FLAGS: %s", p);
		}else if(strcasecmp(key, "OK") == 0) {
			debug_printf("OK: %s", p);
			if(strncasecmp(p, "[UIDNEXT ", sizeof("[UIDNEXT ") - 1) == 0) {
				key = p + sizeof("[UIDNEXT ") - 1;
				p = strchr(p, ']');
				assert(p);
				*p++ = '\0';
				uid_next = strtol(key, NULL, 10);
			}
		}else {
			if(strcasecmp(p, "EXISTS") == 0) num_exists = strtol(key, NULL, 10);
			else if(strcasecmp(p, "RECENT") == 0) num_recent = strtol(key, NULL, 10);
			else {
				debug_printf("unknown message: %s %s", key, p);
			}
		}
	}
	if(p_recent) *p_recent = num_recent;
	if(p_uidnext) *p_uidnext = uid_next;
	return num_exists;
}


static ssize_t query_uid_list(struct imap_client_context *imap, const char *folder, uint64_t **p_uid_list)
{
	json_object *jresult = NULL;
	json_object *jmessages = NULL;
	json_bool ok = FALSE;
	ssize_t num_uids = 0;
	if(NULL == folder) folder = "INBOX";
	int rc = imap->send_command(imap, "EXAMINE", folder, &jresult);
	if(rc) return -1;
	
	assert(jresult);
	debug_printf("examime %s: %s", folder, json_object_to_json_string_ext(jresult, JSON_OUTPUT_FORMAT));
	
	const char *status = json_get_value(jresult, string, status);
	if(strcasecmp(status, "OK") != 0) goto label_err;
		
	ok = json_object_object_get_ex(jresult, "messages", &jmessages);
	if(!ok) goto label_err;
	
	ssize_t num_recent = -1;
	ssize_t uid_next = -1;
	ssize_t num_exists = query_mail_exists(jmessages, &uid_next, &num_recent);
	
	debug_printf("num_exists: %ld, recent: %ld, uidnext: %ld", 
		(long)num_exists, (long)num_recent, (long)uid_next);
	json_object_put(jresult);
	
	
	// query latest mails
	const ssize_t limits = 1;
	ssize_t start_index = num_exists - limits + 1;
	if(start_index < 1) start_index = 1;
	
	char command[100] = "";
	snprintf(command, sizeof(command) - 1, "FETCH %ld:%ld UID", (long)start_index, (long)num_exists);
	rc = imap->send_command(imap, command, NULL, &jresult);
	if(rc) return -1;
	
	assert(jresult);
	debug_printf("fetch uidlist %s: %s", folder, json_object_to_json_string_ext(jresult, JSON_OUTPUT_FORMAT));
	ok = json_object_object_get_ex(jresult, "messages", &jmessages);
	if(!ok) goto label_err;
	
	int num_messages = json_object_array_length(jmessages);
	if(num_messages <= 0) goto label_err;
	uint64_t *uid_list = calloc(num_messages, sizeof(*uid_list));
	assert(uid_list); 
	*p_uid_list = uid_list;
	
	for(int i = 0; i < num_messages; ++i) {
		json_object *jmessage = json_object_array_get_idx(jmessages, i);
		if(NULL == jmessage) continue;
		const char * message = json_object_get_string(jmessage);
		if(NULL == message) continue;
		assert(*message++ == '*');
		char line[1024] = "";
		strncpy(line, message, sizeof(line));
		char *p = line;
		char *p_end = line + strlen(line);
		p = trim_right(trim_left(p, p_end), p_end);

		///< @todo make uppercase
		/// ...
		
		p = line;
		static char search_pattern[]  = "FETCH (UID ";
		p = strstr(p, search_pattern);
		if(NULL == p) continue;
		p += sizeof(search_pattern) - 1;
		uid_list[num_uids++] = strtol(p, NULL, 10);
	}
	
	json_object_put(jresult);
	return num_uids;
label_err:
	if(jresult) json_object_put(jresult);
	return -1;
}

static int load_rawdata(struct bdb_context *db_raw_data, struct imap_client_context *imap, int64_t uid)
{
	int rc = 0;
	json_object *jresult = NULL;
	
	debug_printf("%s(): uid = %ld", __FUNCTION__, (long)uid);
	
	// check uid in db
	DB *dbp = db_raw_data->dbp;
	DBT key, value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	
	uint64_t uid_be64 = htobe64(uid);
	key.data = &uid_be64;
	key.size = sizeof(uid_be64);
	
	value.dlen = 1;	// no need to fetch data, only check the first byte
	value.flags = DB_DBT_PARTIAL;
	rc = dbp->get(dbp, NULL, &key, &value, DB_READ_UNCOMMITTED);
	if(0 == rc) {
		fprintf(stderr, "== uid (%ld) exists.\n", (long)uid);
	//	return 1;	// already exists;
	}
	
	if(rc && rc != DB_NOTFOUND) {
		debug_printf("find uid %ld failed: %s", (long)uid, db_strerror(rc));
		goto label_err;
	}
	
	char command[100] = "";
	snprintf(command, sizeof(command) - 1, "UID FETCH %lu", (unsigned long)uid);
	rc = imap->send_command(imap, command, "RFC822", &jresult);
	if(rc) goto label_err;

	const char *raw_data = json_object_to_json_string_ext(jresult, JSON_OUTPUT_FORMAT);
	if(NULL == raw_data) goto label_err;
	

	memset(&value, 0, sizeof(value));
	value.data = (void *)raw_data;
	value.size = strlen(raw_data) + 1;
	
	
	fprintf(stderr, "== save to raw_db ...\n");
	rc = dbp->put(dbp, NULL, &key, &value, DB_AUTO_COMMIT);
	if(rc) {
		debug_printf("put to db failed(uid=%ld): %s", (long)uid, db_strerror(rc));
		goto label_err;
	}
	
	json_object_put(jresult);
	return 0;
label_err:
	if(jresult) { json_object_put(jresult); jresult = NULL; }
	return -1;
}
static int test_load_mails(struct app_context *app, struct imap_client_context *imap, struct mail_db_context *mail_db)
{
	int rc = 0;
	struct bdb_context *db = &mail_db->db_raw_data;
	uint64_t latest_uid = 0;
	rc = db->iter_last(db);
	if(0 == rc) {
		DBT key = db->pkey[0];
		assert(key.size == sizeof(uint64_t));
		latest_uid = *(uint64_t *)key.data;
		latest_uid = be64toh(latest_uid);
	}else {
		fprintf(stderr, "iter_last_failed: %s\n", db_strerror(rc));
	}
	printf("==lastest_uid: %lu\n", (unsigned long)latest_uid);
	
	// query uid
	uint64_t *uid_list = NULL;
	ssize_t num_uids = query_uid_list(imap, "INBOX", &uid_list);
	if(num_uids > 0) {
		assert(uid_list);
		for(ssize_t i = 0;i < num_uids; ++i) {
			if(uid_list[i] <= latest_uid) {
				printf("uid: %ld already exists.\n", (long)uid_list[i]);
				continue;
			}
			load_rawdata(&mail_db->db_raw_data, imap, uid_list[i]);
			
		}
	}
	return 0;
}

#endif
