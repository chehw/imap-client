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

#include <limits.h>

#include "imap_client.h"
#include "mail_db.h"
#include "utils.h"
#include "app.h"

#include <json-c/json.h>
#include <endian.h>

#include "mail_utils.h"

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

ssize_t mail_utils_query_uidlist(struct mail_utils *mail, const char *folder, ssize_t limits , uint64_t **p_uid_list)
{
	assert(mail && mail->imap);
	struct imap_client_context *imap = mail->imap;
	
	json_object *jresult = NULL;
	json_object *jmessages = NULL;
	json_bool ok = false;
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
	if(limits <= 0) limits = 100;	// default: get latest 100 mails
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

int mail_utils_fetch(struct mail_utils *mail, int64_t uid, const char *params, json_object **p_jresult)
{
	assert(mail && mail->imap);
	struct imap_client_context *imap = mail->imap;
	
	int rc = 0;
	json_object *jresult = NULL;
	char command[100] = "";
	snprintf(command, sizeof(command) - 1, "UID FETCH %lu", (unsigned long)uid);
	if(NULL == params) params = "RFC822";
	rc = imap->send_command(imap, command, params, &jresult);
	if(rc) goto label_err;
	
	*p_jresult = jresult;
	return 0;

label_err:
	if(jresult) json_object_put(jresult);
	return -1;
}

static inline char *get_word(char *begin, char *p_end, char **p_next)
{
	assert(begin);
	begin = trim_left(begin, p_end);
	if(begin >= p_end) return NULL;
	
	char *p = begin;
	if(*p == '"') {
		p = ++begin;
		while((p < p_end) && *p && *p != '"') {
			if(*p == '\\') ++p; // skip next escaped char
			++p;
		}
		if(p >= p_end) return NULL; // invalid format
		*p++ = '\0';
	}else {
		p = strchr(p, ' ');
		if(p) *p++ = '\0';
	}
	
	if(p_next) *p_next = p;
	return begin;
	
}

int mail_utils_list(struct mail_utils *mail, const char *folder, const char *params, json_object **p_jlist)
{
	assert(mail && mail->imap);
	struct imap_client_context *imap = mail->imap;
	int rc = 0;
	json_object *jresult = NULL;
	json_object *jlist = NULL;
	
	char command[PATH_MAX] = "";
	if(NULL == folder) folder = "/";
	if(NULL == params) params = "*";
	
	snprintf(command, sizeof(command) - 1, "LIST %s", folder);
	rc = imap->send_command(imap, command, params, &jresult);
	if(rc) goto label_err;
	
	const char *status = json_get_value(jresult, string, status);
	if(NULL == status || strcasecmp(status, "OK") != 0) goto label_err;
	
	json_object *jmessages = NULL;
	json_bool ok = json_object_object_get_ex(jresult, "messages",  &jmessages);
	if(!ok || NULL == jmessages) goto label_err;
	
	jlist = json_object_new_array();
	assert(jlist);
	
	int num_messages = json_object_array_length(jmessages);
	for(int i = 0; i < num_messages; ++i) {
		json_object *jmessage = json_object_array_get_idx(jmessages, i);
		if(NULL == jmessage) continue;
		const char *message = json_object_get_string(jmessage);
		if(NULL == message) continue;
		
		static const char prefix_pattern[] = "* LIST ";
		static size_t prefix_size = sizeof(prefix_pattern) - 1;
		if(strncasecmp(message, prefix_pattern, prefix_size) != 0) continue;
		
		char line[PATH_MAX] = "";
		strncpy(line, message + prefix_size, sizeof(line) - 1);
		
		char *p_end = line + strlen(line);
		char *p = trim_right(trim_left(line, p_end), p_end);
		if(*p == '(') { // has flags
			p = strchr(p, ')');
			if(NULL == p) continue;
			++p;
			
		}
		char *p_next = NULL;
		char *parent = get_word(p, p_end, &p_next);
		if(NULL == parent) continue;
		
		char *child = NULL;
		if(p_next) child = get_word(p_next, p_end, NULL);
		
		if(child && child[0]) {
			json_object_array_add(jlist, json_object_new_string(child));
		}
	}
	
	if(p_jlist) *p_jlist = jlist;
	else json_object_put(jlist);
	
	json_object_put(jresult);
	return 0;
	
label_err:
	if(jresult) json_object_put(jresult);
	if(jlist) json_object_put(jlist);
	return -1;
}

struct mail_utils *mail_utils_init(struct mail_utils *mail, struct imap_client_context *imap)
{
	assert(imap);
	
	if(NULL == mail) mail = calloc(1, sizeof(*mail));
	else memset(mail, 0, sizeof(*mail));
	assert(mail);
	
	mail->imap = imap;
	mail->query_uidlist = mail_utils_query_uidlist;
	mail->fetch = mail_utils_fetch;
	mail->list = mail_utils_list;
	return mail;
}

void mail_utils_cleanup(struct mail_utils *mail)
{
	return;
}

#if defined(TEST_LOAD_MAILS_) && defined(_STAND_ALONE)
#include <gtk/gtk.h>
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

static int load_rawdata(struct mail_utils *mail, struct bdb_context *db_raw_data, int64_t uid)
{
	assert(mail && mail->imap);
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
	
	rc = mail->fetch(mail, uid, "RFC822", &jresult);
	if(rc) goto label_err;
	
	//~ char command[100] = "";
	//~ snprintf(command, sizeof(command) - 1, "UID FETCH %lu", (unsigned long)uid);
	//~ rc = imap->send_command(imap, command, "RFC822", &jresult);
	//~ if(rc) goto label_err;

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
	
	struct mail_utils mail[1];
	memset(mail, 0, sizeof(mail));
	mail_utils_init(mail, imap);
	
	json_object *jlist = NULL;
	rc = mail->list(mail, "/", NULL, &jlist);
	assert(0 == rc && jlist);
	fprintf(stderr, "LIST INBOX: \n%s\n", json_object_to_json_string_ext(jlist, JSON_OUTPUT_FORMAT));
	json_object_put(jlist);
	jlist = NULL;
	
	return 0;
	
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
	db->iter_close(db);
	printf("==lastest_uid: %lu\n", (unsigned long)latest_uid);
	
	// query uid
	uint64_t *uid_list = NULL;
	ssize_t num_uids = mail_utils_query_uidlist(mail, "INBOX", 1, &uid_list);
	if(num_uids > 0) {
		assert(uid_list);
		for(ssize_t i = 0;i < num_uids; ++i) {
			if(uid_list[i] <= latest_uid) {
				printf("uid: %ld already exists.\n", (long)uid_list[i]);
				continue;
			}
			load_rawdata(mail, &mail_db->db_raw_data, uid_list[i]);
		}
	}
	free(uid_list);
	return 0;
}

#endif
