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
#include "text-utils.h"
#include "base64.h"

#include <stdbool.h>
#include <libsoup/soup.h>

#define MULTIPART_BODY_MAX_ARRAY_SIZE 256
static enum multipart_indicator multipart_indicator_check(const char *line, size_t cb_line, const char *boundary, size_t cb_boundary);

static inline _Bool is_utf8_compatible(const char *charset)
{
	if(NULL == charset 
	|| strcasecmp(charset, "utf8") == 0 
	|| strcasecmp(charset, "utf-8") == 0
	|| strcasecmp(charset, "us-ascii") == 0
	|| 0) return true;

	return false;
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
	printf("imap command: %s %s\n", command, params);
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

void rfc822_mail_body_clear(struct rfc822_mail_body *body)
{
	if(NULL == body) return;
	if(body->is_multipart && body->headers) {
		soup_message_headers_free(body->headers);
		body->headers = NULL;
	}
	body->is_multipart = 0;
	imap_buffer_clear(body->content);
	return;
}

void rfc822_mail_cleanup(struct rfc822_mail *mail)
{
	if(NULL == mail) return;
	if(mail->headers) soup_message_headers_free(mail->headers);
	if(mail->parts) {
		for(ssize_t i = 0; i < mail->num_parts; ++i) {
			rfc822_mail_body_clear(&mail->parts[i]);
		}
		free(mail->parts);
		mail->parts = NULL;
	}
	memset(mail, 0, sizeof(*mail));
	return;
}

//~ static void dump_mail_headers(SoupMessageHeaders *headers)
//~ {
	//~ SoupMessageHeadersIter iter;
	//~ soup_message_headers_iter_init(&iter, headers);
	//~ const char *name = NULL, *value = NULL;
	
	//~ printf("==== %s() ====\n", __FUNCTION__);
	//~ while(soup_message_headers_iter_next(&iter, &name, &value)) {
		//~ printf("%s: %s\n", name, value);
	//~ }
//~ }

enum multipart_indicator
{
	multipart_indicator_unknown = -1,
	multipart_indicator_none = 0,
	multipart_indicator_begin = 1,
	multipart_indicator_end = 2,
};

static enum multipart_indicator multipart_indicator_check(const char *line, size_t cb_line, const char *boundary, size_t cb_boundary)
{ 
	assert(boundary);
	if(cb_boundary == -1) cb_boundary = strlen(boundary);
	if(cb_line == -1) cb_line = strlen(line);
	
	if(cb_line < 2 || boundary <= 0 || (cb_line - 2) < cb_boundary) return multipart_indicator_none;
	if(line[0] != '-' || line[1] != '-') return multipart_indicator_none;
	line += 2;

	if(strncasecmp(line, boundary, cb_boundary) != 0) return multipart_indicator_none;
	line += cb_boundary;
	
	if(line[0] == '\0' || IS_CRLF(line[0])) return multipart_indicator_begin;
	if(line[0] == '-' && line[1] == '-') return multipart_indicator_end;
	
	return multipart_indicator_unknown;
}

ssize_t mime_headers_parse(SoupMessageHeaders *headers, const char **p_top, const char **p_bottom)
{
	char key[1024] = "";
	struct imap_buffer value[1];
	memset(value, 0, sizeof(value));
	imap_buffer_init(value, 4096);
	
	const char **lines = p_top;
	ssize_t lines_count = 0;
	while((lines + lines_count) < p_bottom) {
		const char *line = lines[lines_count++];
		if(line[0] == '\r' && line[1] == '\n') { // end of headers
			debug_printf("== end of line @%ld: prev_line: %s\n", (long)lines_count, lines[lines_count-2]);
			
			if(key[0]) {	// add prev pairs and reset buffer
				value->data[value->length] = '\0';
				soup_message_headers_append(headers, key, value->data);
				
				debug_printf("add_header: [%s]: [%s]\n", key, value->data);
				key[0] = '\0';
				value->data[0] = '\0';
				value->length = 0;
			}
			break;
		}
		
		const char *encoded_value = line;
		int is_new_key = !IS_WSP(line[0]);
		if(is_new_key) {	// next key/value pair
			if(key[0]) {	// add prev pairs and reset buffer
				
				value->data[value->length] = '\0';
				soup_message_headers_append(headers, key, value->data);
				debug_printf("add_header: [%s]: [%s]\n", key, value->data);
				key[0] = '\0';
				value->data[0] = '\0';
				value->length = 0;
			}
			
			const char *p = strchr(line, ':');
			assert(p);
			size_t cb_key = p - line;
			assert(cb_key < sizeof(key));
			memcpy(key, line, cb_key);
			key[cb_key] = '\0';
			
			encoded_value = p + 1;
		}
		while(encoded_value[0] && IS_WSP(encoded_value[0])) ++encoded_value; // trim_left
		
		const char *p_endl = strstr(encoded_value, "\r\n");
		assert(p_endl);
		
		char buffer[4096] = "";
		char *utf8 = buffer;
		size_t length = sizeof(buffer);
		int rc = mime_header_value_decode(encoded_value, p_endl - encoded_value, &utf8, &length);
		assert(0 == rc);
		debug_printf("decoded text(length=%ld): '%s'", (long)length, buffer);
		if(length > 0) imap_buffer_push_data(value, utf8, length);
	}
	
	imap_buffer_clear(value);
	return lines_count;
}

static ssize_t mime_body_load_default(struct imap_buffer *body, 
	const char *charset,
	const char **lines, const char **p_bottom, 
	const char *boundary, ssize_t cb_boundary)
{
	ssize_t lines_count = 0;
	if(boundary && cb_boundary == -1) cb_boundary = strlen(boundary);
	
	while((lines + lines_count) < p_bottom) {
		const char *line = lines[lines_count++];
		ssize_t cb_line = strlen(line);
		assert(cb_line > 0);
		if(boundary) {
			enum multipart_indicator indicator = multipart_indicator_check(line, cb_line, boundary, cb_boundary);
			if(indicator == multipart_indicator_begin || indicator == multipart_indicator_end) return lines_count;
		}
		imap_buffer_push_data(body, (char *)line, cb_line);
	}
	return lines_count;
}
static ssize_t mime_body_load_quoted_printable(struct imap_buffer *body, 
	const char *charset,
	const char **p_top, const char **p_bottom, 
	const char *boundary, ssize_t cb_boundary)
{
	ssize_t lines_count = 0;
	if(boundary && cb_boundary == -1) cb_boundary = strlen(boundary);
	
	const char **lines = p_top;
	char decoded_buf[1024] = "";
	char utf8[4096] = "";
	
	while((lines + lines_count) < p_bottom) {
		const char *line = lines[lines_count++];
		ssize_t cb_line = strlen(line);
		if(boundary) {
			if(line[0] == '-' && line[1] == '-') {
				debug_printf("multipart_indicator_check(%.*s)\n", (int)cb_line, line);
				enum multipart_indicator indicator = multipart_indicator_check(line, cb_line, boundary, cb_boundary);
				
				printf("indicator = %d\n", indicator);
				if(indicator == multipart_indicator_begin || indicator == multipart_indicator_end) {
					return (lines_count - 1);
				}
			}
		}
		
		while(cb_line > 0 && IS_CRLF(line[cb_line - 1])) --cb_line;
		if(cb_line == 0) {
			imap_buffer_push_data(body, "\r\n", 2); // empty line
			continue;
		}
		
		char *dst = decoded_buf;
		int partial_line_flag = (line[cb_line - 1] == '=');
		
		ssize_t cb_decoded = quoted_printable_decode(line, cb_line, &dst);
		assert(cb_decoded >= 0);
		if(0 == cb_decoded) {
			imap_buffer_push_data(body, "\r\n", 2); // empty line
			continue;
		}
		size_t cb_utf8 = cb_decoded;
		if(charset) {
			dst = utf8;
			cb_utf8 = sizeof(utf8) - 1;
			int n = text_to_utf8(charset, decoded_buf, cb_decoded, &dst, &cb_utf8);
			assert(n >= 0);
			assert(cb_utf8 >= cb_decoded);
		}
		imap_buffer_push_data(body, dst, cb_utf8);
		if(!partial_line_flag) imap_buffer_push_data(body, "\r\n", 2);
	}
	return lines_count;
}

static ssize_t mime_body_load_base64(struct imap_buffer *body, const char *charset,
	const char **p_top, const char **p_bottom, 
	const char *boundary, ssize_t cb_boundary)
{
	ssize_t lines_count = 0;
	if(boundary && cb_boundary == -1) cb_boundary = strlen(boundary);
	
	const char **lines = p_top;
	struct imap_buffer b64[1];
	memset(b64, 0, sizeof(b64));
	
	while((lines + lines_count) < p_bottom) {
		const char *line = lines[lines_count++];
		ssize_t cb_line = strlen(line);
		if(boundary) {
			if(line[0] == '-' && line[1] == '-') {
				enum multipart_indicator indicator = multipart_indicator_check(line, cb_line, boundary, cb_boundary);
				if(indicator == multipart_indicator_begin || indicator == multipart_indicator_end) break;
			}
		}
		
		while(cb_line > 0 && IS_CRLF(line[cb_line - 1])) --cb_line;
		if(cb_line == 0) { // empty line
			continue;
		}
		imap_buffer_push_data(b64, (char *)line, cb_line);
	}
	
	if(b64->length > 0) {
		assert((b64->length % 4) == 0);
		imap_buffer_clear(body);
		unsigned char *decoded = NULL;
		ssize_t cb_decoded = base64_decode(b64->data, b64->length, &decoded);
		assert(cb_decoded <= (b64->length / 4 * 3));
		if(charset) {
			int n = text_to_utf8(charset, (char *)decoded, cb_decoded, 
				&body->data, &body->length);
			assert(n >= 0);
			free(decoded);
			decoded = NULL;
		}else {
			body->data = (char *)decoded;
			body->length = cb_decoded;
			body->size = cb_decoded;
		}
	}
	return lines_count;
}


ssize_t mime_body_parse(struct imap_buffer *body, 
	SoupMessageHeaders *headers,
	const char *boundary, size_t cb_boundary,
	const char **lines, const char **p_bottom)
{
	const char *mime_version = soup_message_headers_get_one(headers, "Mime-Version");
	if(NULL == mime_version) mime_version = "1.0";
	assert(0 == strncasecmp(mime_version, "1.0", 3));
	
	GHashTable *type_params = NULL;
	const char *charset = NULL;
	const char *transfer_encoding = NULL;
	const char *content_type = NULL;
	
	content_type = soup_message_headers_get_content_type(headers, &type_params);
	if(content_type && type_params) {
		charset = g_hash_table_lookup(type_params, "charset");
	}
	transfer_encoding = soup_message_headers_get_one(headers, "Content-Transfer-Encoding");
	enum MIME_TRANSFER_ENCODING encoding = mime_transfer_encoding_from_string(transfer_encoding);
	
	int utf8_compatible = is_utf8_compatible(charset);
	if(utf8_compatible) charset = NULL;
	
	switch(encoding) {
	case MIME_TRANSFER_ENCODING_7bit:
	case MIME_TRANSFER_ENCODING_8bit:
	case MIME_TRANSFER_ENCODING_binary:
		assert(encoding != MIME_TRANSFER_ENCODING_binary); // not implemented
		return mime_body_load_default(body, charset, lines, p_bottom, boundary, cb_boundary);
	case MIME_TRANSFER_ENCODING_quoted_printable:
		return mime_body_load_quoted_printable(body, charset, lines, p_bottom, boundary, cb_boundary);
	case MIME_TRANSFER_ENCODING_base64:
		return mime_body_load_base64(body, charset, lines, p_bottom, boundary, cb_boundary);
	default:
		fprintf(stderr, "Not implemented. (encoding = %d) transfer_encoding = %s\n", encoding, transfer_encoding);
		abort();
	}
	return -1;
}

static ssize_t multipart_parse(struct rfc822_mail_body *part, 
	const char *boundary, ssize_t cb_boundary, 
	const char **p_top, const char **p_bottom)
{
	assert(part && boundary);
	const char **lines = p_top;
	assert(lines && lines < p_bottom);
	
	debug_printf("top line: %s\n", lines[0]);
	
	if(cb_boundary == -1) cb_boundary = strlen(boundary);
	assert(cb_boundary > 0);
	while(lines < p_bottom) {
		const char *line = lines[0];
		// find begin line
		if(line[0] == '-' && line[1] == '-') {
			enum multipart_indicator indicator = multipart_indicator_check(lines[0], -1, boundary, cb_boundary);
			printf("indicator = %d\n", indicator);
			if(indicator == multipart_indicator_begin) {
				++lines;
				break;
			}
		}
		fprintf(stderr, "%s(): skip line %s\n", __FUNCTION__, lines[0]);
		++lines;
	}
	if(lines >= p_bottom) return p_bottom - p_top;
	
	SoupMessageHeaders *headers = part->headers;
	struct imap_buffer *body = part->content;
	if(NULL == headers) {
		headers = soup_message_headers_new(SOUP_MESSAGE_HEADERS_MULTIPART);
		assert(headers);
		part->headers = headers;
	}
	if(NULL == body->data) {
		body = imap_buffer_init(part->content, 0);
		assert(body);
	}
	
	ssize_t lines_count = mime_headers_parse(headers, lines, p_bottom);
	assert(lines_count > 0);
	lines += lines_count;
	
	lines_count = mime_body_parse(body, headers, boundary, cb_boundary, lines, p_bottom);
	assert(lines_count >= 0);
	
	lines += lines_count;
	return (lines - p_top); // lines parsed
}

int rfc822_mail_parse(struct rfc822_mail * mail, const struct lines_array *array)
{
	assert(mail);
	SoupMessageHeaders *headers = mail->headers;
	if(NULL == headers) {
		headers = soup_message_headers_new(SOUP_MESSAGE_HEADERS_RESPONSE);
		assert(headers);
		mail->headers = headers;
	}
	
	const char **p_top = (const char **)array->lines;
	const char **lines = p_top;
	const char **p_bottom = lines + array->length;
	
	ssize_t lines_count = mime_headers_parse(headers, lines, p_bottom);
	assert(lines_count > 0);
	lines += lines_count;
	
	GHashTable *type_params = NULL;
	const char *content_type = NULL;
	const char *boundary = NULL;
	ssize_t cb_boundary = -1;
	_Bool is_multipart = false;

	content_type = soup_message_headers_get_content_type(headers, &type_params);
	if(content_type && type_params) {
		is_multipart = (0 == strncasecmp(content_type, "multipart/", 10));
		if(is_multipart) {
			boundary = g_hash_table_lookup(type_params, "boundary");
			assert(boundary);
			cb_boundary = strlen(boundary);
		}
	}
		
	if(is_multipart) {
		struct rfc822_mail_body *parts = calloc(MULTIPART_BODY_MAX_ARRAY_SIZE, sizeof(*parts));
		assert(parts);
		mail->parts = parts;
		int num_parts = 0;
		
		while(lines < p_bottom) {
			assert(num_parts < MULTIPART_BODY_MAX_ARRAY_SIZE);
			struct rfc822_mail_body *body = &parts[num_parts++];
			body->is_multipart = is_multipart;
			
			debug_printf("top_line: %s", lines[0]);
			lines_count = multipart_parse(body, boundary, cb_boundary, lines, p_bottom);
			debug_printf("lines_count: %ld\n", (long)lines_count);
			
			
			assert(lines_count > 0);
			lines += lines_count;
		}
		mail->num_parts = num_parts;
	}else {
		struct rfc822_mail_body *body = calloc(1, sizeof(*body));
		assert(body);
		
		mail->num_parts = 1;
		mail->parts = body;
		body->headers = mail->headers;
		lines_count = mime_body_parse(body->content, mail->headers, NULL, 0, lines, p_bottom);
	}
	return 0;
}


int rfc822_mail_parse_json(struct rfc822_mail *mail, json_object *jrfc822)
{
	json_object *jdata = NULL;
	json_bool ok = json_object_object_get_ex(jrfc822, "data", &jdata);
	assert(ok && jdata);
	
	int num_lines = json_object_array_length(jdata);
	assert(num_lines > 0);
	
	struct lines_array array[1] = {{ 0 }};
	int rc = lines_array_resize(array, num_lines);
	assert(0 == rc);
	
	for(int i = 0; i < num_lines; ++i) {
		json_object *jline = json_object_array_get_idx(jdata, i);
		array->lines[i] = (char *)json_object_get_string(jline);
	}
	array->length = num_lines;
	
	rc = rfc822_mail_parse(mail, array);
	assert(0 == rc);
	
	free(array->lines);
	return rc;
}


#if defined(TEST_LOAD_MAILS_) && defined(_STAND_ALONE)
#include <gtk/gtk.h>
static struct app_context g_app[1];

static int test_load_mails(struct app_context *app, struct imap_client_context *imap, struct mail_db_context *mail_db);

static void test_load_rfc822()
{
	json_object *jrfc822 = json_object_from_file("rfc822-sample.json");
	assert(jrfc822);
	
	json_object *jdata = NULL;
	json_bool ok = json_object_object_get_ex(jrfc822, "data", &jdata);
	assert(ok && jdata);
	
	int num_lines = json_object_array_length(jdata);
	assert(num_lines > 0);
	
	struct lines_array array[1] = {{ 0 }};
	int rc = lines_array_resize(array, num_lines);
	assert(0 == rc);
	
	for(int i = 0; i < num_lines; ++i) {
		json_object *jline = json_object_array_get_idx(jdata, i);
		array->lines[i] = (char *)json_object_get_string(jline);
	}
	array->length = num_lines;
	
	struct rfc822_mail mail[1] = { NULL };
	rc = rfc822_mail_parse(mail, array);
	assert(0 == rc);
	
	free(array->lines);
	rfc822_mail_cleanup(mail);
	json_object_put(jrfc822);
	return;
}
int main(int argc, char **argv)
{
	test_load_rfc822();
	return 0;
	
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
