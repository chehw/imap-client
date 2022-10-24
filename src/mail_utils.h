#ifndef IMAP_MAIL_UTILS_H_
#define IMAP_MAIL_UTILS_H_

#include <stdio.h>
#include <json-c/json.h>

#include <libsoup/soup.h>
#include "imap_client.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mail_utils
{
	struct imap_client_context *imap;
	ssize_t (*query_uidlist)(struct mail_utils *mail, const char *folder, ssize_t limits , uint64_t **p_uidlist);
	int (*fetch)(struct mail_utils *mail, int64_t uid, const char *params, json_object **p_jresult);
	int (*list)(struct mail_utils *mail, const char *folder, const char *params, json_object **p_jresult);
};
struct mail_utils *mail_utils_init(struct mail_utils *mail, struct imap_client_context *imap);
void mail_utils_cleanup(struct mail_utils *mail);

enum RFC822_MAIL_PARSE_STAGE
{
	RFC822_MAIL_PARSE_STAGE_finished = 999,
};
struct rfc822_mail_body
{
	SoupMessageHeaders *headers;
	struct imap_buffer content[1];
	int is_multipart;
	enum RFC822_MAIL_PARSE_STAGE stage;	// 0: init, 1: parse headers, 2: parse body, 3: parse multipart-header 4: parse multipart-body, 999: finished
};
void rfc822_mail_body_clear(struct rfc822_mail_body *body);

struct rfc822_mail
{
	SoupMessageHeaders *headers;
	size_t max_parts;
	ssize_t num_parts;
	struct rfc822_mail_body *parts;
};
int rfc822_mail_parse(struct rfc822_mail * mail, const struct lines_array *array);
void rfc822_mail_cleanup(struct rfc822_mail *mail);
int rfc822_mail_parse_json(struct rfc822_mail *mail, json_object *jrfc822);


ssize_t mime_headers_parse(SoupMessageHeaders *headers, const char **lines, const char **p_bottom);
ssize_t mime_body_parse(struct imap_buffer *body, SoupMessageHeaders *headers, 
	const char *boundary, size_t cb_boundary,
	const char **lines, const char **p_bottom);

#ifdef __cplusplus
}
#endif
#endif
