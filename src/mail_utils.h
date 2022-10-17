#ifndef IMAP_MAIL_UTILS_H_
#define IMAP_MAIL_UTILS_H_

#include <stdio.h>
#include <json-c/json.h>

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

#ifdef __cplusplus
}
#endif
#endif
