#ifndef IMAP_CLIENT_H_
#define IMAP_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <json-c/json.h>

struct imap_credentials
{
	char *server;
	char *user;
	char *secret;
	char *auth_type;
};

struct imap_client_context
{
	void *user_data;
	void *priv;
	struct imap_credentials credentials[1];
	long tag_index;
	
	int (*load_credentials)(struct imap_client_context *imap, const char *credentials_file, const char *file_password);
	int (*list)(struct imap_client_context *imap, const char *folder, const char *params, json_object *jresult);
	int (*send_request)(struct imap_client_context *imap, const char *command, const char *params, json_object *jresult);
};

struct imap_client_context * imap_client_context_init(struct imap_client_context *imap, void *user_data);
void  imap_client_context_cleanup(struct imap_client_context *imap);

#ifdef __cplusplus
}
#endif
#endif
