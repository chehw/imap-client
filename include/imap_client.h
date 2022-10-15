#ifndef IMAP_CLIENT_H_
#define IMAP_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <json-c/json.h>
#include "utils.h"

struct imap_buffer
{
	size_t size;
	size_t length;
	size_t start_pos;
	ssize_t refs;
	char *data;
};
struct imap_buffer *imap_buffer_init(struct imap_buffer *buffer, size_t size);
int imap_buffer_resize(struct imap_buffer *buffer, size_t new_size);
int imap_buffer_push_data(struct imap_buffer *buffer, char *data, size_t length);
ssize_t imap_buffer_pop_data(struct imap_buffer *buffer, char **p_data, size_t size);
void imap_buffer_clear(struct imap_buffer *buffer);
#define imap_buffer_addref(buffer) ++buffer->refs;
#define imap_buffer_unref(buffer) do { \
		if((buffer->refs > 0) && (0 == --buffer->refs)) { imap_buffer_clear(buffer); free(buffer); }; \
	} while(0)

int imap_buffer_to_lines_array(struct imap_buffer *buf, struct lines_array *array, const char *tag, size_t cb_tag);


struct imap_buffer_array
{
	size_t size;
	size_t length;
	struct imap_buffer **items;
};
struct imap_buffer_array *imap_buffer_array_init(struct imap_buffer_array *array, size_t size);
int imap_buffer_array_resize(struct imap_buffer_array *array, size_t new_size);
int imap_buffer_array_append(struct imap_buffer_array *array, struct imap_buffer *buffer);
void imap_buffer_array_cleanup(struct imap_buffer_array *array);

struct imap_credentials
{
	char *server;
	char *user;
	char *secret;
	char *auth_type;
};
struct imap_credentials * imap_credentials_load(struct imap_credentials *cred, const char *credentials_file, const char *file_password);
void imap_credentials_clear(struct imap_credentials *cred);
struct imap_credentials *imap_credentials_copy(struct imap_credentials *dst, const struct imap_credentials *src);


#define IMAP_TAG_SIZE (16)
struct imap_command
{
	char tag[IMAP_TAG_SIZE];
	char *command;
	char *params;
	int status;	// 0: pending, 1: ok, -1: error
};
struct imap_command *imap_command_new(long tag_index, const char *command, const char *params);
void imap_command_free(struct imap_command *command);


struct imap_response
{
	char tag[16];
	char *status;
	char *status_desc;
	
	ssize_t num_lines;
	char **lines;
};

struct imap_private;
struct imap_client_context
{
	void *user_data;
	struct imap_private *priv;
	
	int (*connect)(struct imap_client_context *imap, const struct imap_credentials *credentials);
	int (*disconnect)(struct imap_client_context *imap);
	
	int (*query_capabilities)(struct imap_client_context *imap, json_object **p_jresult);
	int (*authenticate)(struct imap_client_context *imap, const struct imap_credentials *credentials, json_object **p_jresult);
	int (*send_command)(struct imap_client_context *imap, const char *command, const char *params, json_object **p_jresult);
	
};

struct imap_client_context * imap_client_context_init(struct imap_client_context *imap, void *user_data);
void  imap_client_context_cleanup(struct imap_client_context *imap);

#ifdef __cplusplus
}
#endif
#endif
