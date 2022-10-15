/*
 * imap_client.c
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

#include <json-c/json.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>

#include <limits.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>

#include "imap_client.h"
#include "utils.h"
#include "utils_crypto.h"


#define IMAP_CREDENTIALS_DEFAULT_SALT "IMAP_CLIENT"

struct imap_credentials * imap_credentials_load(struct imap_credentials *cred, const char *credentials_file, const char *file_password)
{
	int rc = 0;
	if(NULL == cred) cred = calloc(1, sizeof(*cred));
	else memset(cred, 0, sizeof(*cred));
	
	json_object *jcredentials = NULL;
	const char *server = NULL, *user = NULL, *secret = NULL, *auth_type = NULL;
	if(NULL == credentials_file) {
		server = getenv("IMAP_SERVER");
		user = getenv("IMAP_USER");
		secret = getenv("IMAP_SECRET");
		auth_type = getenv("IMAP_AUTH_TYPE");
	}else{
		jcredentials = json_object_from_file(credentials_file);
		if(jcredentials) {
			server = json_get_value(jcredentials, string, server);
			user = json_get_value(jcredentials, string, user);
			secret = json_get_value(jcredentials, string, secret);
			auth_type = json_get_value(jcredentials, string, auth_type);
			
		}
	}

	assert(server && user && secret);
	if(NULL == auth_type) auth_type = "PLAIN";
	
	cred->server = strdup(server);
	cred->user = strdup(user);
	cred->secret = strdup(secret);
	cred->auth_type = strdup(auth_type);
	if(jcredentials) json_object_put(jcredentials);
	
	if(file_password) {
		gnutls_datum_t secret_data = { NULL };
		rc = gnutls_base64_decode2(&(gnutls_datum_t){(void *)cred->secret, strlen(cred->secret) }, &secret_data);
		assert(GNUTLS_E_SUCCESS == rc);
		
		char *plain_secret = NULL;
		size_t cb_secret = 0;
		struct aes256_gcm aes[1];
		memset(aes, 0, sizeof(aes));
		aes256_gcm_init(aes, file_password, -1, 
			IMAP_CREDENTIALS_DEFAULT_SALT, sizeof(IMAP_CREDENTIALS_DEFAULT_SALT) - 1);
		rc = aes256_gcm_decrypt2(aes, secret_data.data, secret_data.size, &plain_secret, &cb_secret);
		assert(0 == rc);
		aes256_gcm_cleanup(aes);
		
		gnutls_free(secret_data.data);
		free(cred->secret);
		cred->secret = plain_secret;
	}
	return cred;
}

void imap_credentials_clear(struct imap_credentials *cred)
{
	if(NULL == cred) return;
	if(cred->server) free(cred->server);
	if(cred->user) free(cred->user);
	if(cred->secret) free(cred->secret);
	if(cred->auth_type) free(cred->auth_type);
	memset(cred, 0, sizeof(*cred));
}
struct imap_credentials *imap_credentials_copy(struct imap_credentials *dst, const struct imap_credentials *src)
{
	assert(src);
	if(NULL == dst) dst = calloc(1, sizeof(*dst));
	else {
		imap_credentials_clear(dst);
	}
	if(src->server) dst->server = strdup(src->server);
	if(src->user) dst->user = strdup(src->user);
	if(src->secret) dst->secret = strdup(src->secret);
	if(src->auth_type) dst->auth_type = strdup(src->auth_type);
	return dst;
}


struct imap_command *imap_command_new(long tag_index, const char *command, const char *params)
{
	#define TAG_FMT "A%.6ld" 
	assert(tag_index >= 0 && NULL != command);
	struct imap_command *cmd = calloc(1, sizeof(*cmd));
	assert(cmd);
	
	if(tag_index >= 0) {
		snprintf(cmd->tag, sizeof(cmd->tag) - 1, TAG_FMT, tag_index);
	}
	cmd->command = strdup(command);
	if(params) cmd->params = strdup(params);
	return cmd;
	
}
void imap_command_free(struct imap_command *cmd)
{
	if(NULL == cmd) return;
	if(cmd->command) free(cmd->command);
	if(cmd->params) free(cmd->params);
	memset(cmd, 0, sizeof(*cmd));
	free(cmd);
}

size_t imap_command_to_string(const struct imap_command *cmd, char **p_command) 
{
	ssize_t cb_tag = strlen(cmd->tag);
	ssize_t cb_command = strlen(cmd->command);
	ssize_t cb_params = cmd->params?strlen(cmd->params):0;
	
	ssize_t total_bytes = 0;
	
	if(cb_tag > 0) total_bytes = cb_tag + 1;
	if(cb_command) total_bytes += cb_command;
	if(cb_params) total_bytes += 1 + cb_params;
	total_bytes += sizeof("\r\n") - 1; 
	
	if(NULL == p_command) return total_bytes + 1;
	
	char *sz_command = *p_command;
	if(NULL == sz_command) {
		sz_command = calloc(total_bytes + 1, 1);
		assert(sz_command);
		*p_command = sz_command;
	}
	char *p = sz_command;
	
	if(cb_tag > 0) {
		memcpy(p, cmd->tag, cb_tag); 
		p+= cb_tag;
		*p++ = ' ';
	}
	
	memcpy(p, cmd->command, cb_command); 
	p += cb_command;
	
	if(cb_params > 0) {
		*p++ = ' ';
		memcpy(p, cmd->params, cb_params); 
		p += cb_params;
	}
	
	*p++ = '\r'; *p++ = '\n'; *p = '\0';
	
	assert((p - sz_command) == total_bytes);
	
	return total_bytes;
}



struct imap_private
{
	struct imap_client_context *imap;
	pthread_mutex_t mutex;
	gnutls_session_t session;
	
	int socket_fd;
	int connection_status;
	int quit;
	
	struct imap_credentials credentials[1];
	long tag_index;
	
	pthread_t th;
	void *exit_code;
	
	pthread_mutex_t queue_mutex;
	struct clib_queue command_queue[1];
	struct clib_queue pending_commands[1];	// waiting for responses
	
	
	// 
	pthread_mutex_t in_mutex;
	struct imap_buffer buffer[1];
};

static void imap_private_free(struct imap_private *priv)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, priv);
	
	if(priv->imap) {
		priv->imap->disconnect(priv->imap);
	}
	
	if(priv->buffer->data) {
		imap_buffer_clear(priv->buffer);
	}
	
	clib_queue_cleanup(priv->command_queue, (void (*)(void *))imap_command_free);
	clib_queue_cleanup(priv->pending_commands, (void (*)(void *))imap_command_free);
		
	pthread_mutex_destroy(&priv->in_mutex);
	pthread_mutex_destroy(&priv->queue_mutex);
	pthread_mutex_destroy(&priv->mutex);
	
	free(priv);
}

static struct imap_private *imap_private_new(struct imap_client_context *imap)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, imap);
	
	struct imap_private *priv = calloc(1, sizeof(*priv));
	assert(priv);
	priv->imap = imap;
	
	int rc = pthread_mutex_init(&priv->mutex, NULL);
	assert(0 == rc);
	
	rc = pthread_mutex_init(&priv->queue_mutex, NULL);
	assert(0 == rc);
	
	rc = pthread_mutex_init(&priv->in_mutex, NULL);
	assert(0 == rc);
	
	clib_queue_init(priv->command_queue, 0);
	clib_queue_init(priv->pending_commands, 0);
	
	rc = gnutls_init(&priv->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
	assert(rc >= 0);
	
	imap_buffer_init(priv->buffer, 65536);
	
	return priv;
}




#define gnutls_check_error(ret_code) do { \
		if(ret_code < 0) { \
			fprintf(stderr, "%s(%d)::%s(): gnutls error: %s\n", \
				__FILE__, __LINE__, __FUNCTION__, \
				gnutls_strerror(ret_code)); \
			exit(ret_code); \
		} \
	}while(0)
	
	
static int imap_get_response(struct imap_private *priv, 
	gnutls_session_t session, 
	struct imap_buffer *buf,
	const char *tag, size_t cb_tag,
	struct lines_array *p_result_lines
)
{
	int rc = 0;
	if(NULL == buf) buf = priv->buffer;
	struct lines_array *array = p_result_lines;
	if(NULL == array) {
		array = calloc(1, sizeof(*array));
		assert(array);
	}
	const int timeout = 1000;
	while(!priv->quit) {
		char data[4096] = "";
		ssize_t cb_available = 0;
		ssize_t cb = 0;
		cb_available = gnutls_record_check_pending(session);
		while(cb_available > 0) {
			size_t size = sizeof(data) - 1;
			if(size > cb_available) size = cb_available;
			
			cb = gnutls_record_recv(session, data, size);
			assert(cb > 0);
			assert(cb == size);
			
			imap_buffer_push_data(buf, data, cb);
			cb_available -= size;
		}
		
		if(buf->length > 0) {
			rc = imap_buffer_to_lines_array(buf, array, tag, cb_tag);
			if(rc <= 0) break; 
		}
		
		struct pollfd pfd[1] = {{
			.fd = priv->socket_fd,
			.events = POLLIN,
		}};
		int n = poll(pfd, 1, timeout);
		if(n == 0) {
			debug_printf("poll in timeout\n");
			continue;
		}
		if(n == -1) {
			rc = errno;
			break;
		}
		
		cb = gnutls_record_recv(session, data, sizeof(data) - 1);
		if(cb < 0) {
			if(cb == GNUTLS_E_AGAIN || cb == GNUTLS_E_INTERRUPTED) continue;
			rc = cb;
			break;
		}
		rc = imap_buffer_push_data(buf, data, cb);
		assert(0 == rc);
		
		rc = imap_buffer_to_lines_array(buf, array, tag, cb_tag);
		if(rc <= 0) break;
	}
	
	if(NULL == p_result_lines) {
		lines_array_clear(array);
		free(array);
	}
	return rc;
}

static int imap_client_connect2(struct imap_private *priv, const struct imap_credentials *credentials)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, priv);
	
	int rc = 0;
	assert(credentials);
	assert(credentials->server && credentials->user && credentials->secret);
	
	char url[4096] = "";
	strncpy(url, credentials->server, sizeof(url) - 1);
	
	// parse url
	int use_tls = 1;
	char *protocol = NULL, *server = NULL, *port = NULL;
	char *p = strstr(url, "://");
	if(p) {
		*p = '\0';
		p += sizeof("://") - 1;
		protocol = url;
		server = p;
	}else {
		server = url;
	}
	if(protocol) use_tls = (0 == strcasecmp(protocol, "imaps"));
	p = strchr(server, '/');
	if(p) *p = '\0';
	port = strchr(server, ':');
	if(port) *port++ = '\0';
	if(NULL == port) port = use_tls?"993":"143"; 
	
	assert(use_tls == 1); 	// force use tls
	pthread_mutex_lock(&priv->mutex);
	
	int socket_fd = tcp_connect2(server, port, 1, NULL);
	if(socket_fd == -1) {
		priv->connection_status = -1;
		pthread_mutex_unlock(&priv->mutex);
		return -1;
	}
	
	priv->socket_fd = socket_fd;
	priv->connection_status = 1;	// connected, trying to handshake
	pthread_mutex_unlock(&priv->mutex);
	
	debug_printf("socket_fd: %d\n", socket_fd);
	
	gnutls_session_t session = priv->session;

	// tls handshake
	gnutls_certificate_credentials_t x509 = NULL;
	rc = gnutls_certificate_allocate_credentials(&x509);
	gnutls_check_error(rc);
	
	rc = gnutls_certificate_set_x509_system_trust(x509);
	gnutls_check_error(rc);
	
	// init tls session
	if(NULL == session) {
		rc = gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
		gnutls_check_error(rc);
		priv->session = session;
	}
	
	printf("server_name: %s\n", server);
	rc = gnutls_server_name_set(session, GNUTLS_NAME_DNS, server, strlen(server));
	gnutls_check_error(rc);
	
	rc = gnutls_set_default_priority(session);
	rc = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509);
	gnutls_check_error(rc);
	gnutls_session_set_verify_cert(session, server, 0);
	
	gnutls_transport_set_int(session, socket_fd);
	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	
	do {
		rc = gnutls_handshake(session);
	}while(rc < 0 && gnutls_error_is_fatal(rc) == 0);
	gnutls_check_error(rc);
	
	char *desc = gnutls_session_get_desc(session);
	printf("Session Info: %s\n", desc);
	gnutls_free(desc);
	
	unsigned int num_certs = 0;
	const gnutls_datum_t *cert_list = gnutls_certificate_get_peers(session, &num_certs);
	for(size_t i = 0; i < num_certs; ++i){
		const gnutls_datum_t *cert_data = &cert_list[i];
		assert(cert_data && cert_data->data && cert_data->size > 0);
		
		gnutls_x509_crt_t cert;
		rc = gnutls_x509_crt_init(&cert);
		gnutls_check_error(rc);
		
		rc = gnutls_x509_crt_import(cert, cert_data, GNUTLS_X509_FMT_DER);
		gnutls_check_error(rc);
		
		gnutls_datum_t pem = { NULL };
		rc = gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_PEM, &pem);
		printf("== cert[%u]: \n%s\n",(unsigned int)i, (char *)pem.data); 
		if(pem.data) free(pem.data);
		gnutls_x509_crt_deinit(cert);

	}
	
	// waiting for server response
	debug_printf("waiting for server response ...\n");
	//~ int num_retries = 5;
	//~ const int timeout = 5000;
	
	struct lines_array array[1];
	memset(array, 0, sizeof(array));
	
	struct imap_buffer tmp_buf[1];
	memset(tmp_buf, 0, sizeof(tmp_buf));
	
	rc = imap_get_response(priv, session, tmp_buf, NULL, 0, array);
	assert(0 == rc);
	
	
	//~ struct imap_buffer *buf = priv->buffer;
	
	
	//~ while(!priv->quit && num_retries-- > 0) {
		//~ char data[4096] = "";
		//~ ssize_t cb = 0;
		//~ ssize_t cb_available = gnutls_record_check_pending(session);
		
		//~ rc = 1;	// need more data
		//~ while(cb_available > 0) {
			//~ ssize_t size = sizeof(data);
			//~ if(size > cb_available) size = cb_available;
			
			//~ cb = gnutls_record_recv(session, data, size);
			//~ if(cb < 0) {
				//~ rc = cb;
				//~ break;
			//~ }
			
			//~ imap_buffer_push_data(buf, data, cb);
			//~ cb_available -= cb;
		//~ }
		//~ if(rc < 0) break;
		
		//~ if(buf->length > 0) {
			//~ rc = imap_buffer_to_lines_array(buf, array, NULL, 0);
			//~ if(rc <= 0) break;
		//~ }
	
		//~ struct pollfd pfd[1] = {{
			//~ .fd = socket_fd,
			//~ .events = POLLIN,
		//~ }};
		
		//~ while(!priv->quit) {
			//~ int n = poll(pfd, 1, timeout);
			//~ if(n == 0) continue;
			//~ if(n == -1) {
				//~ rc = errno;
				//~ break;
			//~ }
			
			//~ rc = 0;
			//~ cb = gnutls_record_recv(session, data, sizeof(data) - 1);
			//~ if(cb < 0) {
				//~ rc = cb;
				//~ if(rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED) continue;
				//~ break;
			//~ }
			//~ assert(cb > 0);
			//~ imap_buffer_push_data(buf, data, cb);
			//~ rc = imap_buffer_to_lines_array(buf, array, NULL, 0);
			//~ if(rc <= 0) break;
		//~ }
		//~ if(rc <= 0) break;
	//~ }
	
	lines_array_clear(array);
	imap_buffer_clear(tmp_buf);
	return 0;
}

static int imap_connect(struct imap_client_context *imap, const struct imap_credentials *credentials)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, imap);
	int rc = -1;
	struct imap_private *priv = imap->priv;
	assert(priv);
	
	pthread_mutex_lock(&priv->mutex);
	if(priv->connection_status == 1) {
		pthread_mutex_unlock(&priv->mutex);
		return 1; // already connected
	}
	
	
	imap_credentials_copy(priv->credentials, credentials);
	pthread_mutex_unlock(&priv->mutex);
	
	
	//rc = pthread_create(&priv->th, NULL, imap_client_thread, imap);
	rc = imap_client_connect2(priv, credentials);
	assert(0 == rc);

	return rc;
}

static int imap_disconnect(struct imap_client_context *imap)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, imap);
	int rc = 0;
	struct imap_private *priv = imap->priv;
	assert(priv);
	
	if(priv->session) {
		priv->session = NULL;
		gnutls_deinit(priv->session);
		priv->session = NULL;
	}
	
	if(priv->socket_fd != -1) {
		close_socket(priv->socket_fd);
	}
	imap_buffer_clear(priv->buffer);
	return rc;
}

static int imap_request(struct imap_private *priv, gnutls_session_t session, const struct imap_command *cmd)
{
	char *sz_command = NULL;
	ssize_t cb_command = imap_command_to_string(cmd, &sz_command);
	printf("command: [%s]\n", sz_command);
	
	assert(cb_command > 0);
	struct pollfd pfd[1] = {{
		.fd = priv->socket_fd,
		.events = POLLOUT,
	}};
	
	int rc = 0;
	const int timeout = 1000; 
	while(!priv->quit) {
		pfd[0].events = POLLOUT;
		pfd[0].revents = 0;
		
		int n = poll(pfd, 1, timeout);
		if(n == 0) {
			debug_printf("poll out timeout\n");
			continue;
		}
		if(n == -1) {
			rc = errno;
			break;
		}
		if(pfd[0].revents & POLLOUT) {
			ssize_t cb = gnutls_record_send(session, sz_command, cb_command);
			if(cb < 0) {
				if(cb == GNUTLS_E_AGAIN || cb == GNUTLS_E_INTERRUPTED) continue;
				rc = cb;
			}
		}else {
			rc = errno;
		}
		break;
	}
	
	free(sz_command);
	return rc;
}


static int lines_array_to_json(struct lines_array *array, const char *tag, ssize_t cb_tag, json_object **p_jresult)
{
	int rc = 0;
	json_object *jresult = json_object_new_object();
	if(p_jresult) *p_jresult = jresult;
	
	json_object *jmessages = json_object_new_array();
	json_object *jdata_lines = json_object_new_array();
	
	if(tag) json_object_object_add(jresult, "tag", json_object_new_string(tag));
	json_object_object_add(jresult, "messages", jmessages);
	
	
	for(size_t i = 0; i < array->length; ++i) {
		// dump line
		char *line = array->lines[i];
		printf("parse line[%d]: %s\n", (int)i, line);
		
		char *token = NULL;
		char *p = line;
		if(NULL == p) continue;
		
		if(*p == '*') { // message lines
			json_object_array_add(jmessages, json_object_new_string(line));
			
		}else if(cb_tag > 0 && strncasecmp(p, tag, cb_tag) == 0 && p[cb_tag] == ' ') { // command status line
			p += cb_tag + 1;
			char *status = strtok_r(p, " \r\n", &token);
			if(NULL == status) {
				rc = -1;
				break;
			}
			json_object_object_add(jresult, "status", json_object_new_string(status));
			
			char *desc = strtok_r(NULL, "\r\n", &token);
			json_object_object_add(jresult, "status_desc", json_object_new_string(desc?desc:""));
		}else { // data lines
			json_object_array_add(jdata_lines, json_object_new_string(line));
		}
	}
	
	if(json_object_array_length(jdata_lines) > 0) {
		json_object_object_add(jresult, "data", jdata_lines);
	}
	json_object_object_add(jresult, "ret_code", json_object_new_int(rc));
	
	if(NULL == p_jresult) json_object_put(jresult);
	return rc;
}

static int imap_client_send_command(struct imap_client_context *imap, const char *command, const char *params, json_object **p_jresult)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, imap);
	int rc = 0;
	struct imap_private *priv = imap->priv;
	assert(priv && priv->session);
	
	gnutls_session_t session = priv->session;
	struct imap_command *cmd = NULL;
	
	if(NULL == command) cmd = imap_command_new(-1, params, NULL);	// send partial requests
	else cmd = imap_command_new(++priv->tag_index, command, params);
	assert(cmd);
	
	rc = imap_request(priv, session, cmd);
	if(rc != 0) {
		debug_printf("send command failed. tag=%s, command=%s, rc = %d\n", cmd->tag, cmd->command, rc);
		imap_command_free(cmd);
		return rc;
	}

	struct lines_array array[1];
	memset(array, 0, sizeof(array));
	
	imap_buffer_clear(priv->buffer);
	rc = imap_get_response(priv, session, NULL, cmd->tag, strlen(cmd->tag), array);
	if(rc != 0) {
		debug_printf("get response failed. tag=%s, command=%s, rc = %d\n", cmd->tag, cmd->command, rc);
		imap_command_free(cmd);
		lines_array_clear(array);
		return rc;
	}
	
	const char *tag = cmd->tag;
	ssize_t cb_tag = strlen(tag);
	rc = lines_array_to_json(array, tag, cb_tag, p_jresult);

	lines_array_clear(array);
	imap_command_free(cmd);
	return rc;
}



static int imap_client_query_capabilities(struct imap_client_context *imap, json_object **p_jresult)
{
	static const char command[] = "CAPABILITY";
	return imap->send_command(imap, command, NULL, p_jresult);
}

static ssize_t make_credential_data(const struct imap_credentials	*credentials, char **p_b64)
{
	const char *user = credentials->user;
	const char *secret = credentials->secret;
	assert(user && secret);
	
	gnutls_datum_t cred[1] = {{ NULL }};
	gnutls_datum_t b64[1] = {{ NULL }};
	
	int cb_user = strlen(user);
	int cb_secret = strlen(secret);
	assert(cb_user > 0 && cb_secret > 0);
	
	cred->data = calloc(1 + cb_user + 1 + cb_secret + 1, 1);
	assert(cred->data);
	unsigned char *p = cred->data;
	*p++ = '\0';
	memcpy(p, user, cb_user);
	p += cb_user;
	
	*p++ = '\0';
	memcpy(p, secret, cb_secret);
	p += cb_secret;
	cred->size = p - cred->data;
	
	
	int rc = gnutls_base64_encode2(cred, b64);
	assert(0 == rc);
	
	ssize_t cb = b64->size;
	*p_b64 = (char *)b64->data;
	
	for(size_t i = 0; i < cred->size; ++i) {
		if(i && (i % 16) == 0) printf("\n");
		printf("%.2x ", cred->data[i]);
	}
	printf("\n");
	free(cred->data);
	
	return cb;
}
static int imap_client_authenticate(struct imap_client_context *imap, const struct imap_credentials *credentials, json_object **p_jresult)
{
	static const char command[] = "AUTHENTICATE PLAIN";
	debug_printf("%s(%p)...\n", __FUNCTION__, imap);
	
	int rc = 0;
	struct imap_private *priv = imap->priv;
	assert(priv && priv->session);
	
	gnutls_session_t session = priv->session;
	struct imap_command *cmd = NULL;
	
	cmd = imap_command_new(++priv->tag_index, command, NULL);
	assert(cmd);
	
	const char *tag = cmd->tag;
	ssize_t cb_tag = strlen(tag);
	
	rc = imap_request(priv, session, cmd);
	assert(0 == rc);
	// check result
	

	struct imap_buffer tmp_buf[1];
	memset(tmp_buf, 0, sizeof(tmp_buf));
	
	struct lines_array array[1];
	memset(array, 0, sizeof(array));
	rc = imap_get_response(priv, session, tmp_buf, NULL, 0, array);
	assert(0 == rc);
	imap_buffer_clear(tmp_buf);
	
	assert(array->length > 0);
	if(array->lines[0][0] != '+') {
		lines_array_clear(array);
		imap_command_free(cmd);
		exit(1);
	}
	
	
	
	
	
	if(NULL == credentials) credentials = priv->credentials;
	char *b64 = NULL;
	ssize_t cb_data = make_credential_data(credentials, &b64);
	assert(cb_data > 0);
	rc = imap_request(priv, session, &(struct imap_command){.command = (char*)b64,});
	assert(0 == rc);
	free(b64);
	
	lines_array_clear(array);
	rc = imap_get_response(imap->priv, session, NULL, tag, cb_tag, array);
	assert(0 == rc);
	
	lines_array_clear(array);
	imap_command_free(cmd);
	return rc;
}

struct imap_client_context * imap_client_context_init(struct imap_client_context *imap, void *user_data)
{
	if(NULL == imap) imap = calloc(1, sizeof(*imap));
	else memset(imap, 0, sizeof(*imap));
	assert(imap);
	
	imap->user_data = user_data;
	imap->connect = imap_connect;
	imap->disconnect = imap_disconnect;
	
	imap->query_capabilities = imap_client_query_capabilities;
	imap->authenticate = imap_client_authenticate;
	imap->send_command = imap_client_send_command;
	
	imap->priv = imap_private_new(imap);
	assert(imap->priv);
	
	return imap;
}
void  imap_client_context_cleanup(struct imap_client_context *imap)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, imap);
	if(NULL == imap) return;
	imap_private_free(imap->priv);
	return;
}

#if defined(TEST_IMAP_CLIENT_) && defined(_STAND_ALONE)
#include <getopt.h>
#include "app.h"

struct imap_client_context *app_get_imap_client(struct app_context *app);
int main(int argc, char **argv)
{
	gnutls_global_init();
	
	struct app_context *app = app_context_init(NULL, argc, argv, NULL);
	assert(app);
	printf("work_dir: %s\n", app->work_dir);

	struct imap_client_context *imap = imap_client_context_init(NULL, app);
	assert(imap);

	struct imap_credentials cred[1];
	memset(cred, 0, sizeof(cred));
	imap_credentials_load(cred, NULL, NULL);
	printf("==== credentials: \n"
		"server: %s\n"
		"user: %s\n"
		"secret: ***************\n"
		"auth_type: %s\n",
		cred->server, cred->user, cred->auth_type);
	
	int rc = imap->connect(imap, cred);
	assert(0 == rc);
	

	json_object *jresult = NULL;
	rc = imap->query_capabilities(imap, &jresult);
	
	if(jresult) {
		fprintf(stderr, "jresult: %s\n", json_object_to_json_string_ext(jresult, JSON_C_TO_STRING_PRETTY));
		json_object_put(jresult);
		jresult = NULL;
	}
	
	rc = imap->authenticate(imap, NULL, &jresult);
	assert(0 == rc);
	if(jresult) {
		fprintf(stderr, "jresult: %s\n", json_object_to_json_string_ext(jresult, JSON_C_TO_STRING_PRETTY));
		json_object_put(jresult);
		jresult = NULL;
	}
	
	char buf[1024] = "";
	char *line = NULL;
	while((line = fgets(buf, sizeof(buf) - 1, stdin)))
	{
		if(line[0] == 'q' || line[0] == 'Q') break;
		
		int cb = strlen(line);
		if(cb > 0) {
			if(line[cb - 1] == '\n') {
				line[--cb] = '\0';
				if(cb > 0 && line[cb - 1] == '\r') line[--cb] = '\0';
			}
			
			if(cb > 0) {
				rc = imap->send_command(imap, line, NULL, &jresult);
				printf("rc: %d\n", rc);
				if(jresult) {
					const char *tag = json_get_value(jresult, string, tag);
					if(tag) {
						char path_name[200] = "";
						snprintf(path_name, sizeof(path_name), "%s.json", tag);
						printf("save to %s\n", path_name);
						json_object_to_file_ext(path_name, jresult, 
							JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
					}else {
						fprintf(stderr, "jresult: %s\n", 
							json_object_to_json_string_ext(jresult, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE));
					}
					
					json_object_put(jresult);
					jresult = NULL;
				}
			}
		}
		
	}
	imap_client_context_cleanup(imap);
	app_context_cleanup(app);
	
	gnutls_global_deinit();
	return 0;
}

#endif
