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
	cred->secret = strdup(auth_type);
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


struct imap_command *imap_command_new(const char *tag, const char *command, const char *params)
{
	assert(tag && command);
	struct imap_command *cmd = calloc(1, sizeof(*cmd));
	assert(cmd);
	
	strncpy(cmd->tag, tag, sizeof(cmd->tag));
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
	struct imap_buffer *current;
	struct imap_buffer_array in_bufs[1];
	
};

static void imap_private_free(struct imap_private *priv)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, priv);
	
	if(priv->socket_fd != -1) {
		if(priv->imap) priv->imap->disconnect(priv->imap);
		
		assert(priv->socket_fd == -1);
	}
	
	clib_queue_cleanup(priv->command_queue, (void (*)(void *))imap_command_free);
	clib_queue_cleanup(priv->pending_commands, (void (*)(void *))imap_command_free);
	
	if(priv->current) {
		imap_buffer_clear(priv->current);
		priv->current = NULL;
	}
	imap_buffer_array_cleanup(priv->in_bufs);
	
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
	
static int imap_client_connect2(struct imap_private *priv, struct imap_credentials *credentials)
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
	return 0;
}


static void *imap_client_thread(void *user_data)
{
	assert(user_data);
	int rc = 0;
	struct imap_client_context *imap = user_data;
	debug_printf("%s(%p)...\n", __FUNCTION__, imap);
	
	assert(imap && imap->priv);
	struct imap_private *priv = imap->priv;
	struct imap_credentials *credentials = priv->credentials;
	
	rc = imap_client_connect2(priv, credentials);
	if(rc) {
		pthread_exit((void *)(intptr_t)-1);
		return (void *)(intptr_t)-1;	// compatible with win32
	}
	
	gnutls_session_t session = priv->session;
	assert(priv->socket_fd);
	assert(session);
	
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGPIPE);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGHUP);
	
	struct pollfd pfd[1];
	
	struct timespec timeout = {
		.tv_sec = 1,	// 
		.tv_nsec = 0,
	};
	while(!priv->quit)
	{
		memset(pfd, 0, sizeof(pfd));
		pfd[0].fd = priv->socket_fd;
		pfd[0].events = POLLIN;
		
		
		pthread_mutex_lock(&priv->queue_mutex);
		if(priv->command_queue->length > 0) {
			pfd[0].events |= POLLOUT;
		}
		pthread_mutex_unlock(&priv->queue_mutex);
		
		int n = ppoll(pfd, 1, &timeout, &sigs);
		if(n == 0) continue; // timeout
		if(n == -1) {
			rc = errno;
			break;
		}
		
		assert(pfd[0].fd == priv->socket_fd);
		if(!((pfd[0].revents & POLLIN) || (pfd[0].revents & POLLOUT)) ) {
			perror("ppoll()");
			rc = errno;
			break;
		}
		
		if(pfd[0].revents & POLLIN) {
			char data[4096] = "";
			ssize_t cb = gnutls_record_recv(session, data, sizeof(data) - 1);
			if(cb <= 0) {
				if(cb != GNUTLS_E_AGAIN) {
					rc = cb;
					gnutls_check_error(rc);
					break;
				}
				continue;
			}
			data[cb] = '\0';
			printf("%s\n", data);
			
			pthread_mutex_lock(&priv->in_mutex);
			struct imap_buffer *current = priv->current;
			if(NULL == current) {
				current = imap_buffer_init(NULL, 4096);
				assert(current);
				priv->current = current;
			}
			
			char *p_nextline = strrchr(data, '\n');
			if(NULL == p_nextline) {
				imap_buffer_push_data(current, data, cb);
			}else {
				++p_nextline;
				size_t length = p_nextline - data;
				imap_buffer_push_data(current, data, length);
				if(imap->on_response) {
					imap->on_response(imap, current->data, current->length);
				}else {
					fprintf(stderr, "%s", current->data);
				}
				
				if(length < cb) {
					current->length = 0;
					current->start_pos = 0;
					imap_buffer_resize(current, (cb - length) + 1);
					imap_buffer_push_data(current, p_nextline, cb - length);
				}
				
			}
			pthread_mutex_unlock(&priv->mutex);
		}
		
		if(pfd[0].revents & POLLOUT) {
			///< @todo
		}

	}
	pthread_exit((void *)(intptr_t)rc);
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
	
	rc = pthread_create(&priv->th, NULL, imap_client_thread, imap);
	assert(0 == rc);
	pthread_mutex_unlock(&priv->mutex);
	
	return rc;
}

static int imap_disconnect(struct imap_client_context *imap)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, imap);
	int rc = 0;
	struct imap_private *priv = imap->priv;
	assert(priv);
	
	if(priv->connection_status < 0) return -1;
	
	pthread_mutex_lock(&priv->mutex);
	if(!priv->quit) { 
		priv->quit = 1;
		pthread_mutex_unlock(&priv->mutex);
		
		if(priv->connection_status > 0) {
			priv->connection_status = 0;
			priv->exit_code = NULL;
			rc = pthread_join(priv->th, &priv->exit_code);
			debug_printf("imap thread exited with code %p, rc = %d", priv->exit_code, rc);
		}
		
		pthread_mutex_lock(&priv->mutex);
	}
	
	if(priv->socket_fd != -1) {
		if(priv->session) {
			priv->session = NULL;
			gnutls_deinit(priv->session);
			priv->session = NULL;
		}
		close_socket(priv->socket_fd);
	}
	pthread_mutex_unlock(&priv->mutex);
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
	
	imap->priv = imap_private_new(imap);
	assert(imap->priv);
	
	return imap;
}
void  imap_client_context_cleanup(struct imap_client_context *imap)
{
	debug_printf("%s(%p)...\n", __FUNCTION__, imap);
	if(NULL == imap) return;
	
	imap_disconnect(imap);
	imap_private_free(imap->priv);
	return;
}

#if defined(TEST_IMAP_CLIENT_) && defined(_STAND_ALONE)
#include <getopt.h>
#include "app.h"

int main(int argc, char **argv)
{
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
	
	char buf[1024] = "";
	char *line = NULL;
	while((line = fgets(buf, sizeof(buf) - 1, stdin)))
	{
		if(line[0] == 'q' || line[0] == 'Q') break;
	}
	
	imap_client_context_cleanup(imap);
	return 0;
}
#endif
