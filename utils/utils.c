/*
 * utils.c
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
#include <stdbool.h>

#include <fcntl.h>
#include <errno.h>
#include <netdb.h>

#include <termios.h>
#include <unistd.h>
#include "utils.h"

static const char * s_fullwidth_white_chars[] = 
{
	"　",
	NULL
};

#define is_halfwidth_white_char(c) ((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n'))
#define is_fullwidth_white_char(s) ({ \
		ssize_t cb = 0; \
		for(const char **white = s_fullwidth_white_chars; NULL != *white; ++white) { \
			cb = strlen(*white); \
			if(strncmp(*white, s, cb) == 0) break; \
			cb = 0; \
		} \
		cb; \
	})
	
static inline ssize_t is_white_char(const char *s)
{
	char c = *s;
	if((c & 0x80) == 0) return is_halfwidth_white_char(c);
	
	return is_fullwidth_white_char(s);
}

char *trim_left(char *p_begin, char *p_end)
{
	ssize_t cb = is_white_char(p_begin);
	while(cb > 0) {
		p_begin += cb;
		cb = is_white_char(p_begin);
	}
	assert(p_begin <= p_end);
	return p_begin;
}

char *trim_right(char *p_begin, char *p_end)
{
	while(p_end > p_begin) {
		char *utf8 = p_end - 1;
		char c = *utf8;
		if((c & 0x80) == 0) {
			if(!is_halfwidth_white_char(c)) break;
			--p_end;
			continue;
		}
		while(utf8 > p_begin) {
			if((utf8[-1] & 0xC0) == 0) break;
			 --utf8;
		}
		ssize_t cb = is_fullwidth_white_char(utf8);
		if(cb == 0) break;
		p_end -= cb;
	}
	*p_end = '\0';
	return p_begin;
}


/******************************************************************************
 * utf8_strlen
******************************************************************************/
static inline _Bool is_utf8_tail(char c)
{
	/** UTF8-tail   = %x80-BF **/
	return ((c & 0x80) && (c <= 0xBF));
}

static ssize_t utf8_char_size_rfc3629(const char *p)
{
	char c = *p;
	
	/** UTF8-1: %x00-7F **/
	if((c & 0x80) == 0) return 1;
	
	/** UTF8-4: 
	 *  %xF0     %x90-BF          2( UTF8-tail ) 
	 *  %xF1-F3  3( UTF8-tail ) 
	 *  %xF4     %x80-8F          2( UTF8-tail )
	**/
	if((c & 0xF0) == 0xF0) {
		unsigned char lo = c & 0x07;
		switch(lo)
		{
		case 0: 
			if(p[1] < 0x90 || p[1] > 0xBF) return -1;
			if(!is_utf8_tail(p[2]) || !is_utf8_tail(p[3])) return -1;
			break;
		case 1: case 2: case 3:
			if(!is_utf8_tail(p[1]) || !is_utf8_tail(p[2]) || !is_utf8_tail(p[3])) return -1;
			break;
		case 4:
			if((p[1] & 0x80) != 0x80 || !is_utf8_tail(p[2]) || !is_utf8_tail(p[3])) return -1;
			break;
		default:
			return -1;
		}
		return 4;
	}
	
	/** UTF8-3
	 *  %xE0 %xA0-BF    UTF8-tail
	 *  %xE1-EC         2( UTF8-tail )
	 *  %xED            %x80-9F             UTF8-tail
	 *  %xEE-EF         2( UTF8-tail )
	**/
	if((c & 0xE0) == 0xE0)
	{
		if(c == 0xE0) {
			if(p[1] < 0xA0 || p[1] > 0xBF) return -1;
			if(!is_utf8_tail(p[2])) return -1;
		}else if(c <= 0xEC) {
			if(!is_utf8_tail(p[1]) || !is_utf8_tail(p[2])) return -1;
		}else if(c == 0xED) {
			if(p[1] < 0x80 || p[1] > 0x9F) return -1;
		}else {
			if(!is_utf8_tail(p[1]) || !is_utf8_tail(p[2])) return -1;
		}
		return 3;
	}
	
	/** UTF8-2: %xC2-DF UTF8-tail **/
	if(c < 0xC2 || c > 0xDF) return -1;
	if(!is_utf8_tail(p[1])) return -1;
	return 2;
}

ssize_t utf8_strlen(const char *str, ssize_t *p_num_bytes)
{
	assert(str);
	const char *p = str;
	ssize_t length = 0;
	if(p_num_bytes) *p_num_bytes = -1;
	
	while(*p) {
		ssize_t char_size = utf8_char_size_rfc3629(p);
		if(char_size <= 0) return -1;
		p += char_size;
		++length;
	}
	if(p_num_bytes) *p_num_bytes = (p - str);
	return length;
}




/******************************************************************************
 * read_password_stdin
******************************************************************************/
ssize_t read_password_stdin(char secret[], size_t size)
{
	if(NULL == secret || size < 1) return -1;
	
	ssize_t cb_secret = -1;
	struct termios old_attr, attr;
	memset(&old_attr, 0, sizeof(old_attr));
	int rc = tcgetattr(STDIN_FILENO, &old_attr);
	assert(0 == rc);
	attr = old_attr;
	
	attr.c_lflag &= ~ECHO; // hide input characters
	rc = tcsetattr(STDIN_FILENO, TCSANOW, &attr);
	assert(0 == rc);

	char *line = NULL;
	while((line = fgets(secret, size, stdin)))
	{
		printf("\n");
		cb_secret = strlen(line);
		if(cb_secret <= 0) {
			break;
		}
		if(line[cb_secret - 1] == '\n') --cb_secret;
		
		if(cb_secret != 0) break;	
	}
	
	// restore flags
	rc = tcsetattr(STDIN_FILENO, TCSANOW, &old_attr);	
	assert(0 == rc);
	
	if(cb_secret < 0) {
		perror("fgets() failed.");
	}
	return cb_secret;
}



/******************************************************************************
 * make_nonblock
******************************************************************************/
int make_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if(-1 == flags) {
		perror("get file flags failed.");
		return -1;
	}
	
	flags |= O_NONBLOCK;
	int rc = fcntl(fd, F_SETFL, flags);
	if(rc) {
		perror("set nonblock mode failed.");
		return -1;
	}
	return rc;
}

/******************************************************************************
 * tcp_connect2
******************************************************************************/
int tcp_connect2(const char *server, const char *port, int nonblock, struct addrinfo *p_addr)
{
	struct addrinfo hints, *serv_info = NULL, *pai = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	
	int sd = -1;
	int rc = getaddrinfo(server, port, &hints, &serv_info);
	if(rc) {
		fprintf(stderr, "[ERROR]: getaddrinfo(%s:%s) failed: %s\n", server, port, gai_strerror(rc));
		return -1;
	}
	
	for(pai = serv_info; NULL != pai; pai = pai->ai_next)
	{
		sd = socket(pai->ai_family, pai->ai_socktype, pai->ai_protocol);
		if(sd == -1) continue;
		
		rc = connect(sd, pai->ai_addr, pai->ai_addrlen);
		if(-1 == rc) {
			perror("connect failed.");
			close_socket(sd);
		}
		break;
	}
	
	if(NULL == pai) {
		freeaddrinfo(serv_info);
		return -1;
	}
	
	char hbuf[NI_MAXHOST] = "";
	char sbuf[NI_MAXSERV] = "";
	rc = getnameinfo(pai->ai_addr, pai->ai_addrlen, 
		hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), 
		NI_NUMERICHOST | NI_NUMERICSERV);
	if(0 == rc) {
		fprintf(stderr, "connected to %s:%s\n", hbuf, sbuf);
	}
	
	if(p_addr) {
		struct sockaddr *addr = calloc(pai->ai_addrlen, 1);
		assert(addr);
		*p_addr = *pai;
		p_addr->ai_addr = addr;
		p_addr->ai_next = NULL;
	}
	freeaddrinfo(serv_info);
	
	if(nonblock) {
		rc = make_nonblock(sd);
		if(rc) {
			close_socket(sd);
			return -1;
		}
	}
	return sd;
}



/******************************************************************************
struct clib_queue
{
	size_t size;
	size_t length;
	size_t start_pos;
	void **items;
};
******************************************************************************/
int clib_queue_resize(struct clib_queue *queue, size_t new_size)
{
	static const size_t alloc_size = 4096;
	if(new_size == 0) new_size = alloc_size;
	else new_size = (new_size + alloc_size - 1) / alloc_size * alloc_size;
	if(new_size <= queue->size) return -1;
	
	void **items = realloc(queue->items, new_size * sizeof(*items));
	assert(items);
	memset(items + queue->size, 0, (new_size - queue->size)*sizeof(*items));
	
	queue->items = items;
	queue->size = new_size;
	return 0;
}

struct clib_queue *clib_queue_init(struct clib_queue *queue, size_t size)
{
	if(NULL == queue) queue = calloc(1, sizeof(*queue));
	memset(queue, 0, sizeof(*queue));
	assert(queue);
	
	int rc = clib_queue_resize(queue, size);
	assert(0 == rc);
	
	return queue;
}
int clib_queue_enter(struct clib_queue *queue, void *item)
{
	int rc = clib_queue_resize(queue, queue->start_pos + queue->length + 1);
	assert(0 == rc);
	
	queue->items[queue->start_pos + queue->length++] = item;
	return 0;
}
void *clib_queue_leave(struct clib_queue *queue)
{
	if(queue->length == 0) return NULL;
	void *item = queue->items[queue->start_pos];
	queue->items[queue->start_pos] = NULL;
	++queue->start_pos;
	--queue->length;
	if(queue->length == 0) queue->start_pos = 0;
	return item;
}

void clib_queue_cleanup(struct clib_queue *queue, void (*free_item)(void *))
{
	if(NULL == queue) return;
	
	if(queue->items) {
		for(size_t i = 0; i < queue->length; ++i) {
			if(free_item) free_item(queue->items[i + queue->start_pos]);
			queue->items[i + queue->start_pos] = NULL;
		}
		free(queue->items);
		queue->items = NULL;
	}
	
	memset(queue, 0, sizeof(*queue));
	return;
}

#if defined(TEST_UTILS_) && defined(_STAND_ALONE)

#include "../utils/crypto.c"
int main(int argc, char **argv)
{
#define NUM_STRINGS (5)
	const char *utf8s[NUM_STRINGS] = {
		"hello world!\n",
		"123456789abcde", 	// (strlen + 1) == 15 bytes, cb_padding=17
		"123456789abcdef", 	// (strlen + 1) == 16 bytes, cb_padding=16
		"文字列の正確な長さを取得する",
		"其它相关信息"
	};
	for(int i = 0; i < 3; ++i){
		ssize_t n_bytes = 0;
		ssize_t cb = utf8_strlen(utf8s[i], &n_bytes);
		printf("cb=%ld, bytes=%ld, str=%s\n", (long)cb, n_bytes, utf8s[i]);
	}

	
	unsigned char encrypted[200] = "";
	unsigned char *p_dst = encrypted;
	
	struct aes256_gcm aes_buf[1];
	memset(aes_buf, 0, sizeof(aes_buf));
	struct aes256_gcm *aes = aes256_gcm_init(aes_buf, "seckey", -1, "salt", -1);
	assert(aes);
	
	aes->use_padding = 1;
	for(int i = 0; i < NUM_STRINGS; ++i) {
		size_t cb_encrypted = 0;
		int rc = aes->encrypt(aes, utf8s[i], strlen(utf8s[i]) + 1, &p_dst, &cb_encrypted);
		
		printf("==== encrypt %d ====\n", i);
		printf("rc = %d, cb_encrypted: %ld\n", rc, (long)cb_encrypted);
		
		char plain[200] = "";
		char *p = plain;
		size_t length = 0;
		
		rc = aes256_gcm_reset(aes);
		rc = aes->decrypt(aes, encrypted, cb_encrypted, &p, &length);
		printf("rc = %d, length: %ld\n", rc, (long)length);
		
		ssize_t num_bytes = 0;
		ssize_t cb = utf8_strlen(plain, &num_bytes);
		printf("cb=%ld, bytes=%ld, str=%s\n", (long)cb, num_bytes, plain);
		
		rc = aes256_gcm_reset(aes);
		
	}
	
	aes256_gcm_cleanup(aes);

	return 0;
}
#endif

