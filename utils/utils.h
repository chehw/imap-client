#ifndef IMAP_CLIENT_UTILS_H_
#define IMAP_CLIENT_UTILS_H_

#include <stdio.h>
#include <netdb.h>

#include <stdbool.h>
#include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef debug_printf
#ifdef _DEBUG
#define debug_printf(fmt, ...) do { \
		fprintf(stderr, "\e[33m" "%s(%d):" fmt "\e[39m" "\n", \
			__FILE__, __LINE__, ##__VA_ARGS__); \
		} while(0)
#else
#define debug_printf(fmt, ...) do { } while(0)
#endif
#endif

char *trim_left(char *p_begin, char *p_end);
char *trim_right(char *p_begin, char *p_end);
#define trim(p_begin) ({ char *p_end = p_begin +strlen(p_begin); \
		p_begin = trim_right(trim_left(p_begin, p_end), p_end); \
		p_begin; \
	})
	

ssize_t utf8_strlen(const char *str, ssize_t *p_num_bytes);
ssize_t read_password_stdin(char secret[], size_t size);


int make_nonblock(int fd);
int tcp_connect2(const char *server, const char *port, int nonblock, struct addrinfo *p_addr);
#define close_socket(sd) do { if((sd) != -1) {close(sd); sd = -1; } } while(0)


typedef const char *string;
typedef _Bool boolean;
#define json_get_value_default(jobj, type, key, def_val) ({ \
		type value = (type)def_val; \
		json_object *jvalue = NULL; \
		json_bool ok = json_object_object_get_ex(jobj, key, &jvalue); \
		if(ok && jvalue) value = (type)json_object_get_##type(jvalue); \
		value; })

#define json_get_value(jobj, type, key) json_get_value_default(jobj, type, key, (type)0)


struct clib_queue
{
	size_t size;
	size_t length;
	size_t start_pos;
	void **items;
};
int clib_queue_resize(struct clib_queue *queue, size_t new_size);
struct clib_queue *clib_queue_init(struct clib_queue *queue, size_t size);
int clib_queue_enter(struct clib_queue *queue, void *item);
void *clib_queue_leave(struct clib_queue *queue);
void clib_queue_cleanup(struct clib_queue *queue, void (*free_item)(void *));

#ifdef __cplusplus
}
#endif
#endif
