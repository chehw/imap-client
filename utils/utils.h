#ifndef IMAP_CLIENT_UTILS_H_
#define IMAP_CLIENT_UTILS_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

char *trim_left(char *p_begin, char *p_end);
char *trim_right(char *p_begin, char *p_end);
#define trim(p_begin) ({ char *p_end = p_begin +strlen(p_begin); \
		p_begin = trim_right(trim_left(p_begin, p_end), p_end); \
		p_begin; \
	})
	

ssize_t utf8_strlen(const char *str, ssize_t *p_num_bytes);
ssize_t read_password_stdin(char secret[], size_t size);


#ifdef __cplusplus
}
#endif
#endif
