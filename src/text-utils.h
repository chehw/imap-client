#ifndef TEXT_UTILS_H_
#define TEXT_UTILS_H_

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * text_to_utf8()
 * @param
 * @param
 * @param
 * @param
 * @return num_bytes of unprocessed text. -1 on error
 */
ssize_t text_to_utf8(const char *charset, const char *text, size_t cb_text, char **p_utf8, size_t *cb_utf8);

/**
 *  https://www.rfc-editor.org/rfc/rfc1522
**/
struct mime_text
{
	char *raw_data;
	const char *charset;
	char encode_type;
	const char *text;
	size_t length;
	
	char *utf8;
	size_t cb_utf8;
};
_Bool mime_text_is_utf8(const struct mime_text *mime);
void mime_text_clear(struct mime_text *mime);
int mime_text_parse(struct mime_text *mime, const char *msg_header, ssize_t cb_msg);

#ifdef __cplusplus
}
#endif
#endif
