#ifndef TEXT_UTILS_H_
#define TEXT_UTILS_H_

#include <stdio.h>
#include <stdbool.h>

typedef _Bool boolean;

#ifdef __cplusplus
extern "C" {
#endif

boolean IS_USASCII_CHAR(char c);
boolean IS_TSPECIALS(char c);
#define IS_WSP(c)    ( ((c) == ' ')  || ((c) == '\t') )
#define IS_CRLF(c)   ( ((c) == '\r') || ((c) == '\n') )
#define IS_TOKEN_CHAR(c) (IS_USASCII_CHAR(c) && (c) != ' ' && !IS_TSPECIALS(c))

enum MIME_TRANSFER_ENCODING
{
	MIME_TRANSFER_ENCODING_7bit = 0,
	MIME_TRANSFER_ENCODING_8bit,
	MIME_TRANSFER_ENCODING_binary,
	MIME_TRANSFER_ENCODING_quoted_printable,
	MIME_TRANSFER_ENCODING_base64,
	MIME_TRANSFER_ENCODING_ietf_token,
	MIME_TRANSFER_ENCODING_x_token,
	
	MIME_TRANSFER_ENCODINGS_COUNT,
};
enum MIME_TRANSFER_ENCODING mime_transfer_encoding_from_string(const char *encoding_str);
const char *mime_transfer_encoding_to_string(enum MIME_TRANSFER_ENCODING encoding);

/**
 * text_to_utf8()
 * @param
 * @param
 * @param
 * @param
 * @return num_bytes of unprocessed text. -1 on error
 */
ssize_t text_to_utf8(const char *charset, const char *text, size_t cb_text, char **p_utf8, size_t *cb_utf8);

ssize_t quoted_printable_decode(const char *qp_text, ssize_t length, char **p_dst);

/**
 *  https://www.rfc-editor.org/rfc/rfc2045
**/
int mime_header_value_decode(const char *value, size_t cb_value, char **p_utf8, size_t *p_size);
#define mime_text_parse mime_header_value_decode
//~ int mime_text_parse(const char * msg, size_t cb_msg, char **p_utf8, size_t *p_size);

#ifdef __cplusplus
}
#endif
#endif
