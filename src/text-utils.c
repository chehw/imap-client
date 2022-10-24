/*
 * text-utils.c
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

#include <iconv.h>
#include <stdbool.h>
#include <gnutls/gnutls.h>

#include "text-utils.h"
#include "regex-utils.h"
#include "base64.h"
#include "utils.h"

static boolean s_usascii_char_table[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,  
	
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
};


// #define TSPECIALS_RFC2045 "()<>@,;:\\\"/[]?="
static boolean s_rfc2045_tspecials_table[256] = {
	[(int)'('] = 1,
	[(int)')'] = 1,
	[(int)'<'] = 1,
	[(int)'>'] = 1,
	[(int)'@'] = 1,
	[(int)','] = 1,
	[(int)';'] = 1,
	[(int)':'] = 1,
	[(int)'\\'] = 1,
	[(int)'"'] = 1,
	[(int)'/'] = 1,
	[(int)'['] = 1,
	[(int)']'] = 1,
	[(int)'?'] = 1,
	[(int)'='] = 1,
};

boolean IS_USASCII_CHAR(char c) 
{
	return s_usascii_char_table[(unsigned char)c];
}

boolean IS_TSPECIALS(char c) 
{
	return s_rfc2045_tspecials_table[(unsigned char)c];
}


static const char *s_mime_transfer_encoding_string[MIME_TRANSFER_ENCODINGS_COUNT] = 
{
	[MIME_TRANSFER_ENCODING_7bit] = "7bit",
	[MIME_TRANSFER_ENCODING_8bit] = "8bit",
	[MIME_TRANSFER_ENCODING_binary] = "binary",
	[MIME_TRANSFER_ENCODING_quoted_printable] = "quoted-printable",
	[MIME_TRANSFER_ENCODING_base64] = "base64",
	[MIME_TRANSFER_ENCODING_ietf_token] = "ietf-token",
	[MIME_TRANSFER_ENCODING_x_token] = "x-token",
};

enum MIME_TRANSFER_ENCODING mime_transfer_encoding_from_string(const char *encoding_str)
{
	if(NULL == encoding_str) return MIME_TRANSFER_ENCODING_7bit; // default
	for(int i = 0; i < MIME_TRANSFER_ENCODINGS_COUNT; ++i) {
		if(0 == strcasecmp(encoding_str, s_mime_transfer_encoding_string[i])) return i;
	}
	return -1;
}
const char *mime_transfer_encoding_to_string(enum MIME_TRANSFER_ENCODING encoding)
{
	if(encoding < 0 || encoding >= MIME_TRANSFER_ENCODINGS_COUNT) return NULL;
	return s_mime_transfer_encoding_string[encoding];
}



/**
 * text_to_utf8()
 * @param
 * @param
 * @param
 * @param
 * @return num_bytes of unprocessed text. -1 on error
 */
ssize_t text_to_utf8(const char *charset, const char *text, size_t cb_text, char **p_utf8, size_t *cb_utf8)
{
	debug_printf("%s(%s, %s, %ld) ...", __FUNCTION__, charset, text, cb_text);
	assert(charset && p_utf8 && cb_utf8);
	if(NULL == text) return -1;
	if(-1 == cb_text) cb_text = strlen(text);
	if(cb_text == 0) return 0;
	
	iconv_t cd = iconv_open("utf-8", charset);
	if(cd == (iconv_t)-1) {
		perror("text_to_utf8()::iconv_open()");
		return -1;
	}
	
	char *in_buf = (char *)text;
	size_t inbytes_left = cb_text;
	
	char *utf8 = *p_utf8;
	size_t utf8_bufsize = 0;
	if(cb_utf8) utf8_bufsize = *cb_utf8;
	if(NULL == utf8) {
		utf8_bufsize = inbytes_left * 2;
		utf8 = calloc(utf8_bufsize + 1, 1);
		assert(utf8);
		*p_utf8 = utf8;
	}
	
	assert(utf8 && utf8_bufsize > 0);
	char *out_buf = utf8;
	size_t outbytes_left = utf8_bufsize - 1;
	
	size_t cb_nonreversible = iconv(cd, &in_buf, &inbytes_left, &out_buf, &outbytes_left);
	if(cb_nonreversible == -1) {
		perror("text_to_utf8()::iconv() failed");
		iconv_close(cd);
		return -1;
	}
	
	*out_buf = '\0';
	assert(outbytes_left <= utf8_bufsize);
	*cb_utf8 = utf8_bufsize - outbytes_left;
	
	
	iconv_close(cd);
	return inbytes_left;
}


static int s_hex_value[256] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	 0, 1, 2, 3, 4, 5, 6, 7,  8, 9,-1,-1,-1,-1,-1,-1, 
	
	-1,10,11,12,13,14,15,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,10,11,12,13,14,15,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1, 
};

#define hex_value(c) s_hex_value[(unsigned char)(c)]
#define MAKE_BYTE(hi, lo) ( (((unsigned char)(hi)) << 4) | ((unsigned char)(lo)) )
ssize_t quoted_printable_decode(const char *qp_text, ssize_t length, char **p_dst)
{
	assert(qp_text && length < 1024);
	if(length == 0) return 0;
	
	char *dst = *p_dst;
	if(NULL == dst) {
		dst = calloc(length + 1, 1);
		assert(dst);
		*p_dst = dst;
	}
	const char *p = qp_text;
	const char *p_end = p + length;
	
	while(p < p_end && (p_end[-1] == '\r' || p_end[-1] == '\n' || p_end[-1] == '=')) --p_end;
	ssize_t cb_dst = 0;
	
	for(;p < p_end; ++cb_dst) {
		if(*p == '=' && p <= (p_end - 3)) {
			int hi = hex_value(p[1]);
			int lo = hex_value(p[2]);
			if(hi == -1 || lo == -1) return -1;
			*dst++ = MAKE_BYTE(hi, lo);
			p += 3;
			continue;
		}
		*dst++ = *p++;
	}
	*dst = '\0';
	return cb_dst;
}

int mime_header_value_decode(const char *msg, size_t cb_msg, char **p_utf8, size_t *p_size)
{
	static struct regex_context *re_ctx = NULL;
	static const char *pattern = 
		"=\\?([^?]*)"        // 1
		"\\?([QqBb])"        // 2
		"\\?([^?]*)"         // 3
		"\\?=";
	assert(msg && p_size);
	*p_size = 0;
	
	int rc = 0;
	ssize_t cb_utf8 = 0;
	if(NULL == re_ctx) {
		re_ctx = regex_context_init(NULL, NULL);
		assert(re_ctx);
		rc = re_ctx->set_patterns(re_ctx, 1, &pattern);
		assert(0 == rc);
	}
	
	if(cb_msg == -1) cb_msg = strlen(msg);
	if(cb_msg == 0) return 0;

	
	const char *p = msg;
	const char *p_end = p + cb_msg;
	while(p[0] && IS_WSP(p[0])) ++p;	// trim_left
	
	ssize_t utf8_bufsize = cb_msg * 2;
	if(NULL == p_utf8) return utf8_bufsize + 1;
	
	char *utf8 = *p_utf8;
	if(NULL == utf8) {
		utf8 = calloc(utf8_bufsize + 1, 1);
		assert(utf8);
		*p_utf8 = utf8;
	}
	
	
	while(p < p_end) {
		struct regex_matched *matched = NULL;
		ssize_t num_matched = re_ctx->match(re_ctx, p, p_end - p, NULL, &matched);
		if(NULL == matched) break;
		assert(num_matched == 4);
		
		ssize_t begin = matched[0].begin;
		ssize_t end = matched[0].end;
		assert(begin != -1 && end > 0);
		
		if(begin > 0) {
			memcpy(utf8 + cb_utf8, p, begin);
			cb_utf8 += begin;
		}
		
		char charset[32] = "";
		assert(matched[1].begin > 0 && matched[1].end > 0 && matched[1].end > matched[1].begin);
		ssize_t cb_charset = matched[1].end - matched[1].begin;
		assert(cb_charset < sizeof(charset));
		memcpy(charset, &p[matched[1].begin], cb_charset);
		charset[cb_charset] = '\0';
		
		assert(matched[2].begin > 0 && (matched[2].end - matched[2].begin) == 1 );
		unsigned char encoding = p[matched[2].begin];
		
		assert(matched[3].begin > 0 && matched[3].end > 0 && matched[3].end > matched[3].begin);
		const char * text = &p[matched[3].begin];
		ssize_t cb_text = matched[3].end - matched[3].begin;
		
		
		char buffer[1024] = "";
		char *decoded_text = buffer;
		ssize_t cb_decoded = -1;
		 
		switch(encoding) {
		case 'Q': case 'q': cb_decoded = quoted_printable_decode(text, cb_text, &decoded_text); break;
		case 'B': case 'b': cb_decoded = base64_decode(text, cb_text, (unsigned char **)&decoded_text); break;
		default:
			fprintf(stderr, "invalid encoding '%c'\n", encoding);
			break;
		}
		assert(cb_decoded >= 0);
		
		if(cb_decoded > 0) {
			if(0 == strcasecmp(charset, "utf8") 
				|| 0 == strcasecmp(charset, "utf-8") 
				|| 0 == strcasecmp(charset, "us-ascii")
				|| 0)
			{
				memcpy(utf8 + cb_utf8, decoded_text, cb_decoded);
				cb_utf8 += cb_decoded;
			}else {
				size_t length = utf8_bufsize - cb_utf8;
				char *dst = utf8 + cb_utf8;
				rc =  text_to_utf8(charset, decoded_text, cb_decoded, &dst, &length);
				assert(rc >= 0);
				assert(length > 0);
				cb_utf8 += length;
			}
		}
		
		p = &p[matched[0].end];
		free(matched);
	}
	
	if(p < p_end) {
		ssize_t length = p_end - p;
		memcpy(utf8 + cb_utf8, p, length);
		cb_utf8 += length;
	}
	*p_size = cb_utf8;
	utf8[cb_utf8] = '\0';
	return 0;
}



#if defined(TEST_TEXT_UTILS_) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	const char *msg_headers[] = {
		"=?us-ascii?Q?=3Dietf-822@test.mail?= Hello World <test1@example.com>",
		"=?UTF-8?B?V2luZG93c+OCteODvOODkDIwMTLjgYxFT1PjgIHjgYTjgYTmqZ8=?=",
		"=?ISO-2022-JP?B?GyRCIVo/TTpgPlIycCFbQihGfCFBGyhCKDUwGyRCOlAbKEIv?=",
		"=?utf8?q?ccc?=",
		"=?utf8?A?ccc?=", 
		"=?utf8?b?V2luZG93c+OCteODvOODkDIwMTLjgYxFT1PjgIHjgYTjgYTmqZ8=?= =?us-ascii?Q?=3Dietf-822@test.mail?=",
		"==?ISO-2022-JP?B?GyRCIVo/TTpgPlIycCFbQihGfCFBGyhCKDUwGyRCOlAbKEIv?=", 
	};
#define NUM_HDRS ( sizeof(msg_headers) / sizeof(msg_headers[0]) )
	
	int rc = 0;
	char utf8_buf[4096] = "";
	size_t utf8_bufsize = sizeof(utf8_buf);

	for(int i = 0; i< NUM_HDRS; ++i) {
		const char *line = msg_headers[i];
		ssize_t cb_line = strlen(line);
		
		char *utf8 = utf8_buf;
		size_t length = utf8_bufsize - 1;
		
		rc = mime_text_parse(line, cb_line, &utf8, &length);
		assert(0 == rc);
	
		printf("\e[32m" "%.3d: (cb=%ld): ", i, (long)length);
		printf("%s" "\e[39m" "\n", utf8);
	}
	
#undef NUM_HDRS
	return 0;
}
#endif

