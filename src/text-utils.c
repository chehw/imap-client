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
static ssize_t quoted_printable_decode(const char *qp_text, ssize_t length, char **p_dst)
{
	assert(qp_text && length > 0);
	char *dst = *p_dst;
	if(NULL == dst) {
		dst = calloc(length * 3, 1);
		assert(dst);
		*p_dst = dst;
	}
	
	const char *p = qp_text;
	const char *p_end = p + length;
	ssize_t cb_dst = 0;
	
	for(;p < p_end; ++cb_dst) {
		if(*p == '=' && p < (p_end - 3)) {
			++p;
			int hi = hex_value(*p++);
			int lo = hex_value(*p++);
			if(hi == -1 || lo == -1) return -1;
			//~ assert(hi >= 0 && hi < 16);
			//~ assert(lo >= 0 && lo < 16);
			
			*dst = MAKE_BYTE(hi, lo);
			continue;
		}
		*dst++ = *p++;
	}
	return cb_dst;
}

/******************************************************************************
// https://www.rfc-editor.org/rfc/rfc1522
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
******************************************************************************/
_Bool mime_text_is_utf8(const struct mime_text *mtext)
{
	if(NULL == mtext || NULL == mtext->charset) return false;
	return (strcasecmp(mtext->charset, "utf-8") == 0) || (strcasecmp(mtext->charset, "utf8") == 0);
}

void mime_text_clear(struct mime_text *mtext)
{
	if(NULL == mtext) return;
	if(mtext->raw_data) free(mtext->raw_data);
	if(mtext->utf8) {
		free(mtext->utf8);
	}
	memset(mtext, 0, sizeof(*mtext));
	return;
}

ssize_t mime_text_decode2(struct mime_text *mtext, char **p_decoded)
{
	char type = mtext->encode_type;
	type &= ~0x20;
	if(type != 'Q' && type != 'B') return -1;
	
	if(type == 'Q') return quoted_printable_decode(mtext->text, mtext->length, p_decoded);
	
	gnutls_datum_t b64 = { .data = (unsigned char *)mtext->text, .size = mtext->length };
	gnutls_datum_t b64_decoded = { NULL, };
	int rc = gnutls_base64_decode2(&b64, &b64_decoded);
	if(rc == -1) {
		if(b64_decoded.data) gnutls_free(b64_decoded.data);
		return -1;
	}
	*p_decoded = (char *)b64_decoded.data;
	return b64_decoded.size;
}

int mime_text_parse(struct mime_text *mtext, const char *msg, ssize_t cb_msg)
{
	static const char *pattern = "=\\?(.*)\\?([Q,q,B,b]?)\\?(.*)\\?=$";
	
	if(NULL == msg) return -1;
	if(cb_msg == -1) cb_msg = strlen(msg);
	if(cb_msg < 4) return -1;
	
	int rc = 0;
	struct regex_matched *matched = NULL;
	struct regex_context re_ctx[1] = {{ NULL }};
	struct regex_context *ctx = regex_context_init(re_ctx, NULL);
	assert(ctx);
	rc = ctx->set_patterns(ctx, 1, &pattern);
	if(rc) goto label_err;
	
	char *raw_data = calloc(cb_msg + 1, 1);
	assert(raw_data);
	memcpy(raw_data, msg, cb_msg);
	
	ssize_t num_matched = ctx->match(ctx, msg, cb_msg, NULL, &matched);
	if(num_matched != 4) {
		goto label_err;
	}
	int begin = -1, end = -1;
	
	// charset := \1
	begin= matched[1].begin; end = matched[1].end;
	assert(begin != -1 && end != -1);
	raw_data[end] = '\0';
	mtext->charset = &raw_data[begin];
	
	// encode_type := \2
	begin= matched[2].begin; end = matched[2].end;
	if((end - begin) != 1) goto label_err;
	mtext->encode_type = raw_data[begin];
	
	// text := \3
	begin= matched[3].begin; end = matched[3].end;
	assert(begin != -1 && end != -1);
	raw_data[end] = '\0';
	mtext->text = &raw_data[begin];
	mtext->length = end - begin;
	
	// decode text
	if(mtext->length > 0) {
		char *decoded_text = NULL;
		ssize_t cb_decoded = mime_text_decode2(mtext, &decoded_text);
		if(cb_decoded <= 0) goto label_err;
		
		if(mime_text_is_utf8(mtext)) {
			mtext->utf8 = decoded_text;
			mtext->cb_utf8 = cb_decoded;
		}else {
			mtext->utf8 = NULL;
			ssize_t bytes_left = text_to_utf8(mtext->charset, 
				decoded_text, cb_decoded, 
				&mtext->utf8, &mtext->cb_utf8);
			free(decoded_text);
			if(bytes_left == -1) goto label_err;
		}
	}
	mtext->raw_data = raw_data;
	free(matched);
	regex_context_cleanup(ctx);
	return 0;
	
label_err:
	if(matched) free(matched);
	regex_context_cleanup(ctx);
	free(raw_data);
	return -1;
}



#if defined(TEST_TEXT_UTILS_) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
#define NUM_HDRS (3)
	const char *msg_headers[NUM_HDRS] = {
		"=?us-ascii?Q?=3Dietf-822@test.mail?=",
		"=?UTF-8?B?V2luZG93c+OCteODvOODkDIwMTLjgYxFT1PjgIHjgYTjgYTmqZ8=?=",
		"=?ISO-2022-JP?B?GyRCIVo/TTpgPlIycCFbQihGfCFBGyhCKDUwGyRCOlAbKEIv?="
	};
	
	int rc = 0;
	struct mime_text mtext[1];
	memset(mtext, 0, sizeof(mtext));
	
	for(int i = 0; i< NUM_HDRS; ++i) {
		const char *line = msg_headers[i];
		ssize_t cb_line = strlen(line);
		rc = mime_text_parse(mtext, line, cb_line);
		assert(0 == rc);
		
		printf("text(cb=%ld): (charset=%s)", (long)mtext->utf8, mtext->charset);
		printf("%s\n", mtext->utf8);
		mime_text_clear(mtext);
	}
	
#undef NUM_HDRS
	return 0;
}
#endif

