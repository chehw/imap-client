/*
 * regex-utils.c
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

#include "regex-utils.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>




struct regex_private
{
	struct regex_context *ctx;
	pcre2_code **re_list;
	ssize_t list_size;
	ssize_t num_patterns;
};

struct regex_private *regex_private_new(struct regex_context *ctx)
{
	static size_t default_size = 16;
	struct regex_private *priv = calloc(1, sizeof(*priv));
	assert(priv);
	priv->ctx = ctx;
	
	pcre2_code **re_list = calloc(default_size, sizeof(*re_list));
	assert(re_list);
	priv->re_list = re_list;
	priv->list_size = default_size;
	
	return priv;
}

static void regex_private_clear(struct regex_private *priv)
{
	if(NULL == priv) return;
	if(NULL == priv->re_list) return;
	for(int i = 0; i < priv->num_patterns; ++i) {
		pcre2_code *re = priv->re_list[i];
		if(re) {
			pcre2_code_free(re);
			priv->re_list[i] = NULL;
		}
	}
	return;
}

static void regex_private_free(struct regex_private *priv)
{
	if(NULL == priv) return;
	if(priv->re_list) {
		regex_private_clear(priv);
		free(priv->re_list);
		priv->re_list = NULL;
	}
	free(priv);
}


static int regex_set_patterns(struct regex_context *ctx, ssize_t num_patterns, const char *patterns[])
{
	if(num_patterns <= 0) return -1;
	struct regex_private *priv = ctx->priv;
	regex_private_clear(priv);
	
	if(num_patterns > priv->list_size) {
		pcre2_code **re_list = realloc(priv->re_list, num_patterns * sizeof(*re_list));
		assert(re_list);
		memset(priv->re_list + priv->list_size, 0, (num_patterns - priv->list_size) * sizeof(*re_list));
		priv->re_list = re_list;
		priv->list_size = num_patterns;
	}
	
	int rc = 0;
	int err_code = 0;
	size_t err_offset = -1;
	
	priv->num_patterns = num_patterns;
	for(ssize_t i = 0; i < num_patterns; ++i) {
		pcre2_code *re = pcre2_compile(
			(PCRE2_SPTR)patterns[i], PCRE2_ZERO_TERMINATED, 
			0,
			&err_code, &err_offset, 
			NULL);
		if(NULL == re) {
			char err_msg[200] = "";
			rc = pcre2_get_error_message_8(err_code, (unsigned char *)err_msg, sizeof(err_msg) - 1);
			fprintf(stderr, "pattern[%Zd]: err_code: %d, err_offset: %Zu, err_msg: %s\n", 
				i, err_code, err_offset, err_msg);
			return -1;
		}
		priv->re_list[i] = re;
	}
	return rc;
}

static ssize_t regex_match(struct regex_context *ctx, 
	const char *text, ssize_t length, 
	ssize_t *matched_pattern_id, 
	struct regex_matched **p_matched)
{
	assert(ctx && ctx->priv);
	int rc = 0;
	struct regex_private *priv = ctx->priv;
	if(priv->num_patterns <= 0) return -1;
	
	if(length == -1) length = strlen(text);
	if(length == 0) return 0;
	
	PCRE2_SPTR subject = (PCRE2_SPTR)text;
	
	ssize_t num_matched = 0;
	for(ssize_t re_index = 0; re_index < priv->num_patterns; ++re_index) {
		pcre2_code *re = priv->re_list[re_index];
		if(NULL == re) continue;
		
		pcre2_match_data *match_data = NULL;
		
		match_data = pcre2_match_data_create_from_pattern(re, NULL);
		assert(match_data);
		rc = pcre2_match(re, subject, length, 0, 0, match_data, NULL);
		
		if(rc == PCRE2_ERROR_NOMATCH) {
			pcre2_match_data_free(match_data);
			continue;
		}
		
		if(rc < 0) {
			fprintf(stderr, "stderr, matching error: %d\n", rc);
			pcre2_match_data_free(match_data);
			continue;
		}
		
		num_matched = rc;
		PCRE2_SIZE *offsets = pcre2_get_ovector_pointer(match_data);
		
		if(matched_pattern_id) *matched_pattern_id = re_index;
		if(p_matched) {
			struct regex_matched *matched = calloc(num_matched, sizeof(*matched));
			assert(matched);
			for(ssize_t i = 0; i < num_matched; ++i) {
				matched[i].begin = offsets[i*2];
				matched[i].end = offsets[i*2+1];
			}
			*p_matched = matched;
		}
		pcre2_match_data_free(match_data);
		break;
	}
	return num_matched;
}

struct regex_context *regex_context_init(struct regex_context *ctx, void *user_data)
{
	if(NULL == ctx) ctx = calloc(1, sizeof(*ctx));
	ctx->user_data = user_data;
	ctx->priv = regex_private_new(ctx);
	
	ctx->set_patterns = regex_set_patterns;
	ctx->match = regex_match;
	return ctx;
}
void regex_context_cleanup(struct regex_context *ctx)
{
	if(NULL == ctx) return;
	regex_private_free(ctx->priv);
	ctx->priv = NULL;
	return;
}


#if defined(TEST_REGEX_UTILS_) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	//~ PCRE2_SPTR path_pattern = (PCRE2_SPTR)"/[\\w\\-.]+/'";
	//~ const char *path_pattern = "/[\\w\\-.]+/'";
	int rc = 0;
	const char *subjects[] = {
		"* LIST (\\Marked \\HasChildren) \".\" \"INBOX\"\r\n",
		"* 1417 FETCH (FLAGS (\\Seen) BODY[HEADER] {4101}",
		"* 1 FETCH (UID 1 BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\" \"DELSP\" \"yes\" \"FORMAT\" \"flowed\") NIL NIL \"BASE64\" 9294 186 NIL NIL NIL)(\"TEXT\" \"HTML\" (\"CHARSET\" \"UTF-8\") NIL NIL \"QUOTED-PRINTABLE\" 35121 703 NIL NIL NIL) \"ALTERNATIVE\" (\"BOUNDARY\" \"0000000000002feba005807ad70a\") NIL NIL))\r\n",
		NULL
	};
	
	
	const char *patterns[] = {
		"\\* LIST (\\(.*\\)) \"(.*)\" \"(.*)\".*\r,\n$", // with flags
		"\\* LIST .*\"(.*)\" \"(.*)\".*\r\n$", // no flags
		"\\* ([0-9]*) FETCH \\(FLAGS (.*) \\{[0-9]*\\}$", // fetch result1
		"\\* ([0-9]*) FETCH \\(UID ([0-9]*) (\\w*) (.*)\r\n$", // fetch result2
		};
		
#define NUM_PATTERNS ( sizeof(patterns) / sizeof(patterns[0]) )
	static const char *key_names[NUM_PATTERNS][6] = {
		{"text", "flags", "search root", "path", NULL },
		{"text", "search root", "path", NULL },
		{"text", "MAILINDEX", "flags", "length", NULL },
		{"text", "MAININDEX", "UID", "FIELDS", "result", NULL },
	};
		
	struct regex_context re_ctx[1];
	memset(re_ctx, 0, sizeof(re_ctx));
	
	struct regex_context *ctx = regex_context_init(re_ctx, NULL);
	assert(ctx);
	
	rc = ctx->set_patterns(ctx, NUM_PATTERNS, patterns);
	assert(0 == rc);
	
	const char **p_subject = subjects;
	const char *subject = NULL;
	while((subject = *p_subject++)) {
		printf("==== text: %s\n", subject);
	
		struct regex_matched *matched = NULL;
		ssize_t pattern_index = -1;
		ssize_t num_matched = ctx->match(ctx, subject, -1, &pattern_index, &matched);
		
		printf("num_matched: %Zd\n", num_matched);
		const char **keys = NULL;
		if(pattern_index >= 0 && pattern_index < NUM_PATTERNS) keys = key_names[pattern_index];
		
		printf("== result: \n");
		for(ssize_t i = 0; i < num_matched; ++i) {
			printf("  \e[34m(matched[%Zd]: <%Zu,%Zu>)\e[39m\n", i, matched[i].begin, matched[i].end);
			if(i < 5 && keys[i]) {
				
				printf("  [%s]=%.*s\n", keys[i], (int)(matched[i].end - matched[i].begin), &subject[matched[i].begin]);
			}
		}
		if(matched) free(matched);
		
	}
	regex_context_cleanup(re_ctx);
	return 0;
}
#endif

