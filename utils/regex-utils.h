#ifndef REGEX_UTILS_H_
#define REGEX_UTILS_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct regex_matched
{
	size_t begin;
	size_t end;
};

struct regex_private;
struct regex_context
{
	struct regex_private *priv;
	void *user_data;
	
	int (*set_patterns)(struct regex_context *ctx, ssize_t num_patterns, const char *patterns[]);
	ssize_t (*match)(struct regex_context *ctx, 
		const char *text, ssize_t length,
		ssize_t *matched_pattern_id, 
		struct regex_matched **p_matched);
};
struct regex_context *regex_context_init(struct regex_context *ctx, void *user_data);
void regex_context_cleanup(struct regex_context *ctx);

#ifdef __cplusplus
}
#endif
#endif
