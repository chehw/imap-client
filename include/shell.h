#ifndef OOXML_SHELL_H_
#define OOXML_SHELL_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <json-c/json.h>

struct app_context;
struct shell_private;
struct shell_context
{
	struct app_context *app;
	struct shell_private *priv;
	struct json_object *jconfig;
	
	int (*init)(struct shell_context *shell, json_object *jconfig);
	int (*run)(struct shell_context *shell);
	int (*stop)(struct shell_context *shell);
};

struct shell_context *shell_context_init(struct shell_context *shell, struct app_context *app);
void shell_context_cleanup(struct shell_context *shell);

int shell_load_ooxml_file(struct shell_context *shell, const char *filename);
#ifdef __cplusplus
}
#endif
#endif
