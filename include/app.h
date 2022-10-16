#ifndef OOXML_APP_H_
#define OOXML_APP_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <json-c/json.h>

#ifndef debug_printf
#define debug_printf(fmt, ...) do { \
			fprintf(stderr, "\e[33m" "%s(%d)::" fmt "\e[39m" "\n", \
				__FILE__, __LINE__, ##__VA_ARGS__); \
		} while(0)
#endif

struct shell_context;
struct app_private;
struct app_context
{
	void *user_data;
	struct app_private *priv;
	json_object *jconfig;
	
	const char *app_path;
	const char *app_name;
	const char *work_dir;
	struct shell_context *shell;
	
	int (*init)(struct app_context *app, const char *conf_file);
	int (*run)(struct app_context *app);
	int (*stop)(struct app_context *app);
};

struct app_context *app_context_init(struct app_context *app, int argc, char **argv, void *user_data);
void app_context_cleanup(struct app_context *app);

struct mail_db_context *app_get_mail_db(struct app_context *app);
struct imap_client_context *app_get_imap_client(struct app_context *app);
#ifdef __cplusplus
}
#endif
#endif

