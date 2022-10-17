/*
 * app.c
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

#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <getopt.h>

#include "app.h"
#include "shell.h"
#include "mail_db.h"
#include "imap_client.h"

static int app_init(struct app_context *app, const char *conf_file);
static int app_run(struct app_context *app);
static int app_stop(struct app_context *app);

struct app_private
{
	struct app_context *app;
	char app_path[PATH_MAX];
	char *app_name;
	char work_dir[PATH_MAX];
	
	int argc;
	char **argv;
	char conf_file[PATH_MAX];
	
	struct shell_context *shell;
	struct imap_client_context *imap;
	struct mail_db_context *mail_db;
	
	
};

struct imap_client_context *app_get_imap_client(struct app_context *app)
{
	if(NULL == app || NULL == app->priv) return NULL;
	return app->priv->imap;
}

struct mail_db_context *app_get_mail_db(struct app_context *app)
{
	if(NULL == app || NULL == app->priv) return NULL;
	return app->priv->mail_db;
}

struct app_private * app_private_new(struct app_context *app)
{
	struct app_private *priv = calloc(1, sizeof(*priv));
	priv->app = app;
	
	ssize_t cb = readlink("/proc/self/exe", priv->app_path, sizeof(priv->app_path));
	assert(cb > 0);
	priv->app_name = basename(priv->app_path);
	(void)dirname(priv->app_path);
	char *work_dir = getcwd(priv->work_dir, sizeof(priv->work_dir));
	assert(work_dir);
	
	app->priv = priv;
	app->app_name = priv->app_name;
	app->app_path = priv->app_path;
	app->work_dir = priv->work_dir;
	
	return priv;
}
void app_private_free(struct app_private *priv)
{
	debug_printf("%s(%p) ...\n", __FUNCTION__, priv);
	if(NULL == priv) return;
	
	if(priv->imap) imap_client_context_cleanup(priv->imap);
	if(priv->mail_db) mail_db_context_cleanup(priv->mail_db);
	
	free(priv);
}

static void print_usuage(struct app_context *app)
{
	const char *app_name = app?app->app_name:"[app_name]";
	fprintf(stderr, "Usuage: %s [--conf=<conf_file>] [--work_dir=<work_dir>]\n", app_name);
	return;
}

static int app_private_parse_args(struct app_private *priv, int argc, char **argv)
{
	static struct option options[] = {
		{"conf", required_argument, 0, 'c' },
		{"help", no_argument, 0, 'h'},
		{"work_dir", required_argument, 0, 'w'},
		{NULL}
	};
	
	int rc = 0;
	const char *conf_file = NULL;
	const char *work_dir = NULL;
	while(1) {
		int option_index = 0;
		int c = getopt_long(argc, argv, "c:hw:", options, &option_index);
		if(c == -1) break;
		
		switch(c) {
		case 'c': conf_file = optarg; break;
		case 'w': work_dir = optarg; break;
		case 'h':
		default:
			print_usuage(priv->app);
			exit((c != 'h'));
		}
	}
	
	if(work_dir) {
		rc = chdir(work_dir);
		if(0 == rc) strncpy(priv->work_dir, work_dir, sizeof(priv->work_dir) -1);
		else {
			perror("chdir failed");
		}
	}
	
	if(conf_file) strncpy(priv->conf_file, conf_file, sizeof(priv->conf_file));
	else {
		snprintf(priv->conf_file, sizeof(priv->conf_file), "conf/%s", priv->app_name);
		char *p = strrchr(priv->conf_file, '.');
		if(NULL == p) {
			size_t cb = strlen(priv->conf_file);
			assert((cb + 5) < sizeof(priv->conf_file));
			p = priv->conf_file + cb;
		}
		strncpy(p, ".json", priv->conf_file + sizeof(priv->conf_file) - p);
		conf_file = priv->conf_file;
	}
	
	json_object *jconfig = json_object_from_file(conf_file);
	if(NULL == jconfig) {
		debug_printf("[WARNING]: load config file failed: %s", conf_file);
	}
	priv->app->jconfig = jconfig;
	
	priv->argc = argc;
	priv->argv = argv;
	if(optind < argc)
	{
		priv->argc = argc - optind;
		priv->argv = &argv[optind];
	}
	return 0;
}

struct app_context *app_context_init(struct app_context *app, int argc, char **argv, void * user_data)
{
	if(NULL == app) app = calloc(1, sizeof(*app));
	assert(app);
	
	app->user_data = user_data;
	app->init = app_init;
	app->run = app_run;
	app->stop = app_stop;
	
	struct app_private *priv = app_private_new(app);
	assert(priv);
	app->priv = priv;

	int rc = app_private_parse_args(priv, argc, argv);
	assert(0 == rc);
	
	return app;
}

void app_context_cleanup(struct app_context *app)
{
	if(NULL == app) return;
	app_private_free(app->priv);
	app->priv = NULL;
}


static int app_init(struct app_context *app, const char *conf_file)
{
	int rc = 0;
	assert(app && app->priv);

	struct app_private *priv = app->priv;
	json_object *jconfig = NULL;
	if(conf_file) {
		jconfig = json_object_from_file(conf_file);
		assert(jconfig);
		
		if(app->jconfig) json_object_put(app->jconfig);
		app->jconfig = jconfig;
	}
	if(NULL == jconfig) jconfig = app->jconfig;
	
	struct mail_db_context *mail_db = mail_db_context_init(NULL, NULL, 1, app);
	assert(mail_db);
	priv->mail_db = mail_db;
	
	struct imap_client_context *imap = imap_client_context_init(NULL, app);
	assert(imap);
	priv->imap = imap;
	const char *credentials_file = NULL;
	if(jconfig) credentials_file = json_get_value(jconfig, string, credentials_file);
	struct imap_credentials *cred = imap_credentials_load(NULL, credentials_file, NULL);
	imap_client_set_credentials(imap, cred);
	
	struct shell_context *shell = shell_context_init(NULL, app);
	assert(shell);
	priv->shell = shell;
	rc = shell->init(shell, jconfig);

	return rc;
}
static int app_run(struct app_context *app)
{
	assert(app && app->priv);
	struct app_private *priv = app->priv;
	struct shell_context *shell = priv->shell;
	
	if(shell) shell->run(shell);
	return 0;
}
static int app_stop(struct app_context *app)
{
	assert(app && app->priv);
	struct app_private *priv = app->priv;
	struct shell_context *shell = priv->shell;
	
	if(shell) shell->stop(shell);
	return -1;
}

