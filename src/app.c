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
#include "app.h"

static int app_init(struct app_context *app, const char *conf_file);
static int app_run(struct app_context *app);
static int app_stop(struct app_context *app);

struct app_private
{
	struct app_context *app;
	char app_path[PATH_MAX];
	char *app_name;
	char work_dir[PATH_MAX];
	
	struct shell_context *shell;
	struct imap_client_context *imap;
	struct mail_db_context *mail_db;
	
	
};

struct app_private * app_private_new(struct app_context *app)
{
	struct app_private *priv = calloc(1, sizeof(*priv));
	priv->app = app;
	
	ssize_t cb = readlink("/proc/self/exe", priv->app_path, sizeof(priv->app_path));
	assert(cb > 0);
	priv->app_name = basename(priv->app_path);
	char *work_dir = dirname(priv->app_path);
	assert(priv->app_name && work_dir);
	strncpy(priv->work_dir, work_dir, sizeof(priv->work_dir));
	
	app->priv = priv;
	app->app_name = priv->app_name;
	app->app_path = priv->app_path;
	app->work_dir = priv->work_dir;
	
	return priv;
}
void app_private_free(struct app_private *priv)
{
	if(NULL == priv) return;
	
	free(priv);
}

struct app_context *app_context_init(struct app_context *app, int argc, char **argv, void * user_data)
{
	if(NULL == app) app = calloc(1, sizeof(*app));
	assert(app);
	
	struct app_private *priv = app_private_new(app);
	assert(priv);
	app->priv = priv;
		
	app->user_data = user_data;
	app->init = app_init;
	app->run = app_run;
	app->stop = app_stop;
	
	assert(app->work_dir);
	chdir(app->work_dir);
	printf("== work_dir: %s\n"
		   "== app_name: %s\n", 
		app->work_dir, app->app_name);
	
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
	return -1;
}
static int app_run(struct app_context *app)
{
	return -1;
}
static int app_stop(struct app_context *app)
{
	return -1;
}

