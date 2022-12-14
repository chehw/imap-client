/*
 * main.c
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

#include <gtk/gtk.h>
#include "app.h"
#include "utils.h"

#include <locale.h>
#include <gnutls/gnutls.h>


static struct app_context g_app[1];
int main(int argc, char **argv)
{
//	setlocale(LC_ALL, "");
	gtk_init(&argc, &argv);
	
	gnutls_global_init();
	
	int rc = 0;
	struct app_context *app = app_context_init(g_app, argc, argv, NULL);
	assert(app && app->priv);
	
	debug_printf("== work_dir: %s\n"
		"== app_name: %s\n", 
		app->work_dir, app->app_name);
	
	rc = app->init(app, NULL);
	assert(0 == rc);
	
	rc = app->run(app);

	app_context_cleanup(app);
	gnutls_global_deinit();
	return rc;
}

