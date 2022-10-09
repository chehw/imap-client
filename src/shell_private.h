#ifndef SHELL_PRIVATE_H_
#define SHELL_PRIVATE_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <gtk/gtk.h>
#include <limits.h>

#include "app.h"
#include "shell.h"

struct shell_private
{
	struct shell_context *shell;
	GtkWidget *window;
	GtkWidget *header_bar;
	GtkWidget *grid;
	
	GtkWidget *hpaned;
	GtkWidget *mail_list;
	GtkWidget *textview;
	GtkWidget *webview;
	
	GtkStyleProvider *css;
	
	GtkWidget *font_btn;
};

#ifdef __cplusplus
}
#endif
#endif
