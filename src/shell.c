/*
 * shell.c
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
#include <json-c/json.h>

#include <webkit2/webkit2.h>
#include "shell.h"
#include "shell_private.h"

#include "mail_db.h"
#include "imap_client.h"
#include "mail_utils.h"


enum MAILS_TREE_COLUMN
{
	MAILS_TREE_COLUMN_subject,	// string
	MAILS_TREE_COLUMN_uid,		// int64
	MAILS_TREE_COLUMN_timestamp, // uint64
	MAILS_TREE_COLUMN_flags,	// int32
	MAILS_TREE_COLUMN_data_ptr,	// pointer
	MAILS_TREE_COLUMNS_COUNT
};
static inline GtkTreeStore *create_mails_tree_store(void)
{
	GtkTreeStore *store = gtk_tree_store_new(MAILS_TREE_COLUMNS_COUNT, 
		G_TYPE_STRING, 
		G_TYPE_INT64, 
		G_TYPE_UINT64, 
		G_TYPE_INT,
		G_TYPE_POINTER);
	return store;
}

static int shell_init(struct shell_context *shell, json_object *jconfig);
static int shell_run(struct shell_context *shell);
static int shell_stop(struct shell_context *shell);

struct shell_private *shell_private_new(struct shell_context *shell)
{
	struct shell_private *priv = calloc(1, sizeof(*priv));
	assert(priv);
	priv->shell = shell;
	
	return priv;
}

struct shell_context *shell_context_init(struct shell_context *shell, struct app_context *app)
{
	if(NULL == shell) shell = calloc(1, sizeof(*shell));
	assert(shell);
	shell->app = app;
	shell->init = shell_init;
	shell->run = shell_run;
	shell->stop = shell_stop;
	
	struct shell_private *priv = shell_private_new(shell);
	assert(priv);
	shell->priv = priv;
	
	return shell;
}
void shell_context_cleanup(struct shell_context *shell)
{
	
}

static void on_show_inspector(GtkWidget *button, WebKitWebView *webview)
{
	if(NULL == webview) return;
	WebKitWebInspector *inspector = webkit_web_view_get_inspector(webview);
	if(inspector) webkit_web_inspector_show(inspector);
}

static void shell_ui_reset(struct shell_context *shell)
{
	assert(shell && shell->app && shell->priv);
	struct shell_private *priv = shell->priv;
	GtkTreeStore *store = create_mails_tree_store();
	gtk_tree_view_set_model(GTK_TREE_VIEW(priv->mail_list), GTK_TREE_MODEL(store));
	return;
}

static void load_mailbox_folders(struct shell_context *shell, json_object *jlist);
static void shell_load_mails(struct shell_context *shell)
{
	assert(shell && shell->app && shell->priv);
	struct shell_private *priv = shell->priv;
	struct mail_utils *mail = priv->mail;
	struct imap_client_context *imap = mail->imap;
	assert(mail && imap);
	
	json_object *jlist = NULL;
	int rc = mail->list(mail, "/", NULL, &jlist);
	if(0 == rc && jlist) {
		load_mailbox_folders(shell, jlist);
	}
	if(jlist) json_object_put(jlist);
	return;
}

static void on_connect_imap_server(GtkWidget *button, struct shell_context *shell)
{
	assert(shell && shell->app && shell->priv);
	struct shell_private *priv = shell->priv;
	struct imap_client_context *imap = priv->mail->imap;
	assert(imap);
	const struct imap_credentials *cred = imap_client_get_credentials(imap);
	assert(cred);
	
	int rc = 0;
	if(NULL == button) button = priv->btn_connect;

	if(priv->is_connected) {
		imap->disconnect(imap);
		shell_ui_reset(shell);
		priv->is_connected = 0;
	}else {
		gtk_widget_set_sensitive(button, FALSE);
		rc = imap->connect(imap, cred);
		if(0 == rc) {
			rc = imap->query_capabilities(imap, NULL);
			rc = imap->authenticate(imap, NULL, NULL);
			assert(0 == rc);
			priv->is_connected = 1;
			shell_load_mails(shell);
		}
		gtk_widget_set_sensitive(button, TRUE);
	}
	
	gtk_button_set_label(GTK_BUTTON(button), priv->is_connected?"Disconnect":"connect");
	return;
}

static int init_windows(struct shell_context *shell)
{
	assert(shell && shell->priv);
	struct shell_private *priv = shell->priv;
	
	GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	GtkWidget *header_bar = gtk_header_bar_new();
	GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	
	gtk_window_set_titlebar(GTK_WINDOW(window), header_bar);
	gtk_window_set_default_size(GTK_WINDOW(window), 1280, 800);
	gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header_bar), TRUE);
	
	GtkWidget *hpaned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
	gtk_box_pack_start(GTK_BOX(vbox), hpaned, TRUE, TRUE, 0);
	
	GtkWidget *scrolled_win;
	GtkWidget *mail_list = gtk_tree_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	gtk_widget_set_size_request(scrolled_win, 180, -1);
	gtk_container_add(GTK_CONTAINER(scrolled_win), mail_list);
	
	gtk_paned_add1(GTK_PANED(hpaned), scrolled_win);
	
	GtkWidget *stack_switch = gtk_stack_switcher_new();
	GtkWidget *stack = gtk_stack_new();
	gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(stack_switch), GTK_STACK(stack));
	gtk_header_bar_pack_end(GTK_HEADER_BAR(header_bar), stack_switch);
	gtk_paned_add2(GTK_PANED(hpaned), stack);
	
	GtkWidget *textview = gtk_text_view_new();
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_container_add(GTK_CONTAINER(scrolled_win), textview);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(textview), GTK_WRAP_WORD_CHAR);
	gtk_stack_add_titled(GTK_STACK(stack), scrolled_win, "textview", "TEXT");
	
	GtkWidget * webview = webkit_web_view_new();
	WebKitSettings *settings = webkit_web_view_get_settings(WEBKIT_WEB_VIEW(webview));
	g_object_set(G_OBJECT(settings), "enable-developer-extras", TRUE, NULL);
	
	GtkWidget *show_inspector = gtk_button_new_from_icon_name("preferences-system", GTK_ICON_SIZE_BUTTON);
	gtk_header_bar_pack_start(GTK_HEADER_BAR(header_bar), show_inspector);
	g_signal_connect(show_inspector, "clicked", G_CALLBACK(on_show_inspector), webview); 
	gtk_stack_add_titled(GTK_STACK(stack), webview, "webview", "WebView");
	
	static const char test_html[] = "<html><body>"
		"<h1>WebView Test</h1><hr><h3>Hello World</h3>"
		"<div id=\"subject\"></div>"
		"<div id=\"body\"></div>"
		"</body></html>";
	webkit_web_view_load_html(WEBKIT_WEB_VIEW(webview), test_html, "about:blank");
		
	
	priv->window = window;
	priv->header_bar = header_bar;
	priv->mail_list = mail_list;
	priv->textview = textview;
	priv->webview = webview;
	
	// imap ui
	GtkWidget *btn_connect = gtk_button_new_with_label("connect");
	g_signal_connect(btn_connect, "clicked", G_CALLBACK(on_connect_imap_server), shell);
	GtkWidget *url_entry = gtk_entry_new();
	priv->btn_connect = btn_connect;
	priv->url_entry = url_entry;
	gtk_header_bar_pack_start(GTK_HEADER_BAR(header_bar), btn_connect);
	gtk_header_bar_pack_start(GTK_HEADER_BAR(header_bar), url_entry);
	
	g_signal_connect_swapped(priv->window, "destroy", G_CALLBACK(shell->stop), shell);
	return 0;
}

int init_mail_list(struct shell_context *shell);
static int shell_init(struct shell_context *shell, json_object *jconfig)
{
	assert(shell && shell->app && shell->priv);
	struct shell_private *priv = shell->priv;
	struct imap_client_context *imap = app_get_imap_client(shell->app);
	assert(imap);
	const struct imap_credentials *cred = imap_client_get_credentials(imap);
	assert(cred);
	
	mail_utils_init(shell->priv->mail, imap);
	
	init_windows(shell);
	gtk_entry_set_text(GTK_ENTRY(priv->url_entry), cred->server);
	
	init_mail_list(shell);
	return 0;
}

static int shell_run(struct shell_context *shell)
{
	assert(shell && shell->priv);
	struct shell_private *priv = shell->priv;
	
	gtk_widget_show_all(priv->window);
	gtk_main();
	return 0;
}
static int shell_stop(struct shell_context *shell)
{
	gtk_main_quit();
	return 0;
}

int load_test_mail_list(struct shell_context *shell)
{
	assert(shell && shell->priv);
	struct shell_private *priv = shell->priv;
	
	struct mail_db_context *mail_db = app_get_mail_db(shell->app);
	assert(mail_db);
	
	GtkTreeView *mail_list = GTK_TREE_VIEW(priv->mail_list);
	assert(mail_list);
	
	// load test db

	struct bdb_context *db = bdb_context_init(NULL, mail_db->env, shell);
	assert(db);
	int rc = db->open(db, "test1.db", NULL, 0, 0);
	assert(0 == rc);

	
	rc = db->iter_first(db);
	
	GtkTreeStore *store = create_mails_tree_store();
	assert(store);
	
	GtkTreeIter parent, iter;
	gtk_tree_store_append(store, &parent, NULL);
	gtk_tree_store_set(store, &parent, 
		MAILS_TREE_COLUMN_subject, "root", 
		MAILS_TREE_COLUMN_uid, (uint64_t)-1,
		-1);
	
	while(0 == rc) {
		DBT *key = db->pkey;
		uint64_t uid;
		assert(key->data);
		assert(key->size == sizeof(uint64_t));
		
		uid = *(uint64_t *)key->data;
		uid = be64toh(uid);
		gtk_tree_store_append(store, &iter, &parent);
		gtk_tree_store_set(store, &iter, MAILS_TREE_COLUMN_uid, uid, -1);
		rc = db->iter_next(db, 0);
	}
	
	gtk_tree_view_set_model(mail_list, GTK_TREE_MODEL(store));
	return 0;
}

static void load_mailbox_folders(struct shell_context *shell, json_object *jlist)
{
	assert(shell && shell->priv);
	struct shell_private *priv = shell->priv;
	struct imap_client_context *imap = priv->mail->imap;
	assert(imap);
	const struct imap_credentials *cred = imap_client_get_credentials(imap);
	assert(cred);
	
	GtkTreeView *mail_list = GTK_TREE_VIEW(priv->mail_list);
	GtkTreeStore *store = create_mails_tree_store();
	assert(store);
	
	GtkTreeIter parent, iter;
	gtk_tree_store_append(store, &parent, NULL);
	gtk_tree_store_set(store, &parent, 
		MAILS_TREE_COLUMN_subject, cred->server,
		MAILS_TREE_COLUMN_uid, (uint64_t)-1,
		-1);
		
	int count = json_object_array_length(jlist);
	for(int i = 0; i < count; ++i) {
		json_object *jitem = json_object_array_get_idx(jlist, i);
		if(NULL == jitem) continue;
		
		const char *folder = json_object_get_string(jitem);
		assert(folder && folder[0]);
		
		gtk_tree_store_append(store, &iter, &parent);
		gtk_tree_store_set(store, &iter, 
			MAILS_TREE_COLUMN_subject, folder,
			MAILS_TREE_COLUMN_uid, (uint64_t)-1,
			-1);
	}
	gtk_tree_view_set_model(mail_list, GTK_TREE_MODEL(store));
	
	GtkTreePath *tpath = gtk_tree_path_new_from_string("0");
	if(tpath) {
		gtk_tree_view_expand_row(mail_list, tpath, FALSE);
		gtk_tree_path_free(tpath);
	}
	return;
}


static void on_mail_selected_changed(GtkTreeSelection *selection, struct shell_context *shell)
{
	assert(shell && shell->priv);
	struct shell_private *priv = shell->priv;
	
	GtkTreeModel *model = NULL;
	GtkTreeIter iter;
	if(!gtk_tree_selection_get_selected(selection, &model, &iter)) return;
	
	assert(model);
	uint64_t uid = -1;
	
	char *subject = NULL;
	gtk_tree_model_get(model, &iter, 
		MAILS_TREE_COLUMN_uid, &uid, 
		MAILS_TREE_COLUMN_subject, &subject, 
		-1);
	
	// load_mail_raw_data(mail_db, uid, &data);
	GtkTextView *textview = GTK_TEXT_VIEW(priv->textview);
	GtkTextBuffer *buffer = gtk_text_buffer_new(NULL);
	GtkTextIter text_iter;
	char text[200] = "";
	int cb = 0;
	
	gtk_text_buffer_get_start_iter(buffer, &text_iter);
	cb = snprintf(text, sizeof(text), "uid: %lu\n", (unsigned long)uid);
	gtk_text_buffer_insert(buffer, &text_iter, text, cb);
	
	cb = snprintf(text, sizeof(text), "subject: %s\n", subject);
	gtk_text_buffer_insert(buffer, &text_iter, text, cb);
	
	gtk_text_view_set_buffer(textview, buffer);
	
	
	char js_text[4096] = "";
	const char *js_fmt = "var subject=document.getElementById('subject'); "
		"subject.innerHTML='<p>UID: %ld</p><p style=\"color: blue\">Subject: %s</p>'";
	snprintf(js_text, sizeof(js_text), js_fmt, (long)uid, subject);
	webkit_web_view_run_javascript(WEBKIT_WEB_VIEW(priv->webview), js_text, NULL, NULL, NULL);
	
	if(subject) free(subject);
	
	
	
	return;
}
int init_mail_list(struct shell_context *shell)
{
	assert(shell && shell->priv);
	struct shell_private *priv = shell->priv;
	
	GtkTreeView *mail_list = GTK_TREE_VIEW(priv->mail_list);
	GtkCellRenderer *cr = NULL;
	GtkTreeViewColumn *col = NULL;
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("title", cr, "text", MAILS_TREE_COLUMN_subject, NULL);
	gtk_tree_view_append_column(mail_list, col);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("uid", cr, "text", MAILS_TREE_COLUMN_uid, NULL);
	gtk_tree_view_append_column(mail_list, col);
	
	cr = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new_with_attributes("timestamp", cr, "text", MAILS_TREE_COLUMN_timestamp, NULL);
	gtk_tree_view_append_column(mail_list, col);

	GtkTreeSelection *selection = gtk_tree_view_get_selection(mail_list);
	g_signal_connect(selection, "changed", G_CALLBACK(on_mail_selected_changed), shell);
	gtk_tree_view_set_grid_lines(mail_list, GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

	load_test_mail_list(shell);
	return 0;
}



#if defined(TEST_SHELL_) && defined(_STAND_ALONE)
int main(int argc, char **argv)
{
	
	return 0;
}
#endif

