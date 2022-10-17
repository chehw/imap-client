/*
 * imap-terminal.c
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
#include <gnutls/gnutls.h>
#include <vte/vte.h>
#include <webkit2/webkit2.h>

#include <gnutls/x509.h>

/**
 * build:
 * gcc -std=gnu99 -g -Wall -o imap-terminal imap-terminal.c -lm -lpthread $(pkg-config --cflags --libs gtk+-3.0 vte-2.91 gnutls webkit2gtk-4.0) 
**/

struct shell_context
{
	void *app;
	void *priv;
	GtkWidget *window;
	GtkWidget *header_bar;
	GtkWidget *vpaned;
	GtkWidget *webview;
	
	GtkWidget *sidebar;
	GtkWidget *stack;
	GtkWidget *vte;
	GtkWidget *logview;
	
	GtkWidget *connect_btn;
	GtkWidget *url_entry;
	
	GtkWidget *statusbar;
	
	gboolean is_connected;
	gnutls_session_t session;
	
};

static struct shell_context g_shell[1];

static int init_windows(struct shell_context *shell);
static int shell_init(struct shell_context *shell);
static int shell_run(struct shell_context *shell);
static int shell_stop(struct shell_context *shell);

int main(int argc, char **argv)
{
	gtk_init(&argc, &argv);
	gnutls_global_init();
	
	struct shell_context *shell = g_shell;
	shell_init(shell);
	shell_run(shell);
	
	gnutls_global_deinit();
	return 0;
}

void statusbar_update_fmt(struct shell_context *shell, const char *fmt, ...)
{
	if(NULL == shell) shell = g_shell;
	GtkStatusbar *statusbar = GTK_STATUSBAR(shell->statusbar);
	char message[4096] = "";
	va_list ap;
	va_start(ap, fmt);
	int cb = snprintf(message, sizeof(message) - 1, fmt, ap);
	va_end(ap);
	if(cb <= 0) return;
	
	guint msg_id = gtk_statusbar_get_context_id(statusbar, "info");
	gtk_statusbar_push(statusbar, msg_id, message);
	return;
}

void logview_append_fmt(struct shell_context *shell, const char *fmt, ...)
{
	char message[4096] = "";
	va_list ap;
	va_start(ap, fmt);
	int cb = snprintf(message, sizeof(message) - 1, fmt, ap);
	va_end(ap);
	if(cb <= 0) return;
	
	GtkTextView *logview = GTK_TEXT_VIEW(shell->logview);
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(logview);
	GtkTextIter iter;
	gtk_text_buffer_get_end_iter(buffer, &iter);
	gtk_text_buffer_insert(buffer, &iter, message, cb);
	return;
}

static const char s_default_html[] = "<html>"
"<head></head>"
"<body>"
"<p style=\"font-size: 18px\">Debug Messages: </p>"
"<div id=\"debug_window\"></div>"
"</body>"
"</html>";

static const char *jsc_value_type_string(JSCValue *js_value)
{
#define check_type_return(type) if(jsc_value_is_##type(js_value)) return #type
	check_type_return(array);
	check_type_return(boolean);
	check_type_return(constructor);
	check_type_return(function);
	check_type_return(null);
	check_type_return(number);
	check_type_return(string);
	check_type_return(undefined);
#undef check_type_return
	return NULL; 
}

static void on_async_ready_callback(GObject *object, GAsyncResult *result, struct shell_context *shell)
{
	GError *gerr = NULL;
	WebKitJavascriptResult *js_result = NULL;
	js_result = webkit_web_view_run_javascript_finish(WEBKIT_WEB_VIEW(object),
		result, &gerr);
	if(NULL == js_result) {
		if(gerr) {
			g_warning("run javascript failed: %s", gerr->message);
			g_error_free(gerr);
		}
		return;
	}
	
	JSCValue *js_value = NULL;
	js_value = webkit_javascript_result_get_js_value(js_result);
	if(jsc_value_is_string(js_value)) {
		JSCException *exception = NULL;
		gchar *value = NULL;
		
		value = jsc_value_to_string(js_value);
		exception = jsc_context_get_exception(jsc_value_get_context(js_value));
		if(exception) {
			statusbar_update_fmt(shell, "js_error: %s", jsc_exception_get_message(exception));
		}else
		{
		//	logview_append_fmt(shell, "js_result: %s\n", value);
		
			printf("js_result: '%s'\n", value);
		}
		g_free(value);
	}else {
		statusbar_update_fmt(shell, "js warning: unknown return type %s.", jsc_value_type_string(js_value) );
	}
	
	
	webkit_javascript_result_unref(js_result);
	
}


static void show_debug_message(struct shell_context *shell, const char *message, ssize_t length)
{
	WebKitWebView *webview = WEBKIT_WEB_VIEW(shell->webview);
	char js_script[4096] = "";
	char *cooked_message = NULL;
	if(message) {
		if(-1 == length) length = strlen(message);
		
		const char *src = message;
		if(length > 0) {
			const char *p_end = message + length;
			cooked_message = calloc(length * 2 + 1, 1);
			assert(cooked_message);
			char *dst = cooked_message;
			
			int c = 0;
			while((src < p_end) && (c = *src++)) {
				if(c == '\'') *dst++ = '\\';
				*dst++ = c;
			}
		}
	}
	ssize_t cb_script = snprintf(js_script, sizeof(js_script) - 1, 
		"document.getElementById(\"debug_window\").innerHTML += \'%s\';",
		cooked_message?cooked_message:"");
	assert(cb_script > 0);
	
	if(cooked_message) free(cooked_message);
	
	fprintf(stderr, "js_command: %s\n", js_script);
	webkit_web_view_run_javascript(webview, js_script, NULL, 
		(GAsyncReadyCallback)on_async_ready_callback, shell);
		
	logview_append_fmt(shell, "%.*s", (int)length, message?message:"");
	return;
}

static void register_signals(struct shell_context *shell);
static int init_windows(struct shell_context *shell)
{
	GtkWidget *window;
	GtkWidget *header_bar;
	GtkWidget *vbox;
	GtkWidget *vpaned;
	GtkWidget *webview;
	
	GtkWidget *grid;
	GtkWidget *sidebar;
	GtkWidget *stack;
	GtkWidget *vte;
	GtkWidget *scrolled_win;
	GtkWidget *logview;
	
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	header_bar = gtk_header_bar_new();
	vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_window_set_default_size(GTK_WINDOW(window), 1280, 720);
	gtk_window_set_titlebar(GTK_WINDOW(window), header_bar);
	gtk_container_add(GTK_CONTAINER(window), vbox);
	gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header_bar), TRUE);
	
	vpaned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
	gtk_box_pack_start(GTK_BOX(vbox), vpaned, TRUE, TRUE, 0);
	
	webview = webkit_web_view_new();
	gtk_widget_set_size_request(webview, 800, 600);
	gtk_widget_set_hexpand(webview, TRUE);
	gtk_widget_set_vexpand(webview, TRUE);
	gtk_paned_add1(GTK_PANED(vpaned), webview);
	
	
	grid = gtk_grid_new();
	gtk_paned_add2(GTK_PANED(vpaned), grid);
	
	sidebar = gtk_stack_sidebar_new();
	stack = gtk_stack_new();
	gtk_stack_sidebar_set_stack(GTK_STACK_SIDEBAR(sidebar), GTK_STACK(stack));
	gtk_grid_attach(GTK_GRID(grid), sidebar, 0, 0, 1, 1);
	gtk_grid_attach(GTK_GRID(grid), stack, 1, 0, 1, 1);
	
	vte = vte_terminal_new();
	gtk_widget_set_hexpand(vte, TRUE);
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	gtk_widget_set_size_request(scrolled_win, -1, 200);
	gtk_widget_set_vexpand(scrolled_win, TRUE);
	gtk_container_add(GTK_CONTAINER(scrolled_win), vte);
	gtk_stack_add_titled(GTK_STACK(stack), scrolled_win, "terminal", "Terminal");
	
	scrolled_win = gtk_scrolled_window_new(NULL, NULL);
	logview = gtk_text_view_new();
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_win), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
	gtk_widget_set_hexpand(scrolled_win, TRUE);
	gtk_widget_set_size_request(scrolled_win, -1, 180);
	gtk_widget_set_vexpand(logview, TRUE);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_win), GTK_SHADOW_ETCHED_IN);
	
	gtk_container_add(GTK_CONTAINER(scrolled_win), logview);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(logview), GTK_WRAP_WORD_CHAR);
	gtk_stack_add_titled(GTK_STACK(stack), scrolled_win, "logview", "Messages");
	
	

	shell->window = window;
	shell->header_bar = header_bar;
	shell->vpaned = vpaned;
	shell->webview = webview;
	
	shell->sidebar = sidebar;
	shell->stack = stack;
	shell->vte = vte;
	shell->logview = logview;
	
	GtkWidget *statusbar = gtk_statusbar_new();
	shell->statusbar = statusbar;
	gtk_widget_set_margin_top(statusbar, 2);
	gtk_widget_set_margin_bottom(statusbar, 2);
	gtk_box_pack_end(GTK_BOX(vbox), statusbar, FALSE, TRUE, 0);
	
	GtkWidget *connect_btn = gtk_button_new_with_label("connect");
	GtkWidget *url_entry = gtk_entry_new();
	char *server_url = getenv("IMAP_SERVER");
	gtk_entry_set_text(GTK_ENTRY(url_entry), server_url);
	gtk_header_bar_pack_start(GTK_HEADER_BAR(shell->header_bar), connect_btn);
	gtk_header_bar_pack_start(GTK_HEADER_BAR(shell->header_bar), url_entry);

	shell->connect_btn = connect_btn;
	shell->url_entry = url_entry;
	
	WebKitSettings *settings = webkit_web_view_get_settings(WEBKIT_WEB_VIEW(webview));
	webkit_settings_set_enable_developer_extras(settings, TRUE);
	webkit_web_view_load_html(WEBKIT_WEB_VIEW(webview), s_default_html, "about:default");
	
	return 0;
}


static void on_connect_server(GtkButton *button, struct shell_context *shell)
{
	if(shell->is_connected) {
		shell->is_connected = FALSE;
		gtk_widget_set_sensitive(shell->url_entry, TRUE);
		gtk_button_set_label(button, "connect");
		return;
	}
	
	const char *server_url = gtk_entry_get_text(GTK_ENTRY(shell->url_entry));
	if(NULL == server_url) return;
	
	int rc = 0;
	gnutls_session_t session = shell->session;
	if(NULL == session) {
		rc = gnutls_init(&session, GNUTLS_CLIENT);
		assert(0 == rc);
		shell->session = session;
		
		printf("init session: %p\n", session);
	}
	
	gtk_button_set_label(button, shell->is_connected?"disconnect":"connect");
	
	gtk_widget_set_sensitive(shell->url_entry, !shell->is_connected);
	
}

static void register_signals(struct shell_context *shell)
{
	g_signal_connect(shell->connect_btn, "clicked", G_CALLBACK(on_connect_server), shell);
	g_signal_connect_swapped(shell->window, "destroy", G_CALLBACK(shell_stop), shell);
	return;
}

static int shell_init(struct shell_context *shell)
{
	init_windows(shell);
	register_signals(shell);
	return 0;
}


#define gnutls_check_error(ret_code) do { \
		if(ret_code < 0) { \
			fprintf(stderr, "%s(%d)::%s(): gnutls error: %s\n", \
				__FILE__, __LINE__, __FUNCTION__, \
				gnutls_strerror(ret_code)); \
			exit(ret_code); \
		} \
	}while(0)
	

volatile int g_quit = 0;
static pthread_t s_pty_th;

#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
int connect2(const char *server, const char *port, struct addrinfo *p_addr)
{
	struct addrinfo hint, *serv_info = NULL, *p = NULL;
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	
	int rc = getaddrinfo(server, port, &hint, &serv_info);
	if(rc) {
		fprintf(stderr, "error: %s\n", gai_strerror(rc));
		exit(1);
	}
	
	int fd = -1;
	for(p = serv_info; NULL != p; p = p->ai_next)
	{
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(fd < 0) continue;
		
		printf("fd: %d\n", fd);
		rc = connect(fd, p->ai_addr, p->ai_addrlen);
		if(rc) {
			perror("==> connect failed");
			close(fd);
			fd = -1;
			continue;
		}
		break;
	}
	
	if(NULL == p) {
		freeaddrinfo(serv_info);
		return -1;
	}
	
	char host[NI_MAXHOST] = "";
	char service[NI_MAXSERV] = "";
	rc = getnameinfo(p->ai_addr, p->ai_addrlen, 
		host, sizeof(host), service, sizeof(service),
		NI_NUMERICSERV);
	if(0 == rc) {
		fprintf(stderr, "[info]: connected to %s:%s\n", host, service);
	}
	
	if(p_addr) {
		*p_addr = *p;
		struct sockaddr *addr = calloc(p->ai_addrlen, 1);
		assert(addr);
		p_addr->ai_addr = addr;
	}
	freeaddrinfo(serv_info);
	return fd;
}

static inline char *parse_imap_url(const char *_url, 
	char **p_protocol, char **p_server_name, char **p_port)
{
	if(NULL == _url) return NULL;
	
	char *url = strdup(_url);
	char *p = url;
	char *p_end = url + strlen(url);
	char *p_delim = strstr(url, "://");
	if(p_delim) {
		*p_delim = '\0';
		*p_protocol = p;
		p = p_delim + sizeof("://") - 1;
	}
	assert(p < p_end);
	
	*p_server_name = p;
	p_delim = strchr(p, '/');
	if(p_delim) *p_delim = '\0';

	p_delim = strchr(p, ':');
	if(p_delim) {
		*p_delim++ = '\0';
		*p_port = p_delim;
	}
	return url;
}

extern char **environ;
static int shell_run(struct shell_context *shell)
{
	gtk_widget_show_all(shell->window);
	
	VteTerminal *vte = VTE_TERMINAL(shell->vte);
	
	char *argv[] = {
		"tests/test_imap_client",
		NULL,
	};
	vte_terminal_spawn_async(vte, VTE_PTY_DEFAULT, NULL, 
		argv, environ, 
		G_SPAWN_DEFAULT, 
		NULL, NULL, NULL, 
		2000,
		NULL, NULL, NULL);

	gtk_main();
	return 0;
}
static int shell_stop(struct shell_context *shell)
{
	gtk_main_quit();
	
	g_quit = 1;
	int rc = pthread_join(s_pty_th, NULL);
	printf("pty thread exited, rc = %d\n", rc);
	return 0;
}

