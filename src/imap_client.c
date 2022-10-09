/*
 * imap_client.c
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

#include <json-c/json.h>
#include <curl/curl.h>
#include "imap_client.h"


static int imap_client_load_credentials(struct imap_client_context *imap, const char *credentials_file, const char *file_password)
{
	struct imap_credentials *credentials = imap->credentials;
	if(NULL == credentials_file) {
		credentials->server = getenv("IMAP_SERVER");
		credentials->user = getenv("IMAP_USER");
		credentials->secret = getenv("IMAP_SECRET");
		
		return 0;
	}
	
	///< @todo
	// load from file
	return -1;
}

static ssize_t on_header(char *ptr, size_t size, size_t n, FILE *fp)
{
	size_t cb = size * n;
	if(cb == 0) return 0;
	
	fprintf(fp, "Header: '%s'\n", ptr);
	
	return cb;
}

static int imap_client_list(struct imap_client_context *imap, const char *folder, const char *params, json_object *jresult)
{
	struct imap_credentials *credentials = imap->credentials;

	assert(credentials && credentials->server && credentials->user && credentials->secret);
	printf("imap server: %s\n", credentials->server);
	printf("imap user: %s\n", credentials->user);
	
	char url[4096] = "";
	snprintf(url, sizeof(url), 
		"%s%s",
		credentials->server, folder?folder:"");
	printf("url: %s\n", url);
	
	
	FILE *fp = fopen("output.hdrs.log", "w+");
	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_USERNAME, credentials->user);
	curl_easy_setopt(curl, CURLOPT_PASSWORD, credentials->secret);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_header);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, fp);
//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	
	if(params) {
		printf("params: %s\n", params);
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, params);
	}
	CURLcode ret = curl_easy_perform(curl);
	printf("ret: %d\n", ret);
	if(ret) {
		fprintf(stderr, "curlerr: %s\n", curl_easy_strerror(ret));
		
	}
	
	
	fclose(fp);
	curl_easy_cleanup(curl);
	return 0;
}

static int imap_client_send_request(struct imap_client_context *imap, const char *command, const char *params, json_object *jresult)
{
	
	return 0;
}

struct imap_client_context * imap_client_context_init(struct imap_client_context *imap, void *user_data)
{
	if(NULL == imap) imap = calloc(1, sizeof(*imap));
	assert(imap);
	imap->user_data = user_data;
	
	imap->load_credentials = imap_client_load_credentials;
	imap->list = imap_client_list;
	imap->send_request = imap_client_send_request;
	
	return imap;
}
void  imap_client_context_cleanup(struct imap_client_context *imap)
{
	return;
}

#if defined(TEST_IMAP_CLIENT_) && defined(_STAND_ALONE)
#include <getopt.h>
#include "app.c"
int main(int argc, char **argv)
{
	struct app_context *app = app_context_init(NULL, argc, argv, NULL);
	assert(app);
	printf("work_dir: %s\n", app->work_dir);
	

	curl_global_init(CURL_GLOBAL_ALL);
	struct imap_client_context *imap = imap_client_context_init(NULL, NULL);
	imap->load_credentials(imap, NULL, NULL);
	
	//~ imap->list(imap, "/INBOX;MAILINDEX=1435", NULL, NULL);
	
	static const char *default_command = "FETCH 1 UID";
	static const char *default_path = "/INBOX";
	
	const char *command = NULL;
	const char *path = "/INBOX";
	
	struct option options[] = 
	{
		{"path", required_argument, 0, 'd'},
		{"command", required_argument, 0, 'X'},
		{"default", no_argument, 0, 'q'},
		{NULL}
	};
	while(1) {
		int option_index = 0;
		int c =getopt_long(argc, argv, "d:X:q", options, &option_index);
		if(c == -1) break;
		
		switch(c) {
		case 'd': path = optarg; break;
		case 'X': command = optarg; break;
		case 'q': path = default_path; command = default_command; break;
		default:
			break;
		}
	}
	assert(path);
	
	printf("path: %s\ncommand: %s\n", path, command);
	imap->list(imap, path, command, NULL);
	return 0;
}
#endif
