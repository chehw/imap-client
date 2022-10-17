/*
 * gcloud-utils.c
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

#include <curl/curl.h>
#include "jwt_json-c.h"
#include "utils.h"

#include "gcloud-utils.h"


static int gcloud_service_load_credentials(struct gcloud_service_oauth2 *oauth, json_object *jcredentials)
{
	int rc = 0;
	if(NULL == jcredentials) return -1;
	if(oauth->jcredentials) {
		json_object_put(oauth->jcredentials);
		oauth->jcredentials = NULL;
		oauth->token_uri = NULL;
		oauth->client_email = NULL;
		jwt_json_c_reset(oauth->jwt);
	}
	oauth->jcredentials = json_object_get(jcredentials); // add_ref
	
	struct jwt_json_c *jwt = oauth->jwt;
	assert(jwt->jobject);
	json_object *jprivkey = NULL;
	json_bool ok = json_object_object_get_ex(jcredentials, "private_key", &jprivkey);
	assert(ok && jprivkey);
	const char *privkey = json_object_get_string(jprivkey);
	int cb_key = strlen(privkey);
	rc = jwt->set_alg(jwt, jwt_algorithm_rs256);
	rc = jwt->set_privkey(jwt, (const unsigned char*)privkey, cb_key, 0);
	assert(0 == rc);
	
	const char *client_email = json_get_value(jcredentials, string, client_email);
	const char *token_uri = json_get_value(jcredentials, string, token_uri);
	assert(client_email);
	assert(token_uri);
	oauth->token_uri = token_uri;
	oauth->client_email = client_email;
	return rc;
}

static int gcloud_service_set_scope(struct gcloud_service_oauth2 *oauth, const char *scopes)
{
	assert(oauth);
	if(NULL == scopes) return -1;
	
	if(oauth->scopes) {
		free(oauth->scopes);
		oauth->scopes = NULL;
	}
	oauth->scopes = strdup(scopes);
	return 0;
}

static int gcloud_service_request_token(struct gcloud_service_oauth2 *oauth, json_object **p_jresult);
struct gcloud_service_oauth2 *gcloud_service_oauth2_init(struct gcloud_service_oauth2 *oauth, 
	json_object *jcredentials, void *user_data)
{
	if(NULL == oauth) oauth = calloc(1, sizeof(*oauth));
	assert(oauth);
	oauth->user_data = user_data;
	oauth->load_credentials = gcloud_service_load_credentials;
	oauth->set_scope = gcloud_service_set_scope;
	oauth->request_token = gcloud_service_request_token;
	
	oauth->jtok = json_tokener_new();
	assert(oauth->jtok);
	
	struct jwt_json_c *jwt = jwt_json_c_init(oauth->jwt, oauth);
	assert(jwt && jwt == oauth->jwt);
	
	jwt->set_alg_string(jwt, "RS256");
	int rc = oauth->load_credentials(oauth, jcredentials);
	assert(0 == rc);
	
	return oauth;
}
void gcloud_service_oauth2_cleanup(struct gcloud_service_oauth2 *oauth)
{
	
	if(oauth->jcredentials) {
		json_object_put(oauth->jcredentials);
		oauth->jcredentials = NULL;
	}
	
	if(oauth->jtok) {
		json_tokener_free(oauth->jtok);
		oauth->jtok = NULL;
	}
	if(oauth->jresult) {
		json_object_put(oauth->jresult);
	}
	
	jwt_json_c_cleanup(oauth->jwt);
	
	return;
}

static size_t on_response(char *ptr, size_t size, size_t n, void *user_data)
{
	struct gcloud_service_oauth2 *oauth = user_data;
	assert(oauth && oauth->jtok);
	
	size_t cb = size * n;
	if(cb == 0) return 0;
	if(oauth->jerr == json_tokener_success) return cb; // only process the first json object, and skip tailing bytes
	
	oauth->jresult = json_tokener_parse_ex(oauth->jtok, ptr, cb);
	oauth->jerr = json_tokener_get_error(oauth->jtok);
	if(oauth->jerr == json_tokener_continue || oauth->jerr == json_tokener_success) return cb;
	
	return 0; // error
}

static int gcloud_service_request_token(struct gcloud_service_oauth2 *oauth, json_object **p_jresult)
{
	static char grant_type_encoded[] = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";
	static char default_scopes[] = "https://www.googleapis.com/auth/cloud-platform";
	
	assert(oauth && oauth->token_uri && oauth->client_email);
	int rc = 0;
	const char *scopes = oauth->scopes;
	if(NULL == scopes) scopes = default_scopes;
	int64_t issued_at = time(NULL);
	struct jwt_json_c *jwt = oauth->jwt;
	assert(jwt->jobject);
	
	rc = jwt->claims_add_iss(jwt, oauth->client_email);
	rc = jwt->claims_add_aud(jwt, oauth->token_uri);
	rc = jwt->claims_add_iat(jwt, issued_at);
	rc = jwt->claims_add_exp(jwt, issued_at + 3600);
	rc = jwt->claims_add(jwt, "scope", json_object_new_string(scopes));
	assert(0 == rc);
	
	char *jwt_string = NULL;
	ssize_t cb_output = jwt->serialize(jwt, &jwt_string);
	assert(cb_output > 0);
	
	char post_fields[4096] = "";
	long cb_fields = snprintf(post_fields, sizeof(post_fields), 
		"grant_type=%s&assertion=%s",
		grant_type_encoded, 
		jwt_string);
	
	CURL *curl = curl_easy_init();
	assert(curl);
	curl_easy_setopt(curl, CURLOPT_URL, oauth->token_uri);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)cb_fields);
	
	// reset jtok status
	json_tokener_reset(oauth->jtok);
	oauth->jerr = json_tokener_error_parse_eof;
	if(oauth->jresult) { 
		json_object_put(oauth->jresult); 
		oauth->jresult = NULL; 
	}
	
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, oauth);
	
	CURLcode ret = curl_easy_perform(curl);
	if(ret) {
		fprintf(stderr, "ret: %d, err_msg: %s\n", ret, curl_easy_strerror(ret));
	}
	if(oauth->jerr == json_tokener_success && oauth->jresult) {
		fprintf(stderr, "token: %s\n", json_object_to_json_string_ext(oauth->jresult, JSON_C_TO_STRING_PRETTY));
		
		if(p_jresult) *p_jresult = json_object_get(oauth->jresult); // add_ref
	}
	curl_easy_cleanup(curl);
	curl = NULL;
	
	free(jwt_string);
	jwt_string = NULL;
	return 0;
}

#if defined(TEST_GCLOUD_UTILS_) && defined(_STAND_ALONE)

#include <gnutls/gnutls.h>
int main(int argc, char **argv)
{
	gnutls_global_init();
	curl_global_init(CURL_GLOBAL_ALL);
	const char *credentials_file = ".private/credentials.json";
	if(argc > 1) credentials_file = argv[1];
	json_object *jcredentials = json_object_from_file(credentials_file);
	assert(jcredentials);
	
	struct gcloud_service_oauth2 *oauth = gcloud_service_oauth2_init(NULL, jcredentials, NULL);
	assert(oauth);
	json_object_put(jcredentials);
	
	oauth->request_token(oauth, NULL);
	gcloud_service_oauth2_cleanup(oauth);
	free(oauth);
	curl_global_cleanup();
	gnutls_global_deinit();
	return 0;
}
#endif

