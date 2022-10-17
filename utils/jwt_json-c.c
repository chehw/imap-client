/*
 * jwt_json-c.c
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

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>

#include <stdint.h>
#include <stdbool.h>

#include "base64.h"
#include "utils.h"

/*******************************************************
 * JWT library: 
 * 	backend: libgnutls + libjson-c
 *******************************************************/

/* 
 * https://www.rfc-editor.org/rfc/rfc7519 
 */
#include "jwt_json-c.h"

static const char *s_jwt_alg_strings[jwt_algorithms_count] = {
	[jwt_algorithm_none] = "none",
	[jwt_algorithm_hs256] = "HS256", 
	[jwt_algorithm_hs384] = "HS384", 
	[jwt_algorithm_hs512] = "HS512", 
	
	[jwt_algorithm_rs256] = "RS256", 
	[jwt_algorithm_rs384] = "RS384", 
	[jwt_algorithm_rs512] = "RS512", 
	
	[jwt_algorithm_es256] = "ES256", 
	[jwt_algorithm_es384] = "ES384", 
	[jwt_algorithm_es512] = "ES512", 
};

enum private_key_type
{
	private_key_type_none,
	private_key_type_hmac,
	private_key_type_x509
};

struct jwt_private
{
	enum jwt_algorithm alg;
	enum private_key_type key_type; 
	size_t key_size;
	unsigned char key[512];
	gnutls_x509_privkey_t x509_key;
	gnutls_digest_algorithm_t digest_alg;
};

static int jwt_set_alg_string(struct jwt_json_c *jwt, const char *algorithm)
{
	assert(jwt && jwt->priv);
	struct jwt_private *priv = jwt->priv;
	priv->alg = jwt_algorithm_none;
	if(NULL == algorithm) return 0;
	
	for(int i = 0; i < jwt_algorithms_count; ++i) {
		if(strcasecmp(algorithm, s_jwt_alg_strings[i]) == 0) {
			return jwt->set_alg(jwt, i);
		}
	}
	return -1;
}
static int jwt_set_alg(struct jwt_json_c *jwt, enum jwt_algorithm alg)
{
	assert(jwt && jwt->priv);
	struct jwt_private *priv = jwt->priv;
	priv->alg = jwt_algorithm_none;
	priv->key_size = 0;
	
	if(alg < 0 || alg >= jwt_algorithms_count) return -1;
	priv->alg = alg;
	
	switch(alg) {
	case jwt_algorithm_hs256: case jwt_algorithm_rs256: case jwt_algorithm_es256: 
		priv->digest_alg = GNUTLS_DIG_SHA256;
		priv->key_size = 256;
		break;
	case jwt_algorithm_hs384: case jwt_algorithm_rs384: case jwt_algorithm_es384: 
		priv->digest_alg = GNUTLS_DIG_SHA384;
		priv->key_size = 384;
		break;
	case jwt_algorithm_hs512: case jwt_algorithm_rs512: case jwt_algorithm_es512: 
		priv->digest_alg = GNUTLS_DIG_SHA512;
		priv->key_size = 512;
		break;
	default:
		break;
	}
			
	return 0;
}
int jwt_set_privkey(struct jwt_json_c *jwt, const unsigned char *privkey, size_t cb_key, int key_format)
{
	assert(jwt && jwt->priv);
	struct jwt_private *priv = jwt->priv;
	int rc = 0;
	priv->key_type = private_key_type_none;
	
	switch(priv->alg) {
	case jwt_algorithm_none: return 0;
	case jwt_algorithm_hs256: case jwt_algorithm_hs384: case jwt_algorithm_hs512:
		assert(privkey && cb_key <= 512);
		memcpy(priv->key, privkey, cb_key);
		
		priv->key_type = private_key_type_hmac; 
		if(priv->alg == jwt_algorithm_hs256) priv->key_size = 256;
		if(priv->alg == jwt_algorithm_hs384) priv->key_size = 384;
		if(priv->alg == jwt_algorithm_hs512) priv->key_size = 512;
		
		return 0;
	case jwt_algorithm_rs256: case jwt_algorithm_rs384: case jwt_algorithm_rs512:
	case jwt_algorithm_es256: case jwt_algorithm_es384: case jwt_algorithm_es512:
		assert(privkey && cb_key);
		if(NULL == priv->x509_key) {
			rc = gnutls_x509_privkey_init(&priv->x509_key);
			if(rc) return rc;
		}
		if(key_format == -1) key_format = 0;
		rc = gnutls_x509_privkey_import(priv->x509_key, &(gnutls_datum_t){(unsigned char *)privkey, cb_key}, 
			(key_format == 0)?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER);
		if(0 == rc) priv->key_type = private_key_type_x509;
		return rc;
	default:
		break;
	}
	return -1;
}
static int jwt_claims_add(struct jwt_json_c *jwt, const char *key, json_object *jvalue)
{
	assert(jwt && jwt->jobject);
	assert(key && jvalue);
	
	json_object *jobject = jwt->jobject;
	json_object *jclaims = NULL;
	json_bool ok = json_object_object_get_ex(jobject, "claims", &jclaims);
	if(!ok || NULL == jclaims) {
		jclaims = json_object_new_object();
		assert(jclaims);
		json_object_object_add(jobject, "claims", jclaims);
	}
	return json_object_object_add(jclaims, key, jvalue);
}

static int jwt_claims_remove(struct jwt_json_c *jwt, const char *key)
{
	assert(jwt && jwt->jobject);
	assert(key);
	
	json_object *jobject = jwt->jobject;
	json_object *jclaims = NULL;
	json_bool ok = json_object_object_get_ex(jobject, "claims", &jclaims);
	if(!ok || NULL == jclaims) return -1;
	
	json_object_object_del(jclaims, key);
	return 0;
}
static ssize_t jwt_serialize(struct jwt_json_c *jwt, char **p_output)
{
	assert(jwt && jwt->priv && jwt->jobject);
	struct jwt_private *priv = jwt->priv;
	json_object *jobject = jwt->jobject;
	json_object *jheader = NULL;
	json_object *jclaims = NULL;
	json_bool ok;
	
	ok = json_object_object_get_ex(jobject, "header", &jheader);
	if(!ok || NULL == jheader) {
		jheader = json_object_new_object();
		assert(jheader);
		json_object_object_add(jheader, "alg", json_object_new_string(s_jwt_alg_strings[priv->alg]));
		json_object_object_add(jheader, "typ", json_object_new_string("JWT"));
		json_object_object_add(jobject, "header", jheader);
	}
	ok = json_object_object_get_ex(jobject, "claims", &jclaims);
	if(!ok || NULL == jclaims) {
		jclaims = json_object_new_object();
		assert(jclaims);
		json_object_object_add(jclaims, "iat", json_object_new_int64(time(NULL)));
		json_object_object_add(jobject, "claims", jclaims);
	}
	
	int rc = 0;
	char *b64url_header = NULL;
	char *b64url_claims = NULL;
	char *b64url_sig = NULL;
	
	const char *header = json_object_to_json_string_ext(jheader, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	assert(header);
	debug_printf("header: %s", header);
	ssize_t cb_header = base64url_encode(header, strlen(header), &b64url_header);
	assert(cb_header > 0 && b64url_header) ;
	
	const char *claims = json_object_to_json_string_ext(jclaims, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	assert(claims);
	debug_printf("claims: %s", claims);
	ssize_t cb_claims = base64url_encode(claims, strlen(claims), &b64url_claims);
	assert(cb_claims > 0 && b64url_claims);
	
	ssize_t output_bufsize = cb_header + 1 + cb_claims + 1 + 1024;
	assert(output_bufsize > 0);

	char *output = calloc(output_bufsize, 1);
	assert(output);
	char *p = output;
	memcpy(p, b64url_header, cb_header);
	p += cb_header;
	*p++ = '.';
	
	memcpy(p, b64url_claims, cb_claims);
	p += cb_claims;
	*p = '\0';
	size_t cb_msg = p - output;
	debug_printf("message: %s", output);
	
	unsigned char sig[512] = { 0 };
	size_t cb_sig = 0;
	if(priv->key_type == private_key_type_hmac) {
		rc = gnutls_hmac_fast(priv->digest_alg, priv->key, priv->key_size, 
			output, cb_msg, sig);
		assert(0 == rc);
		cb_sig = priv->key_size;
	}else if(priv->key_type == private_key_type_x509) {
		cb_sig = sizeof(sig);
		rc = gnutls_x509_privkey_sign_data(priv->x509_key, priv->digest_alg, 0, 
			&(gnutls_datum_t){.data = (unsigned char *)output, .size = cb_msg }, 
			sig, &cb_sig);
		assert(0 == rc);
	}
	
	if(cb_sig > 0) {
		cb_sig = base64url_encode(sig, cb_sig, &b64url_sig);
	}
	
	if(cb_sig > 0 && b64url_sig) {
		*p++ = '.';
		memcpy(p, b64url_sig, cb_sig);
		p += cb_sig;
	}
	
	cb_msg = p - output;
	*p = '\0';
	*p_output = output;
	
	free(b64url_header);
	free(b64url_claims);
	free(b64url_sig);
	return cb_msg;
}

static int jwt_claims_add_iss(struct jwt_json_c *jwt, const char *issuer)
{
	assert(jwt && jwt->jobject);
	if(NULL == issuer) return -1;
	return jwt->claims_add(jwt, "iss", json_object_new_string(issuer));
}
//~ static int jwt_claims_add_sub(struct jwt_json_c *jwt, const char *subject);
static int jwt_claims_add_aud(struct jwt_json_c *jwt, const char *audience)
{
	return jwt->claims_add(jwt, "aud", json_object_new_string(audience));
}
static int jwt_claims_add_exp(struct jwt_json_c *jwt, int64_t expiration)
{
	assert(jwt && jwt->jobject);
	return jwt->claims_add(jwt, "exp", json_object_new_int64(expiration));
}
//~ static int jwt_claims_add_nbf(struct jwt_json_c *jwt, int64_t not_before);
static int jwt_claims_add_iat(struct jwt_json_c *jwt, int64_t issued_at)
{
	assert(jwt && jwt->jobject);
	if(issued_at <= 0) issued_at = time(NULL);
	return jwt->claims_add(jwt, "iat", json_object_new_int64(issued_at));
}
static int jwt_claims_add_jti(struct jwt_json_c *jwt, const char *jwt_id)
{
	assert(jwt && jwt->jobject);
	if(NULL == jwt_id) return -1;
	return jwt->claims_add(jwt, "jti", json_object_new_string(jwt_id));
}

struct jwt_json_c * jwt_json_c_init(struct jwt_json_c *jwt, void *user_data)
{
	if(NULL == jwt) jwt = calloc(1, sizeof(*jwt));
	assert(jwt);
	
	jwt->jobject = json_object_new_object();
	assert(jwt->jobject);
	
	jwt->user_data = user_data;
	struct jwt_private *priv = calloc(1, sizeof(*priv));
	assert(priv);
	jwt->priv = priv;
	
	jwt->set_alg_string = jwt_set_alg_string;
	jwt->set_alg = jwt_set_alg;
	jwt->set_privkey = jwt_set_privkey;
	jwt->claims_add = jwt_claims_add;
	jwt->claims_remove = jwt_claims_remove;
	jwt->serialize = jwt_serialize;
	
	
	jwt->claims_add_iss = jwt_claims_add_iss;
	jwt->claims_add_aud = jwt_claims_add_aud;
	jwt->claims_add_exp = jwt_claims_add_exp;
	jwt->claims_add_iat = jwt_claims_add_iat;
	jwt->claims_add_jti = jwt_claims_add_jti;
	return jwt;
}
void jwt_json_c_reset(struct jwt_json_c *jwt)
{
	if(NULL == jwt) return;
	if(jwt->jobject) {
		json_object_put(jwt->jobject);
		jwt->jobject = NULL;
	}
	jwt->jobject = json_object_new_object();
	return;
}
void jwt_json_c_cleanup(struct jwt_json_c *jwt)
{
	if(NULL == jwt) return;
	if(jwt->priv) {
		struct jwt_private *priv = jwt->priv;
		if(priv->alg > jwt_algorithm_hs512 && priv->alg < jwt_algorithms_count)
		{
			gnutls_x509_privkey_deinit(priv->x509_key);
		}else {
			memset(priv->key, 0, sizeof(priv->key));
			priv->key_size = 0;
		}
		priv->alg = jwt_algorithm_none;
		free(priv);
		jwt->priv = NULL;
	}
	if(jwt->jobject) {
		json_object_put(jwt->jobject);
		jwt->jobject = NULL;
	}
	return;
}

#if defined(TEST_JWT_JSON_C_) && defined(_STAND_ALONE)
#include <stdarg.h>
#include <curl/curl.h>

#define TEST(func, ...) do { \
		fprintf(stderr, "\e[33m==== %s() ====\e[39m\n", #func); \
		int rc = func( __VA_ARGS__ ); \
		fprintf(stderr, "%s==> rc = %d\e[39m\n================\n\n", rc?"\e[31m":"\e[32m", rc); \
		assert(0 == rc); \
	} while(0)

static int test_jwt_generate();
static int test_oauth2(int argc, char **argv);

int main(int argc, char **argv)
{
	int rc = 0;
	TEST(test_jwt_generate, argc, argv);
	
	rc = test_oauth2(argc, argv);
	
	return rc;
}

static int test_jwt_generate(int argc, char **argv)
{
	int rc = 0;
	struct jwt_json_c *jwt = jwt_json_c_init(NULL, NULL);
	assert(jwt);
	
	const char *iss = "761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com";
	
	rc = jwt->set_alg(jwt, jwt_algorithm_rs256);
	rc = jwt->claims_add(jwt, "iss", json_object_new_string(iss));
	
	char *output = NULL;
	ssize_t cb_output = jwt->serialize(jwt, &output);
	
	printf("output(cb=%ld): %s\n", (long)cb_output, output);
	free(output);
	output = NULL;
	cb_output = 0;
	
	const char *credentials_file = ".private/credentials.json";
	if(argc > 1) credentials_file = argv[1];
	json_object *jcredentials = json_object_from_file(credentials_file);
	assert(jcredentials);
	
	json_object *jprivkey = NULL;
	json_bool ok = json_object_object_get_ex(jcredentials, "private_key", &jprivkey);
	assert(ok && jprivkey);
	
	const char *privkey = json_object_get_string(jprivkey);
	int cb_key = strlen(privkey);
	rc = jwt->set_privkey(jwt, (const unsigned char*)privkey, cb_key, 0);
	assert(0 == rc);
	json_object_put(jcredentials);
	jcredentials = NULL;
	
	cb_output = jwt->serialize(jwt, &output);
	
	printf("output(cb=%ld): %s\n", (long)cb_output, output);
	free(output);
	output = NULL;
	cb_output = 0;
	
	jwt_json_c_cleanup(jwt);
	free(jwt);
	return rc;
}
static int test_oauth2(int argc, char **argv)
{
	curl_global_init(CURL_GLOBAL_ALL);
	
	int rc = 0;
	struct jwt_json_c *jwt = jwt_json_c_init(NULL, NULL);
	assert(jwt);
	
	const char *credentials_file = ".private/credentials.json";
	if(argc > 1) credentials_file = argv[1];
	json_object *jcredentials = json_object_from_file(credentials_file);
	assert(jcredentials);
	
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
	
	int64_t issued_at = time(NULL);
	rc = jwt->claims_add_iss(jwt, client_email);
	rc = jwt->claims_add_aud(jwt, token_uri);
	rc = jwt->claims_add_iat(jwt, issued_at);
	rc = jwt->claims_add_exp(jwt, issued_at + 3600);
	
	static const char *scopes = "https://www.googleapis.com/auth/cloud-platform";
	rc = jwt->claims_add(jwt, "scope", json_object_new_string(scopes));
	
	char *jwt_string = NULL;
	ssize_t cb_output = jwt->serialize(jwt, &jwt_string);
	
	printf("output(cb=%ld): %s\n", (long)cb_output, jwt_string);	
	static char grant_type_encoded[] = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";
	
	char post_fields[4096] = "";
	long cb_fields = snprintf(post_fields, sizeof(post_fields), 
		"grant_type=%s&assertion=%s",
		grant_type_encoded, 
		jwt_string);
	
	CURL *curl = curl_easy_init();
	assert(curl);
	curl_easy_setopt(curl, CURLOPT_URL, token_uri);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)cb_fields);
	//~ curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	
	CURLcode ret = curl_easy_perform(curl);
	if(ret) {
		fprintf(stderr, "ret: %d, err_msg: %s\n", ret, curl_easy_strerror(ret));
	}
	
	curl_easy_cleanup(curl);
	curl = NULL;
	
	free(jwt_string);
	jwt_string = NULL;
	
	json_object_put(jcredentials);
	jcredentials = NULL;
	
	jwt_json_c_cleanup(jwt);
	free(jwt);
	
	curl_global_cleanup();
	return 0;
}
#endif
