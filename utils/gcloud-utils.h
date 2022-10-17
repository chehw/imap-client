#ifndef GCLOUD_UTILS_H_
#define GCLOUD_UTILS_H_

#include <stdio.h>
#include <json-c/json.h>
#include "jwt_json-c.h"

#ifdef __cplusplus 
extern "C" {
#endif


struct gcloud_service_oauth2
{
	struct jwt_json_c jwt[1];
	json_object *jcredentials;
	void *user_data;
	const char *token_uri;
	const char *client_email;
	
	char *scopes;
	int (*load_credentials)(struct gcloud_service_oauth2 *oauth, json_object *jcredentials);
	int (*set_scope)(struct gcloud_service_oauth2 *oauth, const char *scopes);
	
	/**
	 * request_token()
	 * 	@return : jresult = {""access_token":"ya29.c.....", "expires_in":3599,"token_type":"Bearer"}
	 */
	int (*request_token)(struct gcloud_service_oauth2 *oauth, json_object **p_jresult);
	
	json_tokener *jtok;
	json_object *jresult;
	enum json_tokener_error jerr;
};

struct gcloud_service_oauth2 *gcloud_service_oauth2_init(
	struct gcloud_service_oauth2 *oauth, 
	json_object *jcredentials, void *user_data);
void gcloud_service_oauth2_cleanup(struct gcloud_service_oauth2 *oauth);

#ifdef __cplusplus 
}
#endif
#endif
