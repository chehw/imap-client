#ifndef JWT_JSON_C_H_
#define JWT_JSON_C_H_

#include <stdio.h>
#include <json-c/json.h>

#ifdef __cplusplus 
extern "C" {
#endif

enum jwt_algorithm
{
	jwt_algorithm_none = 0,
	jwt_algorithm_hs256, 
	jwt_algorithm_hs384, 
	jwt_algorithm_hs512,
	
	jwt_algorithm_rs256,
	jwt_algorithm_rs384,
	jwt_algorithm_rs512,

	jwt_algorithm_es256,
	jwt_algorithm_es384,
	jwt_algorithm_es512,
	
	jwt_algorithms_count
};

struct jwt_private;
struct jwt_json_c
{
	json_object *jobject;
	void *user_data;
	struct jwt_private *priv;
	
	int (*set_alg_string)(struct jwt_json_c *jwt, const char *algorithm);
	int (*set_alg)(struct jwt_json_c *jwt, enum jwt_algorithm alg);
	int (*set_privkey)(struct jwt_json_c *jwt, 
		const unsigned char *privkey, size_t cb_key, 
		int use_der ///< 0: PEM, 1: DER
	);
	
	int (*claims_add)(struct jwt_json_c *jwt, const char *key, json_object *jvalue);
	int (*claims_remove)(struct jwt_json_c *jwt, const char *key);
	ssize_t (*serialize)(struct jwt_json_c *jwt, char **p_output);
};
struct jwt_json_c * jwt_json_c_init(struct jwt_json_c *jwt, void *user_data);
void jwt_json_c_cleanup(struct jwt_json_c *jwt);


#ifdef __cplusplus 
}
#endif
#endif
