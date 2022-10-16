#ifndef IMAP_CLIENT_MAIL_DB_H_
#define IMAP_CLIENT_MAIL_DB_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <db.h>
void db_check_error(int rc);

struct bdb_environment
{
	DB_ENV *db_env;
	void *user_data;
	char *db_home;
	int cdb_mode;
	u_int32_t flags;
	
	DB_TXN * (*new_transaction)(struct bdb_environment *env, DB_TXN *parent_txn, uint32_t flags);
	void (*err)(struct bdb_environment *env, int err_code, const char *fmt, ...);
};
struct bdb_environment *bdb_environment_init(struct bdb_environment *env, const char *db_home, int cdb_mode, void *user_data);
void bdb_environment_cleanup(struct bdb_environment *env);

struct bdb_context
{
	DB *dbp;
	struct bdb_environment *env;
	char *db_filename; // filename
	char *name; // logical database name
	void *user_data;
	int is_secondary_db;
	
	int (*open)(struct bdb_context *db, const char *db_file, const char *db_name, uint32_t db_type, uint32_t flags);
	int (*close)(struct bdb_context *db);
	int (*associate)(struct bdb_context *db, 
		struct bdb_context *primary_db,
		int (*callback)(DB *sdb, const DBT *key, const DBT *data, DBT *result), 
		uint32_t flags);

	int (*foreign)(struct bdb_context *db, struct bdb_context *secondary, 
		int (*callback)(DB *sdb, const DBT *key, const DBT *data, const DBT *foreignkey, int *changed),
		uint32_t flags);


	DBT pkey[1];	// primary key
	DBT skey[1];	// secondary key
	DBT value[1];
		
	DBC *iter;
	DB_TXN *iter_txn;
	int (*iter_new)(struct bdb_context *db, DB_TXN *txn, uint32_t flags);
	int (*iter_close)(struct bdb_context *db);
	
	int (*iter_first)(struct bdb_context *db);
	int (*iter_next)(struct bdb_context *db, int has_dup);
	int (*iter_prev)(struct bdb_context *db, int has_dup);
	int (*iter_last)(struct bdb_context *db);
	int (*iter_find)(struct bdb_context *db, 
		const void *pkey, size_t cb_pkey, 
		const void *s_key, size_t cb_skey, // nullable
		uint32_t flags);
	int (*iter_put)(struct bdb_context *db, 
		const void *key, size_t cb_key, const void *value, size_t cb_value, 
		uint32_t flags);
	
	int (*get)(struct bdb_context *db, DB_TXN *txn,
		const void *pkey, size_t cb_pkey, 
		const void *s_key, size_t cb_skey, // nullable
		uint32_t flags);
	int (*put)(struct bdb_context *db, DB_TXN *txn,
		const void *key, size_t cb_key, const void *value, size_t cb_value, 
		uint32_t flags);
};


struct bdb_context *bdb_context_init(struct bdb_context *db, struct bdb_environment *env, void *user_data);
void bdb_context_cleanup(struct bdb_context *db);

struct app_context;
struct mail_db_context
{
	struct bdb_environment env[1];
	struct app_context *app;
	void *priv;
		
	union {
		struct bdb_context dbs[4];
		struct {
			struct bdb_context db_raw_data;
			struct bdb_context db_mails;
			struct bdb_context db_fulltext;
			struct bdb_context db_json_results;
		};
	};
	
	//~ DB *dbp_raw_data;	      // { uid, struct mail_rfc822_raw_data }
	//~ DB *dbp_mails;            // { uid, { header, body } }
	//~ DB *dbp_fulltext_search;  // { uid, key:words }
	//~ DB *dbp_json_results;     // { uid, jsonstr }
	
	int (*txn_begin)(struct mail_db_context *db, DB_TXN *parent_txn, DB_TXN **p_txn, uint32_t flags);
};

struct mail_db_context *mail_db_context_init(struct mail_db_context *mail_db, 
	const char *db_home, int use_cdb_mode,
	struct app_context *app);
void mail_db_context_cleanup(struct mail_db_context *mail_db);

struct mail_rfc822_raw_data
{
	uint64_t length;
	char data[0];
}__attribute__((packed));
struct mail_rfc822_raw_data *mail_rfc822_raw_data_new(size_t length, const char *data);
#define mail_rfc822_raw_data_free(raw_data) free(raw_data)

struct mail_db_record
{
	uint64_t uid;
	struct mail_rfc822_raw_data *raw_data;
}__attribute__((packed));

struct mail_db_record *mail_db_record_new(uint64_t uid, size_t length, const char *data);
void mail_db_record_free(struct mail_db_record *record);







#ifdef __cplusplus
}
#endif

#endif
