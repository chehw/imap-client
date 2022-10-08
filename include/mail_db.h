#ifndef IMAP_CLIENT_MAIL_DB_H_
#define IMAP_CLIENT_MAIL_DB_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <db.h>

struct app_context;
struct mail_db_context
{
	struct app_context *app;
	void *priv;
	DB_ENV *db_env;
	int cdb_mode;
	
	DB *dbp_raw_data;	      // { uid, struct mail_rfc822_raw_data }
	DB *dbp_mails;            // { uid, { header, body } }
	DB *dbp_fulltext_search;  // { uid, key:words }
	DB *dbp_json_results;     // { uid, jsonstr }
	
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
