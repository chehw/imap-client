/*
 * bdb_context.c
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

#include <db.h>
#include <stdarg.h>
#include "mail_db.h"


#define print_flag_if_exists(fp, env_flags, flag) do { if(env_flags & flag) fprintf(fp, " "#flag); } while(0)
static void dump_env_flags(FILE *fp, u_int32_t env_flags)
{

	if(NULL == fp) fp = stderr;
	fprintf(fp, "== ENV_FLAGS:");
	print_flag_if_exists(fp, env_flags, DB_INIT_MPOOL);
	print_flag_if_exists(fp, env_flags, DB_INIT_CDB);
	print_flag_if_exists(fp, env_flags, DB_INIT_LOCK);
	print_flag_if_exists(fp, env_flags, DB_INIT_LOG);
	print_flag_if_exists(fp, env_flags, DB_INIT_REP);
	print_flag_if_exists(fp, env_flags, DB_CREATE);
	print_flag_if_exists(fp, env_flags, DB_RECOVER);
	print_flag_if_exists(fp, env_flags, DB_REGISTER);
	print_flag_if_exists(fp, env_flags, DB_THREAD);
	fprintf(fp, "\n");
}

DB_TXN *bdb_environment_new_transaction(struct bdb_environment *env, DB_TXN *parent_txn, uint32_t flags)
{
	assert(env && env->db_env);
	DB_ENV *db_env = env->db_env;
	DB_TXN *txn = NULL;
	
	int rc = 0;
	
	if(env->cdb_mode) rc = db_env->cdsgroup_begin(db_env, &txn);
	else rc = db_env->txn_begin(db_env, parent_txn, &txn, flags);
	
	if(rc) env->err(env, rc, "%s(err=%d)", __FUNCTION__, rc);  
	return txn;
}

static void bdb_environment_err(struct bdb_environment *env, int err_code, const char *fmt, ...)
{
	DB_ENV *db_env = env->db_env;
	va_list ap;
	va_start(ap, fmt);
	db_env->err(db_env, err_code, fmt, ap);
	va_end(ap);
	return;
}

struct bdb_environment *bdb_environment_init(struct bdb_environment *env, const char *db_home, int use_cdb_mode, void *user_data)
{
	if(NULL == env) env = calloc(1, sizeof(*env));
	assert(env);
	env->new_transaction = bdb_environment_new_transaction;
	env->err = bdb_environment_err;
	env->cdb_mode = use_cdb_mode;
	
	int rc = 0;
	u_int32_t env_flags = DB_INIT_MPOOL;
	/** set subsystem flags */
	if(use_cdb_mode) env_flags |= DB_INIT_CDB;
	else {
		env_flags |= DB_INIT_LOCK
			| DB_INIT_LOG
			| DB_INIT_REP	// DB_INIT_TXN
			| DB_INIT_TXN	// transaction subsystem
			| 0;
	}
	/** set other flags */
	env_flags |= DB_CREATE;
	if(!use_cdb_mode) {
		env_flags |= DB_RECOVER // Run normal recovery on this environment before opening it for normal use
			| DB_REGISTER // Check to see if recovery needs to be performed before opening the database environment. 
			| DB_THREAD
			| 0;
	}
	dump_env_flags(stderr, env_flags);
	env->flags = env_flags;
			
	DB_ENV *db_env = NULL;
	rc = db_env_create(&db_env, 0);
	assert(0 == rc);
	env->db_env = db_env;
	
	db_env->set_errpfx(db_env, "BDB::MAIL-DB");
	rc = db_env->open(db_env, db_home, env_flags, 0664);
	if(rc) {
		db_env->err(db_env, rc, "open env failed, err_code=%d. ", rc); 
		exit(1);
	}

	return env;
}
void bdb_environment_cleanup(struct bdb_environment *env)
{
	if(NULL == env) return;
	
	DB_ENV *db_env = env->db_env;
	env->db_env = NULL;
	
	if(db_env) db_env->close(db_env, 0);
	return;
}


static inline void clear_dbt(DBT *dbt)
{
	if(dbt->data && dbt->flags & DB_DBT_MALLOC) free(dbt->data);
	memset(dbt, 0, sizeof(*dbt));
}

static inline void bdb_clear_data(struct bdb_context *db)
{
	clear_dbt(db->pkey);
	clear_dbt(db->skey);
	clear_dbt(db->value);
}


static int bdb_open(struct bdb_context *db, const char *db_filename, const char *db_name, uint32_t db_type, uint32_t flags)
{
	assert(db && db->env && db->dbp);
	int rc = 0;
	DB *dbp = db->dbp;
	
	if(db_type && db_type != DB_BTREE) db_type = DB_HASH;
	db_type = DB_BTREE;
	
	rc = dbp->open(dbp, NULL, db_filename, db_name, db_type, DB_CREATE | flags, 0666);
	if(rc) {
		dbp->err(dbp, rc, "db_open(%s) failed.", db_name);
		return -1;
	}
	return rc;
}
static int bdb_close(struct bdb_context *db)
{
	if(NULL == db) return -1;
	db->iter_close(db);
	
	DB *dbp = db->dbp;
	db->dbp = NULL;
	if(dbp) return dbp->close(dbp, 0);
	return 0;
}

static int bdb_get(struct bdb_context *db, 
	DB_TXN *txn,
	const void *pkey, size_t cb_pkey, 
	const void *skey, size_t cb_skey, 
	uint32_t flags)
{
	assert(db && db->env && db->dbp);
	int rc = 0;
	DB *dbp = db->dbp;	
	bdb_clear_data(db);

	db->value->flags = DB_DBT_MALLOC;
	if(skey) {
		db->skey->data = (void *)skey;
		db->skey->size = cb_skey;
		
		db->pkey->flags = DB_DBT_MALLOC;
		rc = dbp->pget(dbp, txn, db->skey, db->pkey, db->value, flags);
	}else {
		db->pkey->data = (void *)pkey;
		db->pkey->size = cb_pkey;
		rc = dbp->get(dbp, txn, db->pkey, db->value, flags);
	}
	return rc;
}

static int bdb_put(struct bdb_context *db, 
	DB_TXN *txn,
	const void *key, size_t cb_key, 
	const void *value, size_t cb_value, 
	uint32_t flags)
{
	assert(db && db->env && db->dbp);
	int rc = 0;
	DB *dbp = db->dbp;	
	bdb_clear_data(db);
		
	db->pkey->data = (void *)key;
	db->pkey->size = cb_key;
	
	db->value->data = (void *)value;
	db->value->size = cb_value;
	
	rc = dbp->put(dbp, txn, db->pkey, db->value, flags);
	return rc;
}
static int bdb_iter_first(struct bdb_context *db)
{
	int rc = 0;
	DBC *iter = db->iter;
	if(NULL == iter) {
		rc = db->iter_new(db, NULL, 0);
		if(rc) return rc;
		iter = db->iter;
	}
	
	bdb_clear_data(db);
	
	if(db->is_secondary_db) {
		rc = iter->pget(iter, db->skey, db->pkey, db->value, DB_FIRST);
	}else {
		//~ db->pkey->flags = DB_DBT_MALLOC;
		//~ db->value->flags = DB_DBT_MALLOC;
		rc = iter->get(iter, db->pkey, db->value, DB_FIRST);
	}
	
	return rc;
}

static int bdb_iter_next(struct bdb_context *db, int dup)
{
	int rc = 0;
	DBC *iter = db->iter;
	if(NULL == iter) {
		rc = db->iter_new(db, NULL, 0);
		if(rc) return rc;
		iter = db->iter;
	}
	
	bdb_clear_data(db);
	
	
	if(db->is_secondary_db) {
		rc = iter->pget(iter, db->skey, db->pkey, db->value, dup?DB_NEXT_DUP:DB_NEXT);
		if(dup && rc == DB_NOTFOUND) rc = iter->pget(iter, db->skey, db->pkey, db->value, DB_NEXT);
		
	}else {
		//~ db->pkey->flags = DB_DBT_MALLOC;
		//~ db->value->flags = DB_DBT_MALLOC;
		rc = iter->get(iter, db->pkey, db->value, DB_NEXT);
	}
	
	return rc;
}
static int bdb_iter_prev(struct bdb_context *db, int dup)
{
	int rc = 0;
	DBC *iter = db->iter;
	if(NULL == iter) {
		rc = db->iter_new(db, NULL, 0);
		if(rc) return rc;
		iter = db->iter;
	}
	bdb_clear_data(db);
	
	if(db->is_secondary_db) {
		rc = iter->pget(iter, db->skey, db->pkey, db->value, dup?DB_PREV_DUP:DB_PREV);
		if(dup && rc == DB_NOTFOUND) rc = iter->pget(iter, db->skey, db->pkey, db->value, DB_PREV);
		
	}else {
		rc = iter->get(iter, db->pkey, db->value, DB_PREV);
	}
	
	return rc;
}
static int bdb_iter_last(struct bdb_context *db)
{
	int rc = 0;
	DBC *iter = db->iter;
	if(NULL == iter) {
		rc = db->iter_new(db, NULL, 0);
		if(rc) return rc;
		iter = db->iter;
	}
	bdb_clear_data(db);
	
	if(db->is_secondary_db) {
		rc = iter->pget(iter, db->skey, db->pkey, db->value, DB_LAST);
		
	}else {
		rc = iter->get(iter, db->pkey, db->value, DB_LAST);
	}
	
	return rc;
}

static int bdb_iter_new(struct bdb_context *db, DB_TXN *txn, uint32_t flags)
{
	assert(db && db->env && db->dbp);
	db->iter_close(db);
	
	int rc = 0;
	DB *dbp = db->dbp;
	rc = dbp->cursor(dbp, db->env->cdb_mode?NULL:txn, &db->iter, flags);
	return rc;
}

static int bdb_iter_close(struct bdb_context *db)
{
	int rc = 0;
	if(NULL == db) return -1;
	DBC *iter = db->iter;
	db->iter = NULL;
	if(iter) rc = iter->close(iter);
	return rc;
}

struct bdb_context *bdb_context_init(struct bdb_context *db, struct bdb_environment *env, void *user_data)
{
	if(NULL == db) db = calloc(1, sizeof(*db));
	assert(db);

	db->user_data = user_data;
	db->env = env;
	db->open = bdb_open;
	db->close = bdb_close;
	db->get = bdb_get;
	db->put = bdb_put;
	
	db->iter_new = bdb_iter_new;
	db->iter_close = bdb_iter_close;
	db->iter_first = bdb_iter_first;
	db->iter_next = bdb_iter_next;
	db->iter_prev = bdb_iter_prev;
	db->iter_last = bdb_iter_last;
	
	
	int rc = 0;
	DB *dbp = NULL;
	rc = db_create(&dbp, env->db_env, 0);
	if(rc) {
		env->err(env, rc, "db_create() failed.");
		bdb_context_cleanup(db);
		return NULL;
	}
	db->dbp = dbp;
	return db;
}

void bdb_context_cleanup(struct bdb_context *db)
{
	if(NULL == db) return;
	db->iter_close(db);
	
	if(db->dbp) {
		db->dbp->close(db->dbp, 0);
		db->dbp = NULL;
	}
	return;
}
