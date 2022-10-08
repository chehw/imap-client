/*
 * mail-db.c
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
#include <stdint.h>
#include <endian.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "app.h"
#include "mail_db.h"

#define DEFAULT_DB_HOME "db"
#define DEFAULT_RAW_DATA_DB_NAME "mail_rfc822.db"

static int create_dir(const char *dir_name)
{
	int rc = 0;
	rc = mkdir(dir_name, 0775);
	if(-1 == rc) {
		if(errno != EEXIST) goto label_err;
		struct stat st[1];
		memset(st, 0, sizeof(st));
		int rc = stat(dir_name, st);
		if(-1 == rc) goto label_err;
		
		if(!S_ISDIR(st->st_mode)) {
			errno = ENOTDIR;
			goto label_err;
		}
		return 1;
	}
	return 0;
	
label_err:
	perror(dir_name);
	return rc;
}

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

static int db_txn_begin(struct mail_db_context *db, DB_TXN *parent_txn, DB_TXN **p_txn, uint32_t flags)
{
	DB_ENV *env = db->db_env;
	assert(env);
	if(db->cdb_mode) return env->cdsgroup_begin(env, p_txn);
	return env->txn_begin(env, parent_txn, p_txn, flags);
}

struct mail_db_context *mail_db_context_init(struct mail_db_context *mail_db, 
	const char *db_home, 
	int use_cdb_mode, // Concurrent Data Store mode (multiple reader / single writer)
	struct app_context *app)
{
	int rc = 0;
	if(NULL == db_home) db_home = getenv("DB_HOME");
	if(NULL == db_home) db_home = DEFAULT_DB_HOME;
	fprintf(stderr, "== DB_HOME: %s\n", db_home);
	
	// check dir
	rc = create_dir(db_home);
	printf("create_dir(%s) = %d\n", db_home, rc);
	if(rc < 0) {
		fprintf(stderr, "check dir failed, rc = %d\n", rc);
		return NULL;
	}
	
		
	if(NULL == mail_db) mail_db = calloc(1, sizeof(*mail_db));
	assert(mail_db);
	mail_db->app = app;
	mail_db->cdb_mode = use_cdb_mode;
	mail_db->txn_begin = db_txn_begin;
	
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
			
			
	DB_ENV *db_env = NULL;
	rc = db_env_create(&db_env, 0);
	assert(0 == rc);
	mail_db->db_env = db_env;
	
	db_env->set_errpfx(db_env, "MAIL-DB");
	rc = db_env->open(db_env, db_home, env_flags, 0664);
	if(rc) {
		db_env->err(db_env, rc, "open env failed, err_code=%d. ", rc); 
		exit(1);
	}
	
	return mail_db;
}

void mail_db_context_cleanup(struct mail_db_context *mail_db)
{
	///< @todo
}



struct mail_rfc822_raw_data *mail_rfc822_raw_data_new(size_t length, const char *data)
{
	struct mail_rfc822_raw_data *raw_data = NULL;
	ssize_t size = sizeof(*raw_data) + length + 1;
	raw_data = malloc(size);
	assert(raw_data);
	raw_data->data[length] = '\0';
	
	if(length && data) {
		memcpy(raw_data->data, data, length);
	}
	return raw_data;
}

struct mail_db_record * mail_db_record_new( 
	uint64_t uid, 
	size_t length,
	const char *data)
{
	struct mail_db_record *record = calloc(1, sizeof(*record));
	assert(record);
	record->uid = uid;
	record->raw_data = mail_rfc822_raw_data_new(length, data);
	return record;
}


void db_check_error(int rc) {
	if(rc) {
		fprintf(stderr, "%s\n", db_strerror(rc));
		exit(rc);
	}
}


#if defined(TEST_MAIL_DB_) && defined(_STAND_ALONE)
static struct mail_db_context g_mail_db[1];
static struct app_context g_app[1];

static DB *open_db(struct mail_db_context *mail_db, const char *db_name, int type)
{
	int rc = 0;
	u_int32_t db_type = (type==0)?DB_BTREE:DB_HASH;
	DB_ENV *env = mail_db->db_env;
	assert(env);
	
	DB *dbp = NULL;
	rc = db_create(&dbp, env, 0);
	if(rc) {
		env->err(env, rc, "%s() failed. rc=%d\n", "db_create", rc);
		return NULL;
	}
	
	DB_TXN *txn = NULL;
	rc = mail_db->txn_begin(mail_db, NULL, &txn, 0);
	if(rc) {
		env->err(env, rc, "%s() failed, rc=%d.\n", "txn_begin", rc);
		exit(1);
	}
	
	rc = dbp->open(dbp, txn, "test1.db", "raw_data", db_type, DB_CREATE, 0664);
	if(rc) {
		dbp->err(dbp, rc, "open db failed\n");
		txn->abort(txn);
		
		dbp->close(dbp, 0);
		return NULL;
	}
	
	rc = txn->commit(txn, 0);
	if(rc) {
		dbp->err(dbp, rc, "open db: commit txn failed\n");
		dbp->close(dbp, 0);
		return NULL;
	}

	return dbp;
}

#include <pthread.h>
#include <endian.h>

#define NUM_THREADS (4)
struct worker_context 
{
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	DB *dbp;

	int quit;
	int index;
};

static void * reader_thread(void *user_data)
{
	int rc = 0;
	struct worker_context *worker = user_data;
	assert(worker && worker->dbp);
	
	DB *dbp = worker->dbp;
	
	pthread_mutex_lock(&worker->mutex);
	while(!worker->quit) {
		rc = pthread_cond_wait(&worker->cond, &worker->mutex);
		if(rc) {
			perror("pthread_cond_wait()");
			break;
		}
		if(worker->quit) break;
		
		// dump records
		DBT key, value;
		memset(&key, 0, sizeof(key));
		memset(&value, 0, sizeof(value));
		
		uint64_t uid;
		key.data = &uid;
		key.ulen = sizeof(uid);
		key.flags = DB_DBT_USERMEM;
		
		DBC *cursorp = NULL;
		rc = dbp->cursor(dbp, NULL, &cursorp, 0);
		assert(0 == rc);
		
		rc = cursorp->get(cursorp, &key, &value, DB_FIRST);
		while(0 == rc) {
			uid = be64toh(uid);
			printf("worker[%d]: uid: %lu, data(cb=%ld): %s\n", 
				worker->index, 
				(unsigned long)uid, 
				(long)value.size, 
				(char *)value.data);
			
			rc = cursorp->get(cursorp, &key, &value, DB_NEXT);
		}
		if(rc != DB_NOTFOUND) {
			dbp->err(dbp, rc, "cursorp->get() failed\n");
		}
	}
	
	pthread_mutex_unlock(&worker->mutex);
	pthread_exit((void *)(intptr_t)rc);
}

int main(int argc, char **argv)
{
	struct mail_db_context *mail_db = mail_db_context_init(g_mail_db, NULL, (argc == 1), g_app);
	assert(mail_db);
	int rc = 0;
	DB_ENV *env = mail_db->db_env;
	assert(env);
	
	DB *dbp = open_db(mail_db, "test1.db", 0);
	assert(dbp);
	
	
	pthread_t th[NUM_THREADS];
	
	struct worker_context workers[NUM_THREADS];
	memset(workers, 0, sizeof(workers));
	
	for(int i = 0; i < NUM_THREADS; ++i) {
		workers[i].index = i;
		workers[i].dbp = dbp;
		
		rc = pthread_cond_init(&workers[i].cond, NULL);
		assert(0 == rc);
		rc = pthread_mutex_init(&workers[i].mutex, NULL);
		assert(0 == rc);

		rc = pthread_create(&th[i], NULL, reader_thread, &workers[i]);
	}
	
	// insert test data
	for(int i = 0; i < 10; ++i) {
		uint64_t uid = 0;
		char text[100] = "";
		ssize_t cb_text = 0;
		
		cb_text = snprintf(text, sizeof(text), "text %d", i);
		uid = htobe64(i + 1);
		
		DBT key, value;
		memset(&key, 0, sizeof(key));
		memset(&value, 0, sizeof(value));
		
		key.data = &uid;
		key.size = sizeof(uid);
		key.ulen = sizeof(uid);
		key.flags = DB_DBT_USERMEM;
		
		value.data = text;
		value.size = cb_text + 1;
		
		rc = dbp->put(dbp, NULL, &key, &value, DB_AUTO_COMMIT);
		if(rc) {
			if(rc != DB_KEYEXIST) {
				dbp->err(dbp, rc, "insert item %d failed\n", i);
				exit(1);
			}
		}
	}
	
	// read records
	for(int i = 0; i < NUM_THREADS; ++i) {
		pthread_mutex_lock(&workers[i].mutex);
		pthread_cond_signal(&workers[i].cond);
		pthread_mutex_unlock(&workers[i].mutex);
		
	}
	
	// cleanup
	for(int i = 0; i < NUM_THREADS; ++i) {
		pthread_mutex_lock(&workers[i].mutex);
		workers[i].quit = 1;
		pthread_cond_signal(&workers[i].cond);
		pthread_mutex_unlock(&workers[i].mutex);
		
	}
	
	
	for(int i = 0; i < NUM_THREADS; ++i) {
		void *exit_code = NULL;
		rc = pthread_join(th[i], &exit_code);
		printf("thread %d exited with code %p, rc = %d\n", i, exit_code, rc);
		
	}
	

	mail_db_context_cleanup(mail_db);
	return 0;
}
#endif

