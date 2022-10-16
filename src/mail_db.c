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


static int open_databases(struct mail_db_context *mail_db)
{
	int rc = 0;
	static const char *db_filenames[] = {
		"raw_data.db", 
		"mails-rfc822.db",
		NULL
	};
	struct bdb_context *db = NULL;
	size_t num_dbs = sizeof(mail_db->dbs) / sizeof(mail_db->dbs[0]);
	for(size_t i = 0; i < num_dbs; ++i) {
		db = bdb_context_init(&mail_db->dbs[i], mail_db->env, mail_db);
		assert(db);
		
		const char *filename = db_filenames[i];
		if(NULL == filename) continue;
		rc = db->open(db, filename, NULL, DB_BTREE, 0);
		if(rc) {
			db_check_error(rc);
		}
	}
	
	DB *rawdata_dbp = mail_db->db_raw_data.dbp;
	DB *mails_dbp = mail_db->db_mails.dbp;
	assert(rawdata_dbp && mails_dbp);
	
	return rc;
}

static void close_databases(struct mail_db_context *mail_db)
{
	assert(mail_db);
	size_t num_dbs = sizeof(mail_db->dbs) / sizeof(mail_db->dbs[0]);
	for(size_t i = 0; i < num_dbs; ++i) {
		struct bdb_context *db = &mail_db->dbs[i];
		db->close(db);
		bdb_context_cleanup(db);
	}
	return;
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
	
	struct bdb_environment *env = bdb_environment_init(mail_db->env, db_home, use_cdb_mode, mail_db);
	assert(env);
	
	rc = open_databases(mail_db);
	assert(0 == rc);
	
	return mail_db;
}

void mail_db_context_cleanup(struct mail_db_context *mail_db)
{
	if(NULL == mail_db) return;
	close_databases(mail_db);
	bdb_environment_cleanup(mail_db->env);
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

#include "bdb_context.c"

static struct mail_db_context g_mail_db[1];
static struct app_context g_app[1];

static struct bdb_context *open_db(struct mail_db_context *mail_db, const char *db_filename, int type)
{
	int rc = 0;
	u_int32_t db_type = (type==0)?DB_BTREE:DB_HASH;
	
	struct bdb_environment *env = mail_db->env;
	assert(env);
	
	if(NULL == db_filename) db_filename = "test1.db";
	
	struct bdb_context *db = bdb_context_init(NULL, env, mail_db);
	assert(db);
	rc = db->open(db, db_filename, NULL, db_type, 0);
	assert(0 == rc);
	return db;
}

#include <pthread.h>
#include <endian.h>

#define NUM_THREADS (1)
struct worker_context 
{
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	struct bdb_context *db;

	int quit;
	int index;
};

static void * reader_thread(void *user_data)
{
	int rc = 0;
	struct worker_context *worker = user_data;
	assert(worker && worker->db);
	
	struct bdb_context *db = worker->db;
	
	pthread_mutex_lock(&worker->mutex);
	while(!worker->quit) {
		rc = pthread_cond_wait(&worker->cond, &worker->mutex);
		if(rc) {
			perror("pthread_cond_wait()");
			break;
		}
		if(worker->quit) break;
		
		printf("reader %d started ...\n", worker->index);
		
		rc = db->iter_new(db, NULL, 0);
		assert(0 == rc);
		
		rc = db->iter_first(db);
		
		while(0 == rc)
		{
			DBT *key = db->pkey;
			DBT *value = db->value;
			
			assert(key->data);
			if(NULL == key->data) {
				break;
			}
			assert(key->size == sizeof(uint64_t));
			uint64_t uid = *(uint64_t *)key->data;
			uid = be64toh(uid);
			printf("worker[%d]: uid: %lu, data(cb=%ld): %s\n", 
				worker->index, 
				(unsigned long)uid, 
				(long)value->size, 
				(char *)value->data);
				
			rc = db->iter_next(db, 0);
		}
		if(rc != DB_NOTFOUND) {
			db->dbp->err(db->dbp, rc, "cursorp->get() failed\n");
		}
		
		rc = db->iter_close(db);
	}
	
	pthread_mutex_unlock(&worker->mutex);
	pthread_exit((void *)(intptr_t)rc);
}

int main(int argc, char **argv)
{
	struct mail_db_context *mail_db = mail_db_context_init(g_mail_db, NULL, (argc == 1), g_app);
	assert(mail_db && mail_db->env);
	int rc = 0;
	
	
	struct bdb_context *db = open_db(mail_db, "test1.db", 0);
	assert(db);
	
	printf("db: %p\n", db);	
	pthread_t th[NUM_THREADS];
	
	struct worker_context workers[NUM_THREADS];
	memset(workers, 0, sizeof(workers));
	
	for(int i = 0; i < NUM_THREADS; ++i) {
		workers[i].index = i;
		workers[i].db = db;
		workers[i].quit = 0;
		
		rc = pthread_cond_init(&workers[i].cond, NULL);
		assert(0 == rc);
		rc = pthread_mutex_init(&workers[i].mutex, NULL);
		assert(0 == rc);
		rc = pthread_create(&th[i], NULL, reader_thread, &workers[i]);
	}
	
	const struct timespec interval = {
		.tv_sec = 0,
		.tv_nsec = 10 * 1000, // 10 us
	};
	nanosleep(&interval, NULL);
	
	
	printf("insert data ...\n");
	// insert test data
	for(int i = 0; i < 10; ++i) {
		uint64_t uid = 0;
		char text[100] = "";
		ssize_t cb_text = 0;
		
		cb_text = snprintf(text, sizeof(text), "text %d", i);
		uid = htobe64(i + 1);
		
		printf("put %d ...\n", i);
		rc = db->put(db, NULL, &uid, sizeof(uid), text, cb_text + 1, DB_AUTO_COMMIT);
		if(rc) {
			if(rc != DB_KEYEXIST) {
				db->dbp->err(db->dbp, rc, "insert item %d failed\n", i);
				exit(1);
			}else {
				printf(" ==> dup\n");
			}
		}
	}
	
	printf("reading ...\n");
	// read records
	for(int i = 0; i < NUM_THREADS; ++i) {
		pthread_mutex_lock(&workers[i].mutex);
		pthread_cond_signal(&workers[i].cond);
		pthread_mutex_unlock(&workers[i].mutex);
		
	}
	
	nanosleep(&interval, 0);
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
	
	
	db->close(db);
	free(db);

	mail_db_context_cleanup(mail_db);
	return 0;
}
#endif

