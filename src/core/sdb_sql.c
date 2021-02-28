/*
 * Copyright (c) 2019-2021 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * SDB -- Sqlite backend helpers:
 *
 * - Database schema initialization.
 * - Serialization and writing the encrypted database file.
 * - Basic SQL query wrapper.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sqlite3.h>

#include "rvault.h"
#include "storage.h"
#include "sdb.h"
#include "sys.h"

#if SQLITE_VERSION_NUMBER < 3023000
#error need sqlite 3.23 or newer
#endif

struct sdb {
	int		fd;
	sqlite3 *	db;
};

static int
sdb_init(sqlite3 *db)
{
	static const char *sdb_init_q =
	    "CREATE TABLE IF NOT EXISTS secrets ("
	    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  key VARCHAR UNIQUE,"
	    "  val VARCHAR,"
	    "  creation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
	    ");"
	    "CREATE INDEX IF NOT EXISTS secrets_key_idx ON secrets (key);"

	    "CREATE TABLE IF NOT EXISTS tiers ("
	    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  name VARCHAR UNIQUE,"
	    "  creation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
	    ");"

	    "CREATE TABLE IF NOT EXISTS tier_map ("
	    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  tier_id INTEGER REFERENCES tiers (id),"
	    "  key VARCHAR UNIQUE,"
	    "  creation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
	    ");"
	    "CREATE INDEX IF NOT EXISTS tier_map_key_idx ON tier_map (key);";

	app_log(LOG_DEBUG, "%s: initializing database", __func__);

	if (sqlite3_exec(db, sdb_init_q, NULL, NULL, NULL) != SQLITE_OK) {
		app_log(LOG_CRIT, "sqlite3_exec: %s", sqlite3_errmsg(db));
		return -1;
	}
	return 0;
}

sdb_t *
sdb_open(rvault_t *vault)
{
	sdb_t *sdb = NULL;
	sqlite3 *db = NULL;
	ssize_t len = 0, flen;
	sbuffer_t sbuf;
	char *fpath;
	int fd;

	memset(&sbuf, 0, sizeof(sbuffer_t));

	/*
	 * Open the SDB file, decrypt and load the data into a buffer.
	 */
	if (asprintf(&fpath, "%s/%s", vault->base_path, RVAULT_SDB_FILE) == -1) {
		return NULL;
	}
	fd = open(fpath, O_CREAT | O_RDWR, 0600);
	free(fpath);
	if (fd == -1) {
		return NULL;
	}
	if ((flen = fs_file_size(fd)) == -1) {
		goto out;
	}
	if (flen && (len = storage_read_data(vault, fd, flen, &sbuf)) == -1) {
		goto out;
	}

	/*
	 * Open an in-memory SQLite database and:
	 * a) Import the stored database,
	 * b) Initialize a fresh one.
	 */
	if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
		goto out;
	}
	if (sbuf.buf) {
		void *db_buf;

		app_log(LOG_DEBUG, "%s: loading the database", __func__);
		if ((db_buf = sqlite3_malloc64(len)) == NULL) {
			goto out;
		}
		memcpy(db_buf, sbuf.buf, len);
		sbuffer_free(&sbuf);

		/*
		 * Note: if sqlite3_deserialize() fails, it will free the
		 * database buffer, so no need to sqlite3_free().
		 */
		if (sqlite3_deserialize(db, "main", db_buf, len, len,
		    SQLITE_DESERIALIZE_FREEONCLOSE |
		    SQLITE_DESERIALIZE_RESIZEABLE) != SQLITE_OK) {
			app_log(LOG_CRIT, "%s: database loading failed %s",
			    __func__, sqlite3_errmsg(db));
			goto out;
		}
	} else if (sdb_init(db) == -1) {
		goto out;
	}

	if ((sdb = calloc(1, sizeof(sdb_t))) == NULL) {
		goto out;
	}
	sdb->db = db;
	sdb->fd = fd;

	sdb_query(sdb, NULL, NULL, "PRAGMA foreign_keys = ON", 0, NULL);
	return sdb;
out:
	if (sbuf.buf) {
		sbuffer_free(&sbuf);
	}
	if (db) {
		sqlite3_close(db);
	}
	close(fd);
	free(sdb);
	return NULL;
}

int
sdb_sync(rvault_t *vault, sdb_t *sdb)
{
	sqlite3_int64 len;
	unsigned char *buf;
	int ret;

	if ((buf = sqlite3_serialize(sdb->db, "main", &len, 0)) == NULL) {
		app_elog(LOG_DEBUG, "%s: sqlite3_serialize() failed", __func__);
		return -1;
	}
	ret = storage_write_data(vault, sdb->fd, buf, len);
	app_log(LOG_DEBUG, "%s: written %d", __func__, ret);
	sqlite3_free(buf);
	return ret;
}

void
sdb_close(sdb_t *sdb)
{
	sqlite3_close(sdb->db);
	close(sdb->fd);
	free(sdb);
}

///////////////////////////////////////////////////////////////////////////////

int
sdb_query(sdb_t *sdb, sdb_query_cb_t func, void *arg,
    const char *query, unsigned n, const char **params)
{
	sqlite3_stmt *stmt = NULL;
	int ret = -1;

	if (sqlite3_prepare_v2(sdb->db, query, -1, &stmt, NULL) != SQLITE_OK)
		goto out;
	for (unsigned i = 0; i < n; i++) {
		if (sqlite3_bind_text(stmt, i + 1, params[i], -1,
		    SQLITE_STATIC) != SQLITE_OK)
			goto out;
	}
	app_log(LOG_DEBUG, "%s: [%s]", __func__, sqlite3_sql(stmt));

	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		const unsigned ncols = sqlite3_column_count(stmt);

		for (unsigned i = 0; i < ncols; i++) {
			if (sqlite3_column_type(stmt, i) != SQLITE_TEXT) {
				continue;
			}
			func(arg, (const char *)sqlite3_column_text(stmt, i));
		}
	}
	ret = (ret == SQLITE_DONE) ? sqlite3_changes(sdb->db) : -1;
out:
	if (ret == -1) {
		app_log(LOG_ERR, "%s: %s", __func__, sqlite3_errmsg(sdb->db));
	}
	if (stmt) {
		sqlite3_finalize(stmt);
	}
	return ret;
}
