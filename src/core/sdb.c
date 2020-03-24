/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * Secrets database (SDB) to operate key-value pairs of secrets,
 * such as passwords.
 *
 * - Secrets are stored in an encrypted Sqlite3 database.
 * - CLI with auto-complete using editline (libedit).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>

#include <sqlite3.h>
#include <editline/readline.h>

#include "rvault.h"
#include "storage.h"
#include "cli.h"
#include "sys.h"

#if SQLITE_VERSION_NUMBER < 3023000
#error need sqlite 3.23 or newer
#endif

///////////////////////////////////////////////////////////////////////////////

typedef struct {
	int		fd;
	sqlite3 *	db;
} sdb_t;

static sdb_t *sdb_readline_ctx = NULL; // XXX

static int
sdb_init(sqlite3 *db)
{
	static const char *sdb_init_q =
	    "CREATE TABLE IF NOT EXISTS sdb ("
	    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
	    "  key VARCHAR UNIQUE,"
	    "  val VARCHAR UNIQUE"
	    ");"
	    "CREATE INDEX IF NOT EXISTS sdb_key_idx ON sdb (key);";

	app_log(LOG_DEBUG, "%s: initializing database", __func__);

	if (sqlite3_exec(db, sdb_init_q, NULL, NULL, NULL) != SQLITE_OK) {
		app_log(LOG_CRIT, "sqlite3_exec: %s", sqlite3_errmsg(db));
		return -1;
	}
	return 0;
}

static sdb_t *
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

static int
sdb_sync(rvault_t *vault, sdb_t *sdb)
{
	sqlite3_int64 len;
	unsigned char *buf;
	int ret;

	if ((buf = sqlite3_serialize(sdb->db, "main", &len, 0)) == NULL) {
		return -1;
	}
	ret = storage_write_data(vault, sdb->fd, buf, len);
	sqlite3_free(buf);
	return ret;
}

static void
sdb_close(sdb_t *sdb)
{
	sqlite3_close(sdb->db);
	close(sdb->fd);
	free(sdb);
}

///////////////////////////////////////////////////////////////////////////////

static int
sdb_query(sdb_t *sdb, const char *query, const char *k, const char *v, FILE *fp)
{
	sqlite3_stmt *stmt = NULL;
	int ret = -1;

	if (sqlite3_prepare_v2(sdb->db, query, -1, &stmt, NULL) != SQLITE_OK)
		goto out;
	if (k && sqlite3_bind_text(stmt, 1, k, -1, SQLITE_STATIC) != SQLITE_OK)
		goto out;
	if (v && sqlite3_bind_text(stmt, 2, v, -1, SQLITE_STATIC) != SQLITE_OK)
		goto out;

	while (sqlite3_step(stmt) != SQLITE_DONE) {
		const unsigned ncols = sqlite3_column_count(stmt);

		for (unsigned i = 0; i < ncols; i++) {
			if (sqlite3_column_type(stmt, i) != SQLITE_TEXT) {
				continue;
			}
			fprintf(fp, "%s\n", sqlite3_column_text(stmt, i));
		}
	}
	ret = 0;
out:
	if (ret) {
		app_log(LOG_ERR, "%s: %s", __func__, sqlite3_errmsg(sdb->db));
	}
	if (stmt) {
		sqlite3_finalize(stmt);
	}
	return ret;
}

///////////////////////////////////////////////////////////////////////////////

static const struct {
	const char *	cmd;
	unsigned	params;
	const char *	query;
} sdb_cmds[] = {
	{ "LS",  0, "SELECT key FROM sdb ORDER BY key" },
	{ "GET", 1, "SELECT val FROM sdb WHERE key = ?" },
	{ "SET", 2, "INSERT OR REPLACE INTO sdb (key, val) VALUES (?, ?)" },
	{ "DEL", 1, "DELETE FROM sdb WHERE key = ?" },
};

static int
sdb_exec_cmd(sdb_t *sdb, char *line)
{
	char *tokens[2] = { NULL, NULL };
	unsigned n;

	if ((n = str_tokenize(line, tokens, __arraycount(tokens))) < 1) {
		return -1;
	}
	for (unsigned i = 0; i < __arraycount(sdb_cmds); i++) {
		char *key, *secret;
		int ret;

		if (strcasecmp(sdb_cmds[i].cmd, tokens[0]) != 0) {
			continue;
		}

		key = (sdb_cmds[i].params >= 1) ? tokens[1] : NULL;
		secret = (sdb_cmds[i].params >= 2) ? getpass("Secret:") : NULL;
		ret = sdb_query(sdb, sdb_cmds[i].query, key, secret, stdout);

		if (secret) {
			crypto_memzero(secret, strlen(secret));
			secret = NULL; // diagnostic
		}
		return ret;
	}
	return -1;
}

static char *
cmd_generator(const char *text, const int state)
{
	static unsigned cmd_iter_idx;
	static size_t text_len;

	if (!state) {
		cmd_iter_idx = 0;
		text_len = strlen(text);
	}
	while (cmd_iter_idx < __arraycount(sdb_cmds)) {
		const char *cmd = sdb_cmds[cmd_iter_idx++].cmd;
		if (strncasecmp(cmd, text, text_len) == 0) {
			return strdup(cmd);
		}
	}
	cmd_iter_idx = 0;
	return NULL;
}

static char *
keyname_generator(const char *text, const int state)
{
	static FILE *fp = NULL;
	static char *buf = NULL;
	static size_t len = 0;
	char keyname[1024];

	if (!state) {
		const char *query = "SELECT key FROM sdb WHERE key LIKE ?";
		char *like = NULL;

		if ((fp = open_memstream(&buf, &len)) == NULL) {
			return NULL;
		}
		if (asprintf(&like, "%s%%", text) == -1) {
			fclose(fp);
			return NULL;
		}
		sdb_query(sdb_readline_ctx, query, like, NULL, fp);
		fclose(fp);
		free(like);

		if ((fp = fmemopen(buf, len, "r")) == NULL) {
			free(buf);
			return NULL;
		}
	}
	if (fgets(keyname, sizeof(keyname) - 1, fp) && keyname[0]) {
		return strndup(keyname, strlen(keyname) - 1);
	}
	fclose(fp);
	free(buf);
	buf = NULL;
	return NULL;
}

static char **
cmd_completion(const char *text, const int start, const int end __unused)
{
	/* Note: disable default of path completion. */
	rl_attempted_completion_over = 1;
	return rl_completion_matches(text,
	    start ? keyname_generator : cmd_generator);
}

static void
sdb_usage(void)
{
	printf(
	    "Invalid command.\n"
	    "\n"
	    "Usage:\n"
	    "  LS		list secrets\n"
	    "  GET <name>	get the secret value\n"
	    "  SET <name>	set the secret value\n"
	    "  DEL <name>	delete the secret\n"
	    "\n"
	    "Note: names must not have white spaces.\n"
	);
}

int
sdb_cli(const char *datapath, const char *server, int argc, char **argv)
{
	rvault_t *vault;
	sdb_t *sdb;
	char *line;

	vault = open_vault(datapath, server);
	ASSERT(vault != NULL);

	if ((sdb = sdb_open(vault)) == NULL) {
		app_elog(LOG_CRIT, APP_NAME": could not open the database");
		rvault_close(vault);
		return -1;
	}
	rl_attempted_completion_function = cmd_completion;
	sdb_readline_ctx = sdb;
	while ((line = readline("> ")) != NULL) {
		if (sdb_exec_cmd(sdb, line) == 0) {
			sdb_sync(vault, sdb);
		} else {
			sdb_usage();
		}
		crypto_memzero(line, strlen(line));
		free(line);
	}
	sdb_close(sdb);
	rvault_close(vault);

	(void)argc; (void)argv;
	return -1;
}
