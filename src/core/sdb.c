/*
 * Copyright (c) 2019-2021 Mindaugas Rasiukevicius <rmind at noxt eu>
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
#include <unistd.h>
#include <signal.h>

#include <editline/readline.h>

#include "rvault.h"
#include "sdb.h"
#include "cli.h"
#include "utils.h"

static unsigned		sdb_inactivity_time = 10 * 60;
static sdb_t *		sdb_readline_ctx = NULL; // XXX

///////////////////////////////////////////////////////////////////////////////

static void
sdb_sql_print(void *arg, const char *val)
{
	FILE *fp = arg;
	fprintf(fp, "%s\n", val);
}

#define	SDB_NEED_SYNC		0x1	// change made; need to sync DB
#define	SDB_ASK_SECRET		0x2	// ask to input the secret
#define	SDB_CHECK_RESULT	0x4	// check that rows were updated
#define	SDB_TIERS_GC		0x8	// clean up the tiers

static const struct sdb_cmd {
	const char *	cmd;
	unsigned	params;
	unsigned	flags;
	const char *	query;
	const char *	subquery;
} sdb_cmds[] = {
	{
		"LS", 0, 0x0,
		"SELECT key FROM secrets ORDER BY key",
		NULL
	},
	{
		"GET", 1, 0x0,
		"SELECT val FROM secrets WHERE key = ?",
		NULL
	},
	{
		"SET", 1, SDB_NEED_SYNC | SDB_ASK_SECRET,
		"INSERT OR REPLACE INTO secrets (key, val) VALUES (?, ?)",
		NULL
	},
	{
		"DEL", 1, SDB_NEED_SYNC,
		"DELETE FROM secrets WHERE key = ?",
		NULL,
	},
	{
		"TIERS", 0, 0x0,
		"SELECT name FROM tiers ORDER BY name",
		"SELECT key FROM tier_map WHERE tier_id = "
		    "(SELECT id FROM tiers WHERE name = ?)"
		    "ORDER BY lower(key)",
	},
	{
		"NEWTIER", 1, SDB_NEED_SYNC,
		"INSERT OR IGNORE INTO tiers (name) VALUES (?)",
		NULL
	},
	{
		"LINK", 2, SDB_NEED_SYNC | SDB_CHECK_RESULT,
		"INSERT OR REPLACE INTO tier_map (key, tier_id) "
		    "SELECT ?, id from tiers where name = ?",
		NULL
	},
	{
		"UNLINK", 1, SDB_NEED_SYNC | SDB_CHECK_RESULT | SDB_TIERS_GC,
		"DELETE FROM tier_map WHERE key = ?",
		NULL
	},
};

static void
sdb_cmd_handle(void *arg, const char *val)
{
	const struct sdb_cmd *cmdcfg = arg;

	fprintf(stdout, "%*s%s\n", arg ? 0 : 2, "", val);
	if (cmdcfg && cmdcfg->subquery) {
		sdb_query(sdb_readline_ctx, sdb_cmd_handle, NULL,
		    cmdcfg->subquery, 1, (const char *[]){ val });
	}
}

static void
sdb_exec_cmd(sdb_t *sdb, const struct sdb_cmd *cmdcfg,
    unsigned n, const char **params)
{
	const unsigned flags = cmdcfg->flags;
	int ret;

	ret = sdb_query(sdb, sdb_cmd_handle, __UNCONST(cmdcfg),
	    cmdcfg->query, n, params);

	if ((flags & SDB_CHECK_RESULT) != 0 && ret == 0) {
		const char *last_param = params[n - 1];
		fprintf(stderr, "Error: '%s' not found\n", last_param);
	}
	if ((flags & SDB_TIERS_GC) != 0 && ret > 0) {
		sdb_query(sdb, NULL, NULL,
		    "DELETE FROM tiers WHERE id NOT IN "
		    "(SELECT DISTINCT tier_id FROM tier_map);",
		    0, NULL);
	}
}

static int
sdb_process_cmd(sdb_t *sdb, char *line)
{
	char *tokens[] = { NULL, NULL, NULL };
	unsigned n;

	if ((n = str_tokenize(line, tokens, __arraycount(tokens))) < 1) {
		return -1;
	}
	n--; // exclude the command token

	for (unsigned i = 0; i < __arraycount(sdb_cmds); i++) {
		const struct sdb_cmd *cmdcfg = &sdb_cmds[i];
		unsigned paramcount = cmdcfg->params;
		char *secret = NULL;

		if (strcasecmp(cmdcfg->cmd, tokens[0]) != 0) {
			continue;
		}
		if (n < cmdcfg->params) {
			continue;
		}
		if (cmdcfg->flags & SDB_ASK_SECRET) {
			secret = getpass("Secret:");
			tokens[2] = secret;
			paramcount++;
		}
		sdb_exec_cmd(sdb, cmdcfg, paramcount, (const char *[]){
		    tokens[1], tokens[2]
		});

		if (secret) {
			crypto_memzero(secret, strlen(secret));
			secret = NULL; // diagnostic
		}
		return cmdcfg->flags;
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
		const char *query =
		    "SELECT key FROM secrets WHERE key LIKE ? ORDER BY key";
		char *like = NULL;

		if ((fp = open_memstream(&buf, &len)) == NULL) {
			return NULL;
		}
		if (asprintf(&like, "%s%%", text) == -1) {
			fclose(fp);
			return NULL;
		}
		sdb_query(sdb_readline_ctx, sdb_sql_print, fp,
		    query, 1, (const char *[]){ like });
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
	    "  LS                    list secrets\n"
	    "  GET <name>            get the secret value\n"
	    "  SET <name>            set the secret value\n"
	    "  DEL <name>            delete the secret\n"
	    "\n"
	    "  TIERS                 list tiers\n"
	    "  NEWTIER <name>        create a new tier\n"
	    "  LINK <name> <tier>    associate a name with a tier\n"
	    "  UNLINK <name>         remove a name associated with a tier\n"
	    "\n"
	    "Notes:\n"
	    "- Names must not have white spaces.\n"
	    "- Secrets and tier links have separate name spaces.\n"
	    "- Tier gets deleted on the removal of last link.\n"
	);
}


static void
sdb_cli_timeout(int sig __unused)
{
	const char msg[] = "\n"APP_NAME": user inactivity timeout; exiting.\n";
	write(STDOUT_FILENO, msg, sizeof(msg));
	kill(0, SIGINT);
}

int
sdb_cli(const char *datapath, const char *server, int argc, char **argv)
{
	rvault_t *vault;
	sdb_t *sdb;
	char *v, *line;
	int ret;

	vault = open_vault(datapath, server);
	ASSERT(vault != NULL);

	if ((sdb = sdb_open(vault)) == NULL) {
		app_elog(LOG_CRIT, APP_NAME": could not open the database");
		rvault_close(vault);
		return -1;
	}

	sdb_readline_ctx = sdb;
	rl_attempted_completion_function = cmd_completion;
	// rl_event_hook is not yet supported everywhere

	signal(SIGALRM, sdb_cli_timeout);
	if ((v = getenv("RVAULT_CLI_TIMEOUT")) != NULL) {
		sdb_inactivity_time = (unsigned)atoi(v);
	}
	alarm(sdb_inactivity_time);

	while ((line = readline("> ")) != NULL) {
		alarm(sdb_inactivity_time);
		if ((ret = sdb_process_cmd(sdb, line)) == -1) {
			sdb_usage();
			continue;
		}
		if ((ret & SDB_NEED_SYNC) != 0 && sdb_sync(vault, sdb) == -1) {
			app_elog(LOG_ERR, APP_NAME": sdb sync failed");
		}
		crypto_memzero(line, strlen(line));
		free(line);
	}
	sdb_close(sdb);
	rvault_close(vault);

	(void)argc; (void)argv;
	return -1;
}
