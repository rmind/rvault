/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <err.h>

#include "rvault.h"
#include "rvaultfs.h"
#include "fileobj.h"
#include "cli.h"
#include "sys.h"
#include "utils.h"

static void
usage(void)
{
	fprintf(stderr,
	    "Usage:\t" APP_NAME " [OPTIONS] COMMAND\n"
	    "\n"
	    "Options:\n"
	    "  -d, --datapath PATH    Base path to the vault data\n"
	    "  -h, --help             Show this help text\n"
	    "  -l, --log-level LEVEL  Set log level "
	    "(DEBUG, INFO, WARNING, ERROR, CRITICAL)\n"
	    "  -s, --server URL       Authentication server address\n"
	    "  -v, --version          Print version information and quit\n"
	    "\n"
	    "Environment variables:\n"
	    "  RVAULT_PATH            Base path of the vault data\n"
	    "  RVAULT_SERVER          Authentication server address\n"
	    "\n"
	    "Commands:\n"
	    "  create           Create and initialize a new vault\n"
	    "  export-key       Print the metadata and key for backup/recovery\n"
	    "  ls               List the vault contents\n"
	    "  mount            Mount the encrypted vault as a file system\n"
	    "  sdb              CLI to operate secrets/passwords\n"
	    "  read             Read a file from the vault\n"
	    "  write            Write a file to the vault\n"
	    "\n"
	    "Run '"APP_NAME" <COMMAND> -h' for more information on a command.\n"
	);
	exit(EXIT_FAILURE);
}

static void
usage_datapath(void)
{
	fprintf(stderr,
	    APP_NAME ": please specify the base data path.\n\n"
	    "  " APP_NAME " -d PATH COMMAND\n"
	    "    or\n"
	    "  RVAULT_PATH=PATH " APP_NAME " COMMAND\n"
	    "\n"
	);
	exit(EXIT_FAILURE);
}

//////////////////////////////////////////////////////////////////////////////

static int
create_vault(const char *path, const char *server, int argc, char **argv)
{
	static const char *opts_s = "c:hn?";
	static struct option opts_l[] = {
		{ "cipher",	required_argument,	0,	'c'	},
		{ "help",	no_argument,		0,	'h'	},
		{ "noauth",	no_argument,		0,	'n'	},
		{ NULL,		0,			NULL,	0	}
	};
	const char *uid, *cipher = NULL;
	unsigned flags = 0;
	char *passphrase;
	int ch, ret;

	while ((ch = getopt_long(argc, argv, opts_s, opts_l, NULL)) != -1) {
		switch (ch) {
		case 'c':
			cipher = optarg;
			break;
		case 'n':
			flags |= RVAULT_FLAG_NOAUTH;
			break;
		case 'h':
		case '?':
		default:
usage:			fprintf(stderr,
			    "Usage:\t" APP_NAME " create UID\n"
			    "\n"
			    "Create a new vault with the given UID.\n"
			    "\n"
			    "Options:\n"
			    "  -c|--cipher CIPHER  Cipher\n"
			    "  -n|--noauth         No authentication "
			    "(WARNING: this is much less secure)"
			    "\n"
			);
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc == 0) {
		goto usage;
	}
	uid = argv[0];

	if (flags & RVAULT_FLAG_NOAUTH) {
		puts("WARNING: You chose no authentication -- "
		    "it is much less secure!");
	}
	if ((passphrase = getpass("Passphrase: ")) == NULL) {
		errx(EXIT_FAILURE, "missing passphrase");
	}
	ret = rvault_init(path, server, passphrase, uid, cipher, flags);
	crypto_memzero(passphrase, strlen(passphrase));
	if (ret == -1) {
		fprintf(stderr, "vault creation failed -- exiting.\n");
	}
	return ret;
}

rvault_t *
open_vault(const char *datapath, const char *server)
{
	char *passphrase = NULL;
	rvault_t *vault;

	/*
	 * Get the passphrase.
	 */
	if ((passphrase = getpass("Passphrase: ")) == NULL) {
		errx(EXIT_FAILURE, "missing passphrase");
	}

	/*
	 * Open the vault; erase the passphrase immediately.
	 */
	vault = rvault_open(datapath, server, passphrase);
	crypto_memzero(passphrase, strlen(passphrase));
	if (!vault) {
		fprintf(stderr, "failed to open the vault -- exiting.\n");
		exit(EXIT_FAILURE);
	}
	return vault;
}

//////////////////////////////////////////////////////////////////////////////

static int
mount_vault(const char *datapath, const char *server, int argc, char **argv)
{
	if (argc > 1) {
		const char *mountpoint = argv[1];
		rvault_t *vault;
#if 0
		if (!fg && daemon(0, 0) == -1) {
			err(EXIT_FAILURE, "daemon");
		}
#endif
		vault = open_vault(datapath, server);
		rvaultfs_run(vault, mountpoint);
		rvault_close(vault);
		return 0;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " mount PATH\n"
	    "\n"
	    "Mount the vault at the given path.\n"
	    "\n"
	);
	return -1;
}

//////////////////////////////////////////////////////////////////////////////

static int
export_key(const char *datapath, const char *server,
    int argc __unused, char **argv __unused)
{
	rvault_t *vault;

	printf("WARNING: This command is about to expose the "
	    "effective encryption key!\n"
	    "Back it up safely for recovery; "
	    "leaking it would compromise the data.\n\n");

	for (;;) {
		int ch;

		puts("Type 'y' to continue or 'n' to exit:");
		ch = getchar();
		if (ch == 'y')
			break;
		if (ch == 'n')
			return 0;
	}

	vault = open_vault(datapath, server);
	rvault_export_key(vault);
	rvault_close(vault);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////

#define	BUF_SIZE	(64 * 1024)

typedef enum { FILE_READ, FILE_WRITE } file_op_t;

static int
do_file_io(rvault_t *vault, const char *target, file_op_t io)
{
	const int flags = (io == FILE_READ) ? O_RDONLY : (O_CREAT | O_RDWR);
	fileobj_t *fobj;
	void *buf = NULL;
	ssize_t nbytes;
	off_t off = 0;
	int ret = -1;

	if ((fobj = fileobj_open(vault, target, flags, FOBJ_OMASK)) == NULL) {
		err(EXIT_FAILURE, "failed to open `%s'", target);
	}
	switch (io) {
	case FILE_READ:
		if ((nbytes = fileobj_getsize(fobj)) <= 0) {
			break; // nothing to do
		}
		if ((buf = malloc(nbytes)) == NULL) {
			app_elog(LOG_CRIT, APP_NAME": malloc() failed");
			goto out;
		}
		if (fileobj_pread(fobj, buf, nbytes, 0) == -1) {
			app_elog(LOG_CRIT, APP_NAME": fileobj_pread() failed");
			goto out;
		}
		if (fs_write(STDOUT_FILENO, buf, nbytes) != nbytes) {
			app_elog(LOG_CRIT, APP_NAME": fs_write() failed");
			goto out;
		}
		break;
	case FILE_WRITE:
		if ((buf = malloc(BUF_SIZE)) == NULL) {
			app_elog(LOG_CRIT, APP_NAME": malloc() failed");
			goto out;
		}
		while ((nbytes = fs_read(STDIN_FILENO, buf, BUF_SIZE)) > 0) {
			if (fileobj_pwrite(fobj, buf, nbytes, off) == -1) {
				app_elog(LOG_CRIT,
				    APP_NAME": fileobj_pwrite() failed");
				goto out;
			}
			off += nbytes;
		}
		if (nbytes == -1) {
			app_elog(LOG_CRIT, "fs_read() failed");
			goto out;
		}
		break;
	}
	ret = 0;
out:
	fileobj_close(fobj);
	free(buf);
	return ret;
}

typedef enum { FILE_SHOWALL = 0x1 } flist_flag_t;

static void
file_list_iter(void *arg, const char *name, struct dirent *dp)
{
	const flist_flag_t flags = (flist_flag_t)(uintptr_t)arg;

	if ((flags & FILE_SHOWALL) == 0 && name[0] == '.') {
		return; // skip the hidden files if "-a"
	}
	printf("%s\n", name);
	(void)arg; (void)dp;
}

static int
file_list_cmd(const char *datapath, const char *server, int argc, char **argv)
{
	static const char *opts_s = "ah?";
	static struct option opts_l[] = {
		{ "all",	no_argument,		0,	'a'	},
		{ "help",	no_argument,		0,	'h'	},
		{ NULL,		0,			NULL,	0	}
	};
	rvault_t *vault;
	const char *path;
	flist_flag_t flags;
	int ch;

	flags = 0;
	while ((ch = getopt_long(argc, argv, opts_s, opts_l, NULL)) != -1) {
		switch (ch) {
		case 'a':
			flags |= FILE_SHOWALL;
			break;
		case 'h':
		case '?':
		default:
			fprintf(stderr,
			    "Usage:\t" APP_NAME " ls [PATH]\n"
			    "\n"
			    "List the vault content.\n"
			    "The path must represent the namespace in vault.\n"
			    "\n"
			    "Options:\n"
			    "  -a|--all  Show all files and directories, "
			    "including the dot ones.\n"
			    "\n"
			);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	vault = open_vault(datapath, server);
	path = argc ? argv[0] : "/";
	rvault_iter_dir(vault, path, (void *)(uintptr_t)flags, file_list_iter);
	rvault_close(vault);
	return 0;
}

static int
file_read_cmd(const char *datapath, const char *server, int argc, char **argv)
{
	if (argc > 1) {
		const char *target = argv[1];
		rvault_t *vault = open_vault(datapath, server);
		int ret = do_file_io(vault, target, FILE_READ);
		rvault_close(vault);
		return ret;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " read PATH\n"
	    "\n"
	    "Read and decrypt the file in the vault.\n"
	    "The path must represent the namespace in vault.\n"
	    "\n"
	);
	return -1;
}

static int
file_write_cmd(const char *datapath, const char *server, int argc, char **argv)
{
	if (argc > 1) {
		const char *target = argv[1];
		rvault_t *vault = open_vault(datapath, server);
		int ret = do_file_io(vault, target, FILE_WRITE);
		rvault_close(vault);
		return ret;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " write PATH\n"
	    "\n"
	    "Encrypt and write the file into the vault.\n"
	    "The path must represent the namespace in vault.\n"
	    "\n"
	);
	return -1;
}

//////////////////////////////////////////////////////////////////////////////

#ifndef SQLITE3_SERIALIZE
static int
sdb_sqlite3_mismatch(const char *d, const char *server, int argc, char **argv)
{
	(void)d; (void)server; (void)argc; (void)argv;
	fprintf(stderr,
	    APP_NAME ": this command is not supported; "
	    "you need sqlite 3.23 or newer,\n"
	    "compiled with the SQLITE_ENABLE_DESERIALIZE option.\n"
	);
	return -1;
}
#endif

typedef int (*cmd_func_t)(const char *, const char *, int, char **);

static int
process_command(const char *datapath, const char *server, int argc, char **argv)
{
	static const struct {
		const char *	name;
		cmd_func_t	func;
	} commands[] = {
		{ "create",	create_vault		},
		{ "export-key",	export_key		},
		{ "ls",		file_list_cmd,		},
#ifdef SQLITE3_SERIALIZE
		{ "sdb",	sdb_cli,		},
#else
		{ "sdb",	sdb_sqlite3_mismatch,	},
#endif
		{ "mount",	mount_vault,		},
		{ "read",	file_read_cmd,		},
		{ "write",	file_write_cmd,		},
	};

	for (unsigned i = 0; i < __arraycount(commands); i++) {
		if (strcmp(commands[i].name, argv[0]) == 0) {
			int ret;

			/* Run the command. */
			ret = commands[i].func(datapath, server, argc, argv);
			return ret == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
		}
	}
	usage();
	return EXIT_FAILURE;
}

static int
get_log_level(const char *level_name)
{
	static struct {
		const char *	name;
		int		level;
	} log_levels[] = {
		{ "DEBUG",	LOG_DEBUG	},
		{ "INFO",	LOG_INFO	},
		{ "WARNING",	LOG_WARNING	},
		{ "ERROR",	LOG_ERR		},
		{ "CRITICAL",	LOG_CRIT	},
	};
	for (unsigned i = 0; i < __arraycount(log_levels); i++) {
		if (strcasecmp(log_levels[i].name, level_name) == 0) {
			return log_levels[i].level;
		}
	}
	usage();
	return -1;
}

int
main(int argc, char **argv)
{
	static const char *opts_s = "d:hl:s:v?";
	static struct option opts_l[] = {
		{ "datapath",	required_argument,	0,	'd'	},
		{ "help",	no_argument,		0,	'h'	},
		{ "log-level",	required_argument,	0,	'l'	},
		{ "server",	required_argument,	0,	's'	},
		{ "version",	no_argument,		0,	'v' 	},
		{ NULL,		0,			NULL,	0	}
	};
	const char *data_path = getenv("RVAULT_PATH");
	const char *server = getenv("RVAULT_SERVER");
	int ch, loglevel = LOG_WARNING;

	for (;;) {
		/*
		 * Parse the options until the first command only.
		 */
		if (argv[optind] && *argv[optind] != '-') {
			break;
		}
		ch = getopt_long(argc, argv, opts_s, opts_l, NULL);
		if (ch == -1) {
			break;
		}
		switch (ch) {
		case 'd':
			data_path = optarg;
			break;
		case 'l':
			loglevel = get_log_level(optarg);
			break;
		case 's':
			server = optarg;
			break;
		case 'v':
			printf(APP_NAME " version " APP_PROJ_VER "\n");
			exit(EXIT_SUCCESS);
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	/*
	 * Advance and reset: commands may call getopt() again.
	 */
	argc -= optind;
	argv += optind;
	optind = 1;
#ifndef __linux__
	optreset = 1;
#endif

	if (argc == 0) {
		usage();
	}
	if (!data_path) {
		usage_datapath();
	}

	app_setlog(loglevel);
	return process_command(data_path, server, argc, argv);
}
