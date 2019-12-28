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

static void
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
	int ch;

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
	if (rvault_init(path, server, passphrase, uid, cipher, flags) == -1) {
		fprintf(stderr, "vault creation failed -- exiting.\n");
		exit(EXIT_FAILURE);
	}
	crypto_memzero(passphrase, strlen(passphrase));
	passphrase = NULL; // diagnostic
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
	if (vault == NULL) {
		fprintf(stderr, "failed to open the vault -- exiting.\n");
		exit(EXIT_FAILURE);
	}
	crypto_memzero(passphrase, strlen(passphrase));
	passphrase = NULL; // diagnostic
	return vault;
}

//////////////////////////////////////////////////////////////////////////////

static void
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
		return;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " mount PATH\n"
	    "\n"
	    "Mount the vault at the given path.\n"
	    "\n"
	);
	exit(EXIT_FAILURE);
}

//////////////////////////////////////////////////////////////////////////////

#define	BUF_SIZE	(64 * 1024)

typedef enum { FILE_READ, FILE_WRITE } file_op_t;

static void
do_file_io(rvault_t *vault, const char *target, file_op_t io)
{
	const int flags = (io == FILE_READ) ? O_RDONLY : (O_CREAT | O_RDWR);
	fileobj_t *fobj;
	void *buf = NULL;
	ssize_t nbytes;
	off_t off = 0;

	if ((fobj = fileobj_open(vault, target, flags, FOBJ_OMASK)) == NULL) {
		err(EXIT_FAILURE, "failed to open `%s'", target);
	}
	switch (io) {
	case FILE_READ:
		if ((nbytes = fileobj_getsize(fobj)) <= 0) {
			return; // nothing to do
		}
		if ((buf = malloc(nbytes)) == NULL) {
			err(EXIT_FAILURE, "malloc");
		}
		if (fileobj_pread(fobj, buf, nbytes, 0) == -1) {
			err(EXIT_FAILURE, "fileobj_pread() failed");
		}
		if (fs_write(STDOUT_FILENO, buf, nbytes) != nbytes) {
			err(EXIT_FAILURE, "fs_write() failed");
		}
		break;
	case FILE_WRITE:
		if ((buf = malloc(BUF_SIZE)) == NULL) {
			err(EXIT_FAILURE, "malloc");
		}
		while ((nbytes = fs_read(STDIN_FILENO, buf, BUF_SIZE)) > 0) {
			if (fileobj_pwrite(fobj, buf, nbytes, off) == -1) {
				err(EXIT_FAILURE, "fileobj_pwrite() failed");
			}
			off += nbytes;
		}
		if (nbytes == -1) {
			err(EXIT_FAILURE, "fs_read() failed");
		}
		break;
	}
	fileobj_close(fobj);
	free(buf);
}

static void
file_list_cmd_iter(void *arg, const char *name, struct dirent *dp)
{
	printf("%s\n", name);
	(void)arg; (void)dp;
}

static void
file_list_cmd(const char *datapath, const char *server, int argc, char **argv)
{
	static const char *opts_s = "h?";
	static struct option opts_l[] = {
		{ "help",	no_argument,		0,	'h'	},
		{ NULL,		0,			NULL,	0	}
	};
	rvault_t *vault;
	const char *path;
	int ch;

	while ((ch = getopt_long(argc, argv, opts_s, opts_l, NULL)) != -1) {
		switch (ch) {
		case 'h':
		case '?':
		default:
			fprintf(stderr,
			    "Usage:\t" APP_NAME " ls [PATH]\n"
			    "\n"
			    "List the vault content.\n"
			    "The path must represent the namespace in vault.\n"
			    "\n"
			);
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	vault = open_vault(datapath, server);
	path = argc ? argv[0] : "/";
	rvault_iter_dir(vault, path, NULL, file_list_cmd_iter);
	rvault_close(vault);
}

static void
file_read_cmd(const char *datapath, const char *server, int argc, char **argv)
{
	if (argc > 1) {
		const char *target = argv[1];
		rvault_t *vault;

		vault = open_vault(datapath, server);
		do_file_io(vault, target, FILE_READ);
		rvault_close(vault);
		return;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " read PATH\n"
	    "\n"
	    "Read and decrypt the file in the vault.\n"
	    "The path must represent the namespace in vault.\n"
	    "\n"
	);
	exit(EXIT_FAILURE);
}

static void
file_write_cmd(const char *datapath, const char *server, int argc, char **argv)
{
	if (argc > 1) {
		const char *target = argv[1];
		rvault_t *vault;

		vault = open_vault(datapath, server);
		do_file_io(vault, target, FILE_WRITE);
		rvault_close(vault);
		return;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " write PATH\n"
	    "\n"
	    "Encrypt and write the file into the vault.\n"
	    "The path must represent the namespace in vault.\n"
	    "\n"
	);
	exit(EXIT_FAILURE);
}

//////////////////////////////////////////////////////////////////////////////

#ifndef SQLITE3_SERIALIZE
static void
sdb_sqlite3_mismatch(const char *d, const char *server, int argc, char **argv)
{
	(void)d; (void)server; (void)argc; (void)argv;
	fprintf(stderr,
	    APP_NAME ": this command is not supported; "
	    "you need sqlite 3.23 or newer,\n"
	    "compiled with the SQLITE_ENABLE_DESERIALIZE option.\n"
	);
	exit(EXIT_FAILURE);
}
#endif

typedef void (*cmd_func_t)(const char *, const char *, int, char **);

static void
process_command(const char *datapath, const char *server, int argc, char **argv)
{
	static const struct {
		const char *	name;
		cmd_func_t	func;
	} commands[] = {
		{ "create",	create_vault		},
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
			/* Run the command. */
			commands[i].func(datapath, server, argc, argv);
			return;
		}
	}
	(void)server;
	usage();
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
	process_command(data_path, server, argc, argv);
	return EXIT_SUCCESS;
}
