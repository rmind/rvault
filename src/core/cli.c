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
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <err.h>

#include "rvault.h"
#include "rvaultfs.h"
#include "fileobj.h"
#include "sdb.h"
#include "sys.h"
#include "utils.h"

//////////////////////////////////////////////////////////////////////////////

static void
create_vault(const char *path, int argc, char **argv)
{
	if (argc > 1) {
		const char *cipher = argv[1];
		char *passphrase = NULL;

		if ((passphrase = getpass("Passphrase: ")) == NULL) {
			errx(EXIT_FAILURE, "missing passphrase");
		}
		if (rvault_init(path, passphrase, cipher) == -1) {
			err(EXIT_FAILURE, "failed to initialize metadata");
		}
		crypto_memzero(passphrase, strlen(passphrase));
		passphrase = NULL; // diagnostic
		return;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " create CIPHER\n"
	    "\n"
	    "Create a new vault\n"
	    "\n"
	);
	exit(EXIT_FAILURE);
}

static void
mount_vault(rvault_t *vault, int argc, char **argv)
{
	if (argc > 1) {
		const char *mountpoint = argv[1];
#if 0
		if (!fg && daemon(0, 0) == -1) {
			err(EXIT_FAILURE, "daemon");
		}
#endif
		rvaultfs_run(vault, mountpoint);
		return;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " mount PATH\n"
	    "\n"
	    "Mount the vault at the given path\n"
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
		break;
	}
	fileobj_close(fobj);
	free(buf);
}

static void
file_list_cmd(rvault_t *vault, int argc, char **argv)
{
	static const char *opts_s = "h?";
	static struct option opts_l[] = {
		{ "help",	no_argument,		0,	'h'	},
		{ NULL,		0,			NULL,	0	}
	};
	const char *path;
	char *vault_path;
	struct dirent *dp;
	DIR *dirp;
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
			    "The path must represent the namespace "
			    "of encrypted vault.\n"
			    "\n"
			);
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	path = argc ? argv[0] : "/";
	if ((vault_path = rvault_resolve_path(vault, path, NULL)) == NULL) {
		err(EXIT_FAILURE, "rvault_resolve_path");
	}
	dirp = opendir(vault_path);
	if (dirp == NULL) {
		err(EXIT_FAILURE, "opendir");
	}
	free(vault_path);

	while ((dp = readdir(dirp)) != NULL) {
		char *name;

		if (dp->d_name[0] == '.') {
			continue;
		}
		if (!strncmp(dp->d_name, "rvault.", sizeof("rvault.") - 1)) {
			continue;
		}
		name = rvault_resolve_vname(vault, dp->d_name, NULL);
		if (name == NULL) {
			err(EXIT_FAILURE, "rvault_resolve_vname");
		}
		printf("%s\n", name);
		free(name);
	}
	closedir(dirp);
}

static void
file_read_cmd(rvault_t *vault, int argc, char **argv)
{
	if (argc > 1) {
		const char *target = argv[1];
		do_file_io(vault, target, FILE_READ);
		return;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " read PATH\n"
	    "\n"
	    "Read and decrypt the file in the vault.\n"
	    "The path must represent the namespace of encrypted vault.\n"
	    "\n"
	);
	exit(EXIT_FAILURE);
}

static void
file_write_cmd(rvault_t *vault, int argc, char **argv)
{
	if (argc > 1) {
		const char *target = argv[1];
		do_file_io(vault, target, FILE_WRITE);
		return;
	}
	fprintf(stderr,
	    "Usage:\t" APP_NAME " write PATH\n"
	    "\n"
	    "Encrypt and write the file into the vault.\n"
	    "The path must represent the namespace of encrypted vault.\n"
	    "\n"
	);
	exit(EXIT_FAILURE);
}

//////////////////////////////////////////////////////////////////////////////

static void
usage(void)
{
	fprintf(stderr,
	    "Usage:\t" APP_NAME " [OPTIONS] COMMAND\n"
	    "\n"
	    "Options:\n"
	    "  -d, --datapath PATH      Base path to the vault data\n"
	    "  -h, --help               Show this help text\n"
	    "  -l, --log-level LEVEL    Set log level "
	    "(DEBUG, INFO, WARNING, ERROR, CRITICAL)\n"
	    "  -s, --server ADDRESS     Authentication server address\n"
	    "  -v, --version            Print version information and quit\n"
	    "\n"
	    "Environment variables:\n"
	    "  RVAULT_PATH              Base path of the vault data\n"
	    "  RVAULT_SERVER            Authentication server address\n"
	    "\n"
	    "Commands:\n"
	    "  create           Create and initialize a new vault\n"
	    "  ls               List the vault contents\n"
	    "  mount            Mount the encrypted vault as a file system\n"
#ifdef SQLITE3_SERIALIZE
	    "  sdb              CLI to operate secrets/passwords\n"
#endif
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

typedef void (*cmd_func_t)(rvault_t *, int, char **);

static void
process_command(const char *datapath, const char *server, int argc, char **argv)
{
	static const struct {
		const char *	name;
		cmd_func_t	func;
	} commands[] = {
		/* "create" -- handled separately to create the vault */
		{ "ls",		file_list_cmd,		},
#ifdef SQLITE3_SERIALIZE
		{ "sdb",	sdb_cli,		},
#endif
		{ "mount",	mount_vault,		},
		{ "read",	file_read_cmd,		},
		{ "write",	file_write_cmd,		},
	};
	char *passphrase = NULL;
	cmd_func_t cmd_func = NULL;
	rvault_t *vault;
	bool create;

	for (unsigned i = 0; i < __arraycount(commands); i++) {
		if (strcmp(commands[i].name, argv[0]) == 0) {
			cmd_func = commands[i].func;
			break;
		}
	}
	create = strcmp("create", argv[0]) == 0;
	if (create) {
		create_vault(datapath, argc, argv);
		exit(EXIT_SUCCESS);
	}
	if (!cmd_func) {
		usage();
	}

	/*
	 * Get the passphrase.
	 */
	if ((passphrase = getpass("Passphrase: ")) == NULL) {
		errx(EXIT_FAILURE, "missing passphrase");
	}
	(void)server; // TODO

	/*
	 * Open the vault; erase the passphrase immediately.
	 */
	vault = rvault_open(datapath, passphrase);
	if (vault == NULL) {
		err(EXIT_FAILURE, "failed to open metadata");
	}
	crypto_memzero(passphrase, strlen(passphrase));
	passphrase = NULL; // diagnostic

	/*
	 * Run the operation.  Close the vault.
	 */
	cmd_func(vault, argc, argv);
	rvault_close(vault);
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
	int loglevel = LOG_WARNING;
	int ch;

	while ((ch = getopt_long(argc, argv, opts_s, opts_l, NULL)) != -1) {
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
