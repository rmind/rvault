/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <err.h>

#include "rvault.h"
#include "rvaultfs.h"
#include "fileobj.h"
#include "sys.h"

#define	BUF_SIZE	(64 * 1024)

typedef enum {
	FILE_READ, FILE_WRITE
} file_op_t;

static void
usage(void)
{
	fprintf(stderr,
	    "Usage:\t" APP_NAME " [OPTIONS] COMMAND\n"
	    "\n"
	    "Options:\n"
	    "  -b, --basepath PATH      Base path to the vault\n"
	    "  -h, --help               Show this help text\n"
	    "  -l, --log-level LEVEL    Set log level "
	    "(DEBUG, INFO, WARNING, ERROR, CRITICAL)\n"
	    "  -v, --version            Print version information and quit\n"
	    "\n"
	    "Commands:\n"
	    "  create      Create and initialize a new vault\n"
	    "  read        Read a file from the vault\n"
	    "  mount       Mount the encrypted vault as a file system\n"
	    "  write       Write a file to the vault\n"
	    "\n"
	    "Run '"APP_NAME" <COMMAND> -h' for more information on a command.\n"
	);
	exit(EXIT_FAILURE);
}

static void
do_file_io(rvault_t *vault, const char *target, file_op_t io)
{
	fileobj_t *fobj;
	void *buf = NULL;
	ssize_t nbytes;
	off_t off = 0;

	if ((fobj = fileobj_open(vault, target, O_CREAT | O_RDWR)) == NULL) {
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

int
main(int argc, char **argv)
{
	static struct option options[] = {
		{ "basepath",	required_argument,	0,	'b'	},
		{ "help",	no_argument,		0,	'h'	},
		{ "log-level",	required_argument,	0,	'l'	},
		{ "version",	no_argument,		0,	'v' 	},
		{ NULL,		0,			NULL,	0	}
	};
	const char *base_path = NULL, *cipher = NULL;
	const char *mountpoint = NULL, *target = NULL;
	char *passphrase = NULL;
	file_op_t io = -1;
	rvault_t *vault;
	bool fg = true;
	int ch;

	while ((ch = getopt_long(argc, argv, "b:hl:v", options, NULL)) != -1) {
		switch (ch) {
		case 'c':
			cipher = optarg;
			break;
		case 'b':
			base_path = optarg;
			break;
		case 'f':
			fg = true;
			break;
		case 'm':
			mountpoint = optarg;
			break;
		case 'r':
			target = optarg;
			io = FILE_READ;
			break;
		case 'w':
			target = optarg;
			io = FILE_WRITE;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	printf("MEOW: %d/%s\n", argc, argv[0]);
	exit(EXIT_SUCCESS);

	if (!base_path) {
		usage();
	}

	if ((passphrase = getpass("Passphrase: ")) == NULL) {
		errx(EXIT_FAILURE, "missing passphrase");
	}
#if 0
	if (!fg && daemon(0, 0) == -1) {
		err(EXIT_FAILURE, "daemon");
	}
#else
	(void)fg;
#endif
	if (cipher && rvault_init(base_path, passphrase, cipher) == -1) {
		err(EXIT_FAILURE, "failed to initialize metadata");
	}
	vault = rvault_open(base_path, passphrase);
	if (vault == NULL) {
		err(EXIT_FAILURE, "failed to open metadata");
	}
	crypto_memzero(passphrase, strlen(passphrase)); // paranoid

	if (target) {
		do_file_io(vault, target, io);
	}
	if (mountpoint) {
		rvaultfs_run(vault, mountpoint);
	}
	rvault_close(vault);
	free(passphrase);

	return EXIT_SUCCESS;
}
