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
	fprintf(stderr, "usage: " APP_NAME "\n"
	    "        -b <base_path>\n"
	    "        [ -c <cipher> ]\n"
	    "        [ -r <file> | -w <file> ]\n"
	    "        [ -m <mountpoint>\n"
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
	const char *base_path = NULL, *cipher = NULL;
	const char *mountpoint = NULL, *target = NULL;
	char *passphrase = NULL;
	file_op_t io = -1;
	rvault_t *vault;
	bool fg = true;
	int ch;

	while ((ch = getopt(argc, argv, "c:b:fm:r:w:")) != -1) {
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
