/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

#include "rvault.h"
#include "utils.h"
#include "mock.h"

int
get_tmp_file(void)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path) - 1, "/tmp/rvault-test.XXXXXX");
	fd = mkstemp(path);
	assert(fd != -1);
	unlink(path);
	return fd;
}

void
corrupt_byte_at(int fd, off_t offset, unsigned char *bytep)
{
	unsigned char byte;
	ssize_t nbytes;

	if (bytep == NULL) {
		nbytes = pread(fd, &byte, sizeof(byte), offset);
		assert(nbytes == 1);

		byte++; // just change to a different value
		bytep = &byte;
	}
	nbytes = pwrite(fd, bytep, sizeof(byte), offset);
	assert(nbytes == 1);
}

char *
get_vault_dir(void)
{
	return mkdtemp(strdup("/tmp/rvault-test.XXXXXX"));
}

void
cleanup_vault_dir(char *path)
{
	char metafile[PATH_MAX];
	snprintf(metafile, sizeof(metafile), "%s/%s", path, RVAULT_META_FILE);
	unlink(metafile);
	rmdir(path);
	free(path);
}

rvault_t *
get_vault(const char *cipher, char **path)
{
	char *base_path = get_vault_dir();
	char *passphrase = strdup("test");
	rvault_t *vault;

	rvault_init(base_path, passphrase,
	    cipher ? cipher : "aes-256-cbc", RVAULT_FLAG_NOAUTH);
	vault = rvault_open(base_path, passphrase);
	free(passphrase);

	*path = base_path;
	return vault;
}

void
cleanup_vault(rvault_t *vault, char *base_path)
{
	rvault_close(vault);
	cleanup_vault_dir(base_path);
}

void *
hex_readmem_arbitrary(const char *s, size_t len, size_t *outlen)
{
	void *buf = NULL;
	FILE *fp;

	if ((fp = fmemopen(__UNCONST(s), len, "r")) != NULL) {
		buf = hex_read_arbitrary(fp, outlen);
		fclose(fp);
	}
	return buf;
}
