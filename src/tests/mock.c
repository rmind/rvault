/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <assert.h>

#include "rvault.h"
#include "storage.h"
#include "fileobj.h"
#include "cli.h"
#include "utils.h"
#include "mock.h"

int
mock_get_tmpfile(char **pathp)
{
	char path_storage[PATH_MAX], *path;
	int fd;

	path = pathp ? calloc(1, PATH_MAX) : path_storage;
	snprintf(path, PATH_MAX, "/tmp/rvault-test.XXXXXX");
	fd = mkstemp(path);
	assert(fd != -1);
	if (pathp) {
		*pathp = path;
	} else {
		unlink(path);
	}
	return fd;
}

void
mock_corrupt_byte_at(int fd, off_t offset, unsigned char *bytep)
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
mock_get_vault_dir(void)
{
	return mkdtemp(strdup("/tmp/rvault-test.XXXXXX"));
}

static void
mock_remove_vault_dir(const char *path)
{
	struct dirent *dp;
	DIR *dirp;

	if (strncmp(path, "/tmp/", 5) != 0) {
		abort(); // only for tests!
	}

	/*
	 * Only to clean up tests.. don't care about error handling.
	 */
	dirp = opendir(path);
	assert(dirp != NULL);

	while ((dp = readdir(dirp)) != NULL) {
		char *dpath = NULL;
		struct stat st;
		int ret;

		if (dp->d_name[0] == '.')
			continue; // no dot-files in vault

		ret = asprintf(&dpath, "%s/%s", path, dp->d_name);
		assert(ret > 0);
		ret = stat(dpath, &st);
		assert(ret == 0);

		if (S_ISDIR(st.st_mode)) {
			mock_remove_vault_dir(dpath);
		} else {
			unlink(dpath);
		}
		free(dpath);
	}
	closedir(dirp);
	rmdir(path);
}

void
mock_cleanup_vault_dir(char *path)
{
	mock_remove_vault_dir(path);
	free(path);
}

rvault_t *
mock_get_vault(const char *cipher, char **path)
{
	char *base_path = mock_get_vault_dir();
	char *passphrase = strdup("test");
	rvault_t *vault;
	int ret;

	ret = rvault_init(base_path, NULL, passphrase, TEST_UUID,
	    cipher, NULL, RVAULT_FLAG_NOAUTH);
	assert(ret == 0);

	vault = rvault_open(base_path, NULL, passphrase);
	free(passphrase);
	assert(vault);

	*path = base_path;
	return vault;
}

void
mock_cleanup_vault(rvault_t *vault, char *base_path)
{
	assert(vault->file_count == 0);  // should be no leaks
	rvault_close(vault);
	mock_cleanup_vault_dir(base_path);
}

void
mock_vault_fwrite(rvault_t *vault, const char *f, const char *data)
{
	const size_t datalen = strlen(data);
	fileref_t *fref = fileobj_open(vault, f, O_CREAT | O_RDWR, FOBJ_OMASK);
	ssize_t nbytes = fileobj_pwrite(fref, data, datalen, 0);
	assert(nbytes == (ssize_t)datalen);
	fileobj_close(fref);
}

void
mock_vault_fcheck(rvault_t *vault, const char *f, const char *data)
{
	const size_t datalen = strlen(data);
	fileref_t *fref = fileobj_open(vault, f, O_RDONLY, FOBJ_OMASK);
	char buf[1024];
	ssize_t nbytes;

	assert(fref != NULL);
	assert(datalen < sizeof(buf));

	nbytes = fileobj_pread(fref, buf, sizeof(buf), 0);
	assert(nbytes == (ssize_t)datalen);
	buf[nbytes] = '\0';
	assert(strcmp(data, buf) == 0);
	fileobj_close(fref);
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

#if defined(SQLITE3_SERIALIZE)
int
sdb_cli(const char *datapath, const char *server, int argc, char **argv)
{
	(void)datapath; (void)server; (void)argc; (void)argv;
	return 0;
}
#endif
