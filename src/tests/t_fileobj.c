/*
 * Copyright (c) 2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <assert.h>

#include "rvault.h"
#include "fileobj.h"
#include "sys.h"
#include "utils.h"
#include "mock.h"

#define	TEST_BLOCK_COUNT	128
#define	TEST_BLOCK_SIZE		(32U * 1024) // 32 KB

static void
test_file_expand(rvault_t *vault)
{
	fileobj_t *fobj;
	ssize_t nbytes;
	void *buf, *rbuf;
	off_t off;

	fobj = fileobj_open(vault, "/expand_test", O_CREAT | O_RDWR, FOBJ_OMASK);
	assert(fobj != NULL);

	buf = malloc(TEST_BLOCK_SIZE);
	assert(buf != NULL);
	off = 0;

	/*
	 * Sequentially write the data blocks.
	 */
	for (unsigned i = 0; i < TEST_BLOCK_COUNT; i++) {
		memset(buf, (unsigned char)i, TEST_BLOCK_SIZE);
		nbytes = fileobj_pwrite(fobj, buf, TEST_BLOCK_SIZE, off);
		assert(nbytes == TEST_BLOCK_SIZE);
		off += nbytes;
	}
	nbytes = fileobj_getsize(fobj);
	assert(nbytes == (TEST_BLOCK_SIZE * TEST_BLOCK_COUNT));

	/*
	 * NOTE: fileobj_close() should invoke SYNC.
	 */
	fileobj_close(fobj);

	/*
	 * Open a new file handle and verify the written data.
	 */
	fobj = fileobj_open(vault, "/expand_test", O_RDONLY, FOBJ_OMASK);
	assert(fobj != NULL);

	nbytes = fileobj_getsize(fobj);
	assert(nbytes == (TEST_BLOCK_SIZE * TEST_BLOCK_COUNT));

	rbuf = malloc(TEST_BLOCK_SIZE);
	assert(rbuf != NULL);
	off = 0;

	for (unsigned i = 0; i < TEST_BLOCK_COUNT; i++) {
		nbytes = fileobj_pread(fobj, rbuf, TEST_BLOCK_SIZE, off);
		assert(nbytes == TEST_BLOCK_SIZE);
		off += nbytes;

		memset(buf, (unsigned char)i, TEST_BLOCK_SIZE);
		if (memcmp(rbuf, buf, TEST_BLOCK_SIZE) != 0) {
			fprintf(stderr, "test_file_expand: data mismatch");
			abort();
		}
	}
	fileobj_close(fobj);

	free(rbuf);
	free(buf);
}

static void
test_file_onebyte(rvault_t *vault)
{
	unsigned char b = '$', buf[16];
	fileobj_t *fobj;
	ssize_t nbytes;

	fobj = fileobj_open(vault, "/1b_test", O_CREAT | O_RDWR, FOBJ_OMASK);
	assert(fobj != NULL);

	nbytes = fileobj_pwrite(fobj, &b, 1, 0);
	assert(nbytes == 1);

	nbytes = fileobj_getsize(fobj);
	assert(nbytes == 1);

	fileobj_close(fobj);

	fobj = fileobj_open(vault, "/1b_test", O_RDONLY, FOBJ_OMASK);
	assert(fobj != NULL);

	nbytes = fileobj_getsize(fobj);
	assert(nbytes == 1);

	buf[0] = '\0';
	nbytes = fileobj_pread(fobj, buf, sizeof(buf), 0);
	assert(nbytes == 1);
	assert(buf[0] == '$');

	fileobj_close(fobj);
}

static void
run_tests(const char *cipher)
{
	char *base_path = NULL;
	rvault_t *vault = mock_get_vault(cipher, &base_path);
	test_file_expand(vault);
	test_file_onebyte(vault);
	mock_cleanup_vault(vault, base_path);
}

int
main(void)
{
	const char **ciphers;
	unsigned nitems = 0;

	ciphers = crypto_cipher_list(&nitems);
	for (unsigned i = 0; i < nitems; i++) {
		const char *cipher = ciphers[i];
		run_tests(cipher);
	}
	puts("ok");
	return 0;
}
