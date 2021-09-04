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
test_file_basic(rvault_t *vault)
{
	fileref_t *fref;
	ssize_t nbytes;

	fref = fileobj_open(vault, "/basic", O_CREAT | O_RDWR, FOBJ_OMASK);
	assert(fref != NULL);
	fileobj_close(fref);

	fref = fileobj_open(vault, "/basic", O_RDONLY, FOBJ_OMASK);
	assert(fref != NULL);
	nbytes = fileobj_getsize(fref);
	assert(nbytes == 0);
	fileobj_close(fref);
}

static void
test_file_expand(rvault_t *vault)
{
	fileref_t *fref;
	ssize_t nbytes;
	void *buf, *rbuf;
	off_t off;

	fref = fileobj_open(vault, "/expand_test", O_CREAT | O_RDWR, FOBJ_OMASK);
	assert(fref != NULL);

	buf = malloc(TEST_BLOCK_SIZE);
	assert(buf != NULL);
	off = 0;

	/*
	 * Sequentially write the data blocks.
	 */
	for (unsigned i = 0; i < TEST_BLOCK_COUNT; i++) {
		memset(buf, (unsigned char)i, TEST_BLOCK_SIZE);
		nbytes = fileobj_pwrite(fref, buf, TEST_BLOCK_SIZE, off);
		assert(nbytes == TEST_BLOCK_SIZE);
		off += nbytes;
	}
	nbytes = fileobj_getsize(fref);
	assert(nbytes == (TEST_BLOCK_SIZE * TEST_BLOCK_COUNT));

	/*
	 * NOTE: fileobj_close() should invoke SYNC.
	 */
	fileobj_close(fref);

	/*
	 * Open a new file handle and verify the written data.
	 */
	fref = fileobj_open(vault, "/expand_test", O_RDONLY, FOBJ_OMASK);
	assert(fref != NULL);

	nbytes = fileobj_getsize(fref);
	assert(nbytes == (TEST_BLOCK_SIZE * TEST_BLOCK_COUNT));

	rbuf = malloc(TEST_BLOCK_SIZE);
	assert(rbuf != NULL);
	off = 0;

	for (unsigned i = 0; i < TEST_BLOCK_COUNT; i++) {
		nbytes = fileobj_pread(fref, rbuf, TEST_BLOCK_SIZE, off);
		assert(nbytes == TEST_BLOCK_SIZE);
		off += nbytes;

		memset(buf, (unsigned char)i, TEST_BLOCK_SIZE);
		if (memcmp(rbuf, buf, TEST_BLOCK_SIZE) != 0) {
			fprintf(stderr, "test_file_expand: data mismatch");
			abort();
		}
	}
	fileobj_close(fref);

	free(rbuf);
	free(buf);
}

static void
test_file_onebyte(rvault_t *vault)
{
	unsigned char b = '$', buf[16];
	fileref_t *fref;
	ssize_t nbytes;

	fref = fileobj_open(vault, "/1b_test", O_CREAT | O_RDWR, FOBJ_OMASK);
	assert(fref != NULL);

	nbytes = fileobj_pwrite(fref, &b, 1, 0);
	assert(nbytes == 1);

	nbytes = fileobj_getsize(fref);
	assert(nbytes == 1);

	fileobj_close(fref);

	fref = fileobj_open(vault, "/1b_test", O_RDONLY, FOBJ_OMASK);
	assert(fref != NULL);

	nbytes = fileobj_getsize(fref);
	assert(nbytes == 1);

	buf[0] = '\0';
	nbytes = fileobj_pread(fref, buf, sizeof(buf), 0);
	assert(nbytes == 1);
	assert(buf[0] == '$');

	fileobj_close(fref);
}

static void
test_file_setsize(rvault_t *vault)
{
	static const unsigned zeros[16];
	unsigned buf[16];
	fileref_t *fref;
	ssize_t nbytes;

	fref = fileobj_open(vault, "/empty", O_CREAT | O_RDWR, FOBJ_OMASK);
	assert(fref != NULL);

	/* Test an empty file. */
	nbytes = fileobj_pread(fref, buf, sizeof(buf), 0);
	assert(nbytes == 0);

	/* Setting the file size must fill the space with zeros. */
	fileobj_setsize(fref, sizeof(buf));
	nbytes = fileobj_pread(fref, buf, sizeof(buf), 0);
	assert(nbytes == sizeof(buf));
	assert(memcmp(buf, zeros, sizeof(buf)) == 0);

	/*
	 * Shrink to zero, must result in zero bytes to read.
	 * Re-open the file to test with a separate file descriptor.
	 */
	fileobj_setsize(fref, 0);
	fileobj_close(fref);

	fref = fileobj_open(vault, "/empty", O_RDONLY, FOBJ_OMASK);
	assert(fref != NULL);
	nbytes = fileobj_pread(fref, buf, sizeof(buf), 0);
	assert(nbytes == 0);
	fileobj_close(fref);

	/*
	 * Write some data, shrink size, expand, check.
	 */
	fref = fileobj_open(vault, "/empty", O_CREAT | O_RDWR, FOBJ_OMASK);
	assert(fref != NULL);

	nbytes = fileobj_pwrite(fref, (const void *)"ab", 2, 0);
	assert(nbytes == 2);

	fileobj_setsize(fref, 1);
	fileobj_setsize(fref, 3);

	nbytes = fileobj_pread(fref, buf, sizeof(buf), 0);
	assert(nbytes == 3);
	assert(memcmp(buf, "a\0\0", 3) == 0);
	fileobj_close(fref);
}

static void
test_file_refs(rvault_t *vault)
{
	fileref_t *fref1, *fref2;
	unsigned char b1 = 'x', b2 = 'y', buf[3];
	unsigned fcount;
	ssize_t nbytes;
	int ret;

	/*
	 * Open two references (descriptors).
	 */
	fref1 = fileobj_open(vault, "/some", O_CREAT | O_RDWR, FOBJ_OMASK);
	assert(fref1 != NULL);

	fref2 = fileobj_open(vault, "/some", O_RDWR, FOBJ_OMASK);
	assert(fref2 != NULL);


	/*
	 * Writes via separate references; sync each.
	 */
	assert(fref1 != fref2);

	nbytes = fileobj_pwrite(fref1, &b1, 1, 0);
	assert(nbytes == 1);

	nbytes = fileobj_pwrite(fref2, &b2, 1, 1);
	assert(nbytes == 1);

	ret = fileobj_sync(fref1, FOBJ_FULLSYNC);
	assert(ret == 0);

	ret = fileobj_sync(fref2, FOBJ_FULLSYNC);
	assert(ret == 0);

	/*
	 * Both reads should have the same visibility.
	 */
	nbytes = fileobj_pread(fref1, buf, sizeof(buf), 0);
	assert(nbytes == 2);
	assert(memcmp(buf, "xy", 2) == 0);

	nbytes = fileobj_pread(fref2, buf, sizeof(buf), 0);
	assert(nbytes == 2);
	assert(memcmp(buf, "xy", 2) == 0);

	/*
	 * Close the references.
	 *
	 * Two references to one file object -- double check that.
	 */
	fcount = vault->file_count;

	fileobj_close(fref1);
	assert(vault->file_count == fcount);

	fileobj_close(fref2);
	assert(vault->file_count == --fcount);
}

static void
run_tests(const char *cipher)
{
	char *base_path = NULL;
	rvault_t *vault = mock_get_vault(cipher, &base_path);
	test_file_basic(vault);
	test_file_expand(vault);
	test_file_onebyte(vault);
	test_file_setsize(vault);
	test_file_refs(vault);
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
