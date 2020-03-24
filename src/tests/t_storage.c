/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <assert.h>

#include "rvault.h"
#include "storage.h"
#include "sys.h"
#include "mock.h"

static void
test_basic(rvault_t *vault)
{
	const int fd = mock_get_tmpfile(NULL);
	ssize_t nbytes, file_len, len;
	sbuffer_t sbuf;

	vault->compress = false;
	nbytes = storage_write_data(vault, fd, TEST_TEXT, TEST_TEXT_LEN);
	assert(nbytes > 0);

	file_len = fs_file_size(fd);
	assert(file_len == nbytes);

	memset(&sbuf, 0, sizeof(sbuffer_t));
	len = storage_read_data(vault, fd, file_len, &sbuf);
	assert(len == TEST_TEXT_LEN);

	assert(strncmp(sbuf.buf, TEST_TEXT, TEST_TEXT_LEN) == 0);
	sbuffer_free(&sbuf);

	close(fd);
}

static void
test_corrupted_data(rvault_t *vault)
{
	const int fd = mock_get_tmpfile(NULL);
	ssize_t nbytes, file_len, len;
	sbuffer_t sbuf;

	nbytes = storage_write_data(vault, fd, TEST_TEXT, TEST_TEXT_LEN);
	file_len = fs_file_size(fd);
	assert(nbytes > 0 && file_len == nbytes);

	mock_corrupt_byte_at(fd, file_len - 1, NULL);

	memset(&sbuf, 0, sizeof(sbuffer_t));
	len = storage_read_data(vault, fd, file_len, &sbuf);
	assert(len == -1);
	close(fd);
}

static void
test_corrupted_aetag(rvault_t *vault)
{
	const int fd = mock_get_tmpfile(NULL);
	ssize_t nbytes, file_len, len;
	sbuffer_t sbuf;
	unsigned off;

	nbytes = storage_write_data(vault, fd, TEST_TEXT, TEST_TEXT_LEN);
	file_len = fs_file_size(fd);
	assert(nbytes > 0 && file_len == nbytes);

	off = (uintptr_t)FILEOBJ_HDR_TO_AETAG((uintptr_t)0);
	mock_corrupt_byte_at(fd, off, NULL);

	memset(&sbuf, 0, sizeof(sbuffer_t));
	len = storage_read_data(vault, fd, file_len, &sbuf);
	assert(len == -1);
	close(fd);
}

#if defined(USE_LZ4)

#define	TEST_CTEXT	"test test test test test ...................."
#define	TEST_CTEXT_LEN	(sizeof(TEST_CTEXT) - 1)

static void
test_compression(rvault_t *vault)
{
	const int fd = mock_get_tmpfile(NULL);
	ssize_t nbytes, file_len, len;
	sbuffer_t sbuf;

	vault->compress = true;
	nbytes = storage_write_data(vault, fd, TEST_CTEXT, TEST_CTEXT_LEN);
	assert(nbytes > 0);

	file_len = fs_file_size(fd);
	assert(file_len == nbytes);

	memset(&sbuf, 0, sizeof(sbuffer_t));
	len = storage_read_data(vault, fd, file_len, &sbuf);
	assert(len == TEST_CTEXT_LEN);

	assert(strncmp(sbuf.buf, TEST_CTEXT, TEST_CTEXT_LEN) == 0);
	sbuffer_free(&sbuf);

	close(fd);
}
#else
#define	test_compression(v)
#endif

static void
run_tests(const char *cipher)
{
	char *base_path = NULL;
	rvault_t *vault = mock_get_vault(cipher, &base_path);
	test_basic(vault);
	test_corrupted_data(vault);
	test_corrupted_aetag(vault);
	test_compression(vault);
	mock_cleanup_vault(vault, base_path);
}

int
main(void)
{
	const char **ciphers;
	unsigned nitems = 0;

	app_setlog(LOG_CRIT);

	ciphers = crypto_cipher_list(&nitems);
	for (unsigned i = 0; i < nitems; i++) {
		const char *cipher = ciphers[i];
		run_tests(cipher);
	}
	puts("ok");
	return 0;
}
