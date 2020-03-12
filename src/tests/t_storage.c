/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
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
test_corrupted(rvault_t *vault)
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
run_tests(const char *cipher)
{
	char *base_path = NULL;
	rvault_t *vault = mock_get_vault(cipher, &base_path);
	test_basic(vault);
	test_corrupted(vault);
	mock_cleanup_vault(vault, base_path);
}

int
main(void)
{
	app_setlog(LOG_CRIT);
	run_tests("aes-256-cbc");
	run_tests("chacha20");
	run_tests("aes-256-gcm");
	run_tests("chacha20-poly1305");

	puts("ok");
	return 0;
}
