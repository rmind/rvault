/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "rvault.h"
#include "fileobj.h"
#include "storage.h"
#include "crypto.h"
#include "sys.h"
#include "mock.h"
#include "utils.h"

/*
 * rvault create -n -c $crypto 8bba987f-28b7-417e-9e78-dd733dfc2879
 *
 * cd mounted-vault && mkdir dir && printf "some-content" > dir/test-file-0001
 */

static const struct test_case {
	const char *	metadata;
	const char *	dir;
	const char *	file;
	const char *	content;
} test_cases[] = {
	/*
	 * ABI v2
	 */

	// AES 256 + CBC
	{
		.metadata =
		    "02 01 01 1c 00 10 00 00 8b ba 98 7f 28 b7 41 7e"
		    "9e 78 dd 73 3d fc 28 79 08 e2 b9 7c 74 bd 33 54"
		    "13 04 26 93 aa be ae f5 01 00 00 00 00 00 00 00"
		    "00 00 40 00 ac 6c 5a 25 dd d5 d3 3d 61 a3 19 21"
		    "63 40 a2 fc cf 6f 21 32 b2 ec 38 62 44 b6 6d 0e"
		    "22 9c 35 5e ef c1 68 d6 9a ca 6a db b6 10 b3 4a"
		    "3c 3b 6d 94",
		.dir =
		    "RV:ed71f82229703c106e0014955e3900ea",
		.file =
		    "RV:672d37b1baec141763258e22d18893ab",
		.content =
		    "02 01 20 04 00 00 00 00 00 00 00 10 00 00 00 00"
		    "05 e1 00 a5 ec fe 7e 95 96 9a ac 2e 4e 98 53 cb"
		    "9b 79 c1 0c 96 92 1d cb 17 fd c9 05 b7 dc c9 21"
		    "a5 37 9c bc f6 bf 4d a6 88 38 82 3a 1b 12 8d bf",
	},
	// AES 256 + GCM
	{
		.metadata =
		    "02 02 01 1c 00 0c 00 00 8b ba 98 7f 28 b7 41 7e"
		    "9e 78 dd 73 3d fc 28 79 95 55 e6 46 21 4c f6 9d"
		    "36 82 c6 da 01 00 00 00 00 00 00 00 00 00 40 00"
		    "e2 87 fe 0c fe a0 ad 5c 14 4f 64 f8 99 a0 ae e6"
		    "a4 e7 f1 e0 50 21 df 94 23 84 24 13 5a b2 ed a4"
		    "4e ee 75 71 11 ed 83 d7 cf 92 5b fc 6f 77 b3 89",
		.dir =
		    "RV:bd6f37:874b8c52a9c350082acea53d65f5c9f1",
		.file =
		    "RV:ad63368f5d0ea2b0eae13fb66aaf:"
		    "4569d82c334629222226822a9a122b40",
		.content =
		    "02 02 10 00 00 00 00 00 00 00 00 0c 00 00 00 00"
		    "aa 69 28 9e 5d 0b a4 b2 fb a9 61 f2 62 42 09 8a"
		    "b1 11 0a bc f9 53 5d 14 80 c2 4f fa",
	},
	// Chacha20 + Poly1305
	{
		.metadata =
		    "02 04 01 1c 00 0c 00 00 8b ba 98 7f 28 b7 41 7e"
		    "9e 78 dd 73 3d fc 28 79 03 be 5a a3 52 4a 2e 6d"
		    "78 fc fe de 01 00 00 00 00 00 00 00 00 00 40 00"
		    "83 2d a5 12 a6 65 e7 27 51 2c bc fa 51 ab 38 68"
		    "c9 60 7d ba d0 50 8c b8 2a b9 2d a0 cf 2c 84 90"
		    "d7 11 cb 7c 7f 79 72 ac 07 50 6d 85 8c f2 11 4b",
		.dir =
		    "RV:f7f6e1:4b55cb97d19524b06caea20a175886f9",
		.file =
		    "RV:e7fae088fabe78a93fc761709768:"
		    "a854460567c95aada1efba7cf40c958a",
		.content =
		    "02 04 10 00 00 00 00 00 00 00 00 0c 00 00 00 00"
		    "e0 f0 fe 99 fa bb 7e ab 2e 8f 3f 34 87 b2 a5 b4"
		    "b4 c4 04 e9 9c 30 7a 7d f1 2c 25 a5",
	},
};

///////////////////////////////////////////////////////////////////////////////

static void
test_rvault_verify(const char *base_path)
{
	const char exp_content[] = "some-content";
	const ssize_t exp_content_len = sizeof(exp_content) - 1;
	rvault_t *vault;
	fileobj_t *fobj;
	ssize_t nbytes;
	char buf[512];

	/*
	 * Attempt to open the vault.
	 */
	vault = rvault_open(base_path, NULL, "test");
	assert(vault != NULL);

	/*
	 * Attempt to read the file in the directory.
	 */
	fobj = fileobj_open(vault, "/dir/test-file-0001", O_RDONLY, FOBJ_OMASK);
	assert(fobj != NULL);

	nbytes = fileobj_pread(fobj, buf, sizeof(buf), 0);
	assert(nbytes == exp_content_len);
	assert(strncmp(buf, exp_content, exp_content_len) == 0);
	fileobj_close(fobj);

	rvault_close(vault);
}

static void
test_rvault_compat(const char *meta, const char *dir,
    const char *file, const char *content)
{
	char path[PATH_MAX], *base_path = mock_get_vault_dir();
	size_t buf_len;
	ssize_t nbytes;
	void *buf;
	int fd, ret;

	snprintf(path, sizeof(path) - 1, "%s/"RVAULT_META_FILE, base_path);
	fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
	assert(fd != -1);

	/*
	 * Write the metadata file.
	 */
	buf = hex_readmem_arbitrary(meta, strlen(meta), &buf_len);
	assert(buf != NULL);

	nbytes = fs_write(fd, buf, buf_len);
	assert(nbytes == (ssize_t)buf_len);

	free(buf);
	close(fd);

	/*
	 * Create the directory, file and write the contents.
	 */
	snprintf(path, sizeof(path) - 1, "%s/%s", base_path, dir);
	ret = mkdir(path, 0755);
	assert(ret == 0);

	snprintf(path, sizeof(path) - 1, "%s/%s/%s", base_path, dir, file);
	fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
	assert(fd != -1);

	buf = hex_readmem_arbitrary(content, strlen(content), &buf_len);
	assert(buf);

	nbytes = fs_write(fd, buf, buf_len);
	assert(nbytes == (ssize_t)buf_len);

	free(buf);
	close(fd);

	/*
	 * Verify the vault.
	 */
	test_rvault_verify(base_path);
	mock_cleanup_vault_dir(base_path);
}

int
main(void)
{
	for (unsigned i = 0; i < __arraycount(test_cases); i++) {
		const struct test_case *t = &test_cases[i];
		test_rvault_compat(t->metadata, t->dir, t->file, t->content);
	}
	puts("ok");
	return 0;
}
