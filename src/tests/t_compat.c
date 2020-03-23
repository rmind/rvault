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
 * rvault create -n -c $cipher 8bba987f-28b7-417e-9e78-dd733dfc2879
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
	 * ABI v3
	 */
#if !defined(USE_AE_CIPHERS_ONLY)
	// AES 256 + CBC
	{
		.metadata =
		    "03 01 01 00 01 00 10 00 1c 20 8b ba 98 7f 28 b7"
		    "41 7e 9e 78 dd 73 3d fc 28 79 00 00 00 00 00 00"
		    "33 15 65 92 3d d2 df 71 fe af c5 77 79 25 65 a6"
		    "01 00 00 00 00 00 00 00 00 00 40 00 61 4d 00 20"
		    "89 e2 5e b1 46 e4 6f bd d7 7f 9a c7 98 e3 0d 97"
		    "65 25 02 b8 fe 3f 0d 02 97 b7 27 d7 22 72 04 0a"
		    "ac aa a7 7f 76 0b 3b 14 55 59 1a c3",
		.dir =
		    "RV:468de840f3446eeab8a54a9e50d4c85e:"
		    "95ffdda9d63bf410868c856387ae00d4"
		    "31c856464b2ced36ef8e8642ef1c3f06",
		.file =
		    "RV:fbb54e88ebfc9f12ec8850a296103a14:"
		    "cf4aea00340313a315e8fbdd528de6d3"
		    "bab7308cb778a879987c3690374bba12",
		.content =
		    "03 00 20 04 00 00 00 00 00 00 00 0c 00 00 00 00"
		    "00 00 00 00 00 00 00 00 5e 76 28 b5 00 00 00 00"
		    "67 b2 70 da 8b 2e 15 88 9a cf 25 32 91 bf b7 b4"
		    "f7 5d fe 8c 48 28 4f 11 67 47 60 83 e4 53 26 db"
		    "44 76 77 ea ed 3f 9a c4 f9 be 98 e3 e5 84 15 02",
	},
#endif
	// AES 256 + GCM
	{
		.metadata =
		    "03 01 02 00 01 00 0c 00 1c 20 8b ba 98 7f 28 b7"
		    "41 7e 9e 78 dd 73 3d fc 28 79 00 00 00 00 00 00"
		    "8c 62 27 22 bc 78 b7 fe e6 70 c0 a0 01 00 00 00"
		    "00 00 00 00 00 00 40 00 a2 e5 78 cb d4 8e b9 89"
		    "a9 82 3d 55 56 3a f5 27 0f 87 c9 44 90 61 f4 f1"
		    "15 2b 55 c3 13 c4 1c 38 ae 9b 35 1b 4a 8e 5a 33"
		    "5d 97 e5 97 2a cb 5a 98",
		.dir =
		    "RV:a94880:89cb5f5c5f4c63625236bf24f3daa3d6",
		.file =
		    "RV:b9448151e78ce56dbfb2bcc9ff2c:"
		    "daca131b5f5f8e2d3f8ae112348c10fd",
		.content =
		    "03 00 10 00 00 00 00 00 00 00 00 0c 00 00 00 00"
		    "00 00 00 00 00 00 00 00 5e 76 29 7e 00 00 00 00"
		    "31 60 6d 32 51 e3 02 ee 78 aa ee 2c c9 d5 c2 ad"
		    "be 4e 9f 40 e7 89 e3 6f ae fa e2 8d",
	},
	// Chacha20 + Poly1305
	{
		.metadata =
		    "03 01 04 00 01 00 0c 00 1c 20 8b ba 98 7f 28 b7"
		    "41 7e 9e 78 dd 73 3d fc 28 79 00 00 00 00 00 00"
		    "35 7e 47 03 2b d4 9a 51 87 53 c7 7e 01 00 00 00"
		    "00 00 00 00 00 00 40 00 75 32 b4 38 f3 91 20 db"
		    "be 4e 0f 69 54 19 c7 8f e8 3d 7b f7 4d 32 8d 98"
		    "81 dc 8b ef 4a 62 38 1a 35 c9 6b f6 9c 36 25 ea"
		    "8c 80 51 ff f7 1a 34 78",
		.dir =
		    "RV:9d6007:c00e7d6f355480d640252feaaf60a8fd",
		.file =
		    "RV:8d6c06c2b99f0f2bf67b60512b2f:"
		    "b3ffe41e1736afedd2f92b5194bbd8ca",
		.content =
		    "03 00 10 00 00 00 00 00 00 00 00 0c 00 00 00 00"
		    "00 00 00 00 00 00 00 00 5e 76 29 ed 00 00 00 00"
		    "43 be 59 db 00 87 76 93 63 23 98 7f fc a5 bc 63"
		    "8a 66 18 d3 b9 9a 09 29 e7 33 3e 15",
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
