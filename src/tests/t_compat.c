/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "rvault.h"
#include "storage.h"
#include "crypto.h"
#include "sys.h"
#include "mock.h"
#include "utils.h"

static const char *rvault_v1_metadata =
    "01 01 01 1c 00 10 6d 2f 2e 03 dd 71 41 29 85 ab"
    "d5 e3 eb 3b 3e 47 00 00 f6 e9 26 4b bb b5 19 63"
    "d4 0a 2f 81 77 1c 3f c3 01 00 00 00 00 00 00 00"
    "00 00 40 00 ab 57 19 47 fe e3 bd eb 19 e3 71 ec"
    "4c 7f fd fd 5f 43 25 03 a3 db e5 1b a0 a5 83 45"
    "73 c7 21 44 b3 1e 5d 8a ce 98 e5 d0 9b 44 23 f2"
    "7d 6e 6c be";

///////////////////////////////////////////////////////////////////////////////

static void
test_rvault_compat(const char *meta)
{
	char path[PATH_MAX], *base_path = mock_get_vault_dir();
	void *buf_meta;
	size_t buf_len;
	rvault_t *vault;
	int fd, nbytes;

	snprintf(path, sizeof(path) - 1, "%s/"RVAULT_META_FILE, base_path);
	fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
	assert(fd != -1);

	/*
	 * Write the metadata file.
	 */
	buf_meta = hex_readmem_arbitrary(meta, strlen(meta), &buf_len);
	assert(buf_meta != NULL);

	nbytes = fs_write(fd, buf_meta, buf_len);
	assert(nbytes == (ssize_t)buf_len);

	free(buf_meta);
	close(fd);

	/*
	 * Attempt to open the vault.
	 */
	vault = rvault_open(base_path, NULL, "test");
	assert(vault != NULL);
	rvault_close(vault);

	mock_cleanup_vault_dir(base_path);
}

int
main(void)
{
	test_rvault_compat(rvault_v1_metadata);
	puts("ok");
	return 0;
}
