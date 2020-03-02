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

/*
 * rvault create -n -c aes-256-gcm 8bba987f-28b7-417e-9e78-dd733dfc2879
 */
static const char *rvault_v2_metadata =
    "02 02 01 1c 00 0c 00 00 8b ba 98 7f 28 b7 41 7e"
    "9e 78 dd 73 3d fc 28 79 ea 6b e3 47 47 d4 0e 9c"
    "5b da 19 53 01 00 00 00 00 00 00 00 00 00 40 00"
    "6a 05 71 52 79 10 39 c8 db e1 6f d6 d9 a1 10 b9"
    "3e 57 d5 37 b9 47 49 a5 6f 1b ef 3d 3c 85 bc 78"
    "8c 02 db fc 43 db f8 f5 1b 11 80 93 1c 79 71 03";

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
	test_rvault_compat(rvault_v2_metadata);
	puts("ok");
	return 0;
}
