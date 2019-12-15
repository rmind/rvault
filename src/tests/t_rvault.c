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
#include "mock.h"

static void
test_basic(void)
{
	char *base_path = get_vault_dir();
	char *passphrase = strdup("test");
	rvault_t *vault;
	int ret;

	ret = rvault_init(base_path, passphrase, "aes-256-cbc");
	assert(ret == 0);

	vault = rvault_open(base_path, passphrase);
	assert(vault != NULL);
	rvault_close(vault);

	cleanup_vault_dir(base_path);
	free(passphrase);
}

static void
test_invalid_passphrase(void)
{
	char *base_path = get_vault_dir();
	char *passphrase = strdup("test");
	rvault_t *vault;
	int ret;

	ret = rvault_init(base_path, "not-test", "aes-256-cbc");
	assert(ret == 0);

	vault = rvault_open(base_path, passphrase);
	assert(vault == NULL);

	cleanup_vault_dir(base_path);
	free(passphrase);
}

int
main(void)
{
	test_basic();
	test_invalid_passphrase();
	return 0;
}
