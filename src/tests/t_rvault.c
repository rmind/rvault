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
#include <limits.h>
#include <assert.h>

#include "rvault.h"
#include "recovery.h"
#include "utils.h"
#include "mock.h"
#include "sys.h"

static void
test_basic(void)
{
	char *base_path = mock_get_vault_dir();
	char *passphrase = strdup("test");
	rvault_t *vault;
	int ret;

	ret = rvault_init(base_path, NULL, passphrase, TEST_UUID,
	    "aes-256-cbc", RVAULT_FLAG_NOAUTH);
	assert(ret == 0);

	vault = rvault_open(base_path, NULL, passphrase);
	assert(vault != NULL);
	rvault_close(vault);

	mock_cleanup_vault_dir(base_path);
	free(passphrase);
}

static void
test_invalid_passphrase(void)
{
	char *base_path = mock_get_vault_dir();
	char *passphrase = strdup("test");
	rvault_t *vault;
	int ret;

	ret = rvault_init(base_path, NULL, "not-test", TEST_UUID,
	    "aes-256-cbc", RVAULT_FLAG_NOAUTH);
	assert(ret == 0);

	vault = rvault_open(base_path, NULL, passphrase);
	assert(vault == NULL);

	mock_cleanup_vault_dir(base_path);
	free(passphrase);
}

static void
test_recovery(void)
{
	char *base_path = NULL, *buf = NULL, *recovery = NULL;
	rvault_t *vault;
	size_t len = 0;
	FILE *fp;
	int fd;

	/* Create a vault and export the recovery data. */
	fp = open_memstream(&buf, &len);
	vault = mock_get_vault("aes-256-gcm", &base_path);
	mock_vault_fwrite(vault, "/some-file", "arbitrary data");
	rvault_recovery_export(vault, fp);
	rvault_close(vault);
	fclose(fp);

	/* Write the recovery key to the temporary file. */
	fd = mock_get_tmpfile(&recovery);
	fs_write(fd, buf, len);
	close(fd);
	free(buf);

	/* Open the vault with the recovery file. */
	vault = rvault_open_ekey(base_path, recovery);
	assert(vault != NULL);

	/* Verify the file. */
	mock_vault_fcheck(vault, "/some-file", "arbitrary data");
	mock_cleanup_vault(vault, base_path);

	unlink(recovery);
	free(recovery);
}

static void
test_paths(void)
{
	static const struct {
		const char *		path;
		const char *		expected;
	} test_paths[] = {
		{ "a",			"/a"		},
		{ "a/..",		"/"		},
		{ ".",			"/"		},
		{ "./",			"/"		},
		{ "/./.",		"/"		},
		{ "/",			"/"		},
		{ "///",		"/"		},
		{ "..",			"/"		},
		{ "../",		"/"		},
		{ "/../",		"/"		},
		{ "../a",		"/a"		},
		{ "/../a",		"/a"		},
		{ "/./a/./..",		"/"		},

		{ "/a/b/",		"/a/b"		},
		{ "/a/b",		"/a/b"		},

		{ "/a/b/c/d/e",		"/a/b/c/d/e"	},
		{ "/a/./c/d/.",		"/a/c/d"	},
		{ "/a/.././c/d/",	"/c/d"		},

		{ "/../a/b",		"/a/b"		},
		{ "/a..a/b.c",		"/a..a/b.c"	},
		{ "/a..a/../b.c",	"/b.c"		},
		{ "/x.x/../test.txt",	"/test.txt"	},
		{ "/./a/..//../../.b.",	"/.b."		},
		{ "/./a/b//../../c",	"/a/c"		},
	};
	const char test_pref_path[] = "/tmp/rvault-test";
	const size_t test_pref_path_len = sizeof(test_pref_path) - 1;
	rvault_t vault;

	memset(&vault, 0, sizeof(rvault_t)); // dummy
	vault.base_path = strdup(test_pref_path);

	for (unsigned i = 0; i < __arraycount(test_paths); i++) {
		char *path, *p;
		size_t len;

		path = rvault_resolve_path(&vault, test_paths[i].path, &len);
		ASSERT(path && strlen(path) == len);

		ASSERT(strncmp(path, test_pref_path, test_pref_path_len) == 0);
		p = path + test_pref_path_len;
		ASSERT(strcmp(p, test_paths[i].expected) == 0);

		free(path);
	}
	free(vault.base_path);
}

int
main(void)
{
	app_setlog(0);
	test_basic();
	test_recovery();
	test_invalid_passphrase();
	test_paths();
	puts("ok");
	return 0;
}
