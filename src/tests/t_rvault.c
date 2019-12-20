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
#include "utils.h"
#include "mock.h"

static void
test_basic(void)
{
	char *base_path = get_vault_dir();
	char *passphrase = strdup("test");
	rvault_t *vault;
	int ret;

	ret = rvault_init(base_path, passphrase,
	    "aes-256-cbc", RVAULT_FLAG_NOAUTH);
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

	ret = rvault_init(base_path, "not-test",
	    "aes-256-cbc", RVAULT_FLAG_NOAUTH);
	assert(ret == 0);

	vault = rvault_open(base_path, passphrase);
	assert(vault == NULL);

	cleanup_vault_dir(base_path);
	free(passphrase);
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
	app_setlog(LOG_ERR);
	test_basic();
	test_invalid_passphrase();
	test_paths();

	puts("ok");
	return 0;
}
