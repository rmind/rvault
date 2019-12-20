/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_RVAULT_H_
#define	_RVAULT_H_

#include <sys/queue.h>
#include "crypto.h"

#define	APP_NAME		"rvault"
#define	APP_PROJ_VER		"0.1"

#define	APP_ABI_VER		1
#define	APP_META_FILE		"rvault.metadata"

struct fileobj;

typedef struct {
	char *			base_path;
	crypto_cipher_t		cipher;
	crypto_t *		crypto;
	LIST_HEAD(, fileobj)	file_list;
	unsigned		file_count;
} rvault_t;

int		rvault_init(const char *, const char *, const char *);
rvault_t *	rvault_open(const char *, const char *);
void		rvault_close(rvault_t *);

char *		rvault_resolve_path(rvault_t *, const char *, size_t *);
char *		rvault_resolve_vname(rvault_t *, const char *, size_t *);

#endif
