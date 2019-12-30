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

#define	RVAULT_ABI_VER		1
#define	RVAULT_META_FILE	"rvault.metadata"

#define	RVAULT_META_PREF	"rvault."
#define	RVAULT_META_PREFLEN	(sizeof(RVAULT_META_PREF) - 1)

struct fileobj;

typedef struct {
	char *			base_path;
	const char *		server_url;

	crypto_cipher_t		cipher;
	crypto_t *		crypto;
	uint8_t			uid[16];

	LIST_HEAD(, fileobj)	file_list;
	unsigned		file_count;
} rvault_t;

#define	RVAULT_FLAG_NOAUTH	(1U << 0)	// authentication disabled

int		rvault_init(const char *, const char *, const char *,
		    const char *, const char *, unsigned);
rvault_t *	rvault_open(const char *, const char *, const char *);
void		rvault_close(rvault_t *);

int		rvault_key_set(rvault_t *);
int		rvault_key_get(rvault_t *);
int		rvault_unhex_aedata(const char *, void **, size_t *,
		    void **, size_t *);

struct dirent;
typedef void (*dir_iter_t)(void *, const char *, struct dirent *);

int		rvault_iter_dir(rvault_t *, const char *, void *, dir_iter_t);
char *		rvault_resolve_path(rvault_t *, const char *, size_t *);
char *		rvault_resolve_vname(rvault_t *, const char *, size_t *);

#endif
