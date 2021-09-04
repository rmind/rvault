/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_RVAULT_H_
#define	_RVAULT_H_

#include <stdio.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <rhashmap.h>

#include "crypto.h"

#define	APP_NAME		"rvault"
#define	APP_PROJ_VER		"0.4"

struct fileobj;

typedef struct {
	char *			base_path;
	const char *		server_url;
	bool			weak_sync;
	bool			compress;

	crypto_cipher_t		cipher;
	crypto_hmac_t		hmac_id;
	crypto_t *		crypto;
	uint8_t			uid[16];

	LIST_HEAD(, fileobj)	file_list;
	unsigned		file_count;
	rhashmap_t *		file_map;
} rvault_t;

void *		open_metadata_mmap(const char *, char **, size_t *);

int		rvault_init(const char *, const char *, const char *,
		    const char *, const char *, const char *, unsigned);
rvault_t *	rvault_open(const char *, const char *, const char *);
rvault_t *	rvault_open_ekey(const char *, const char *);
void		rvault_close(rvault_t *);

int		rvault_push_key(rvault_t *);
int		rvault_pull_key(rvault_t *);
int		rvault_unhex_aedata(const char *, void **, size_t *,
		    void **, size_t *);

struct dirent;
typedef void (*dir_iter_t)(void *, const char *, struct dirent *);

int		rvault_iter_dir(rvault_t *, const char *, void *, dir_iter_t);
char *		rvault_resolve_path(rvault_t *, const char *, size_t *);
char *		rvault_resolve_vname(rvault_t *, const char *, size_t *);

#endif
