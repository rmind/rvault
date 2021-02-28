/*
 * Copyright (c) 2019-2021 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_SDB_H_
#define	_SDB_H_

typedef struct sdb sdb_t;

sdb_t *	sdb_open(rvault_t *);
int	sdb_sync(rvault_t *, sdb_t *);
void	sdb_close(sdb_t *);

typedef void (*sdb_query_cb_t)(void *, const char *);

int	sdb_query(sdb_t *, sdb_query_cb_t, void *,
	    const char *, unsigned, const char **);

#endif
