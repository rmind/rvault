/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_FILEOBJ_H_
#define	_FILEOBJ_H_

struct fileobj;
typedef struct fileobj fileobj_t;

enum { FOBJ_WRITEBACK, FOBJ_FULLSYNC };

#define	FOBJ_OMASK	0644	// default file mask

fileobj_t *	fileobj_open(rvault_t *, const char *, int, mode_t);
void		fileobj_close(fileobj_t *);
ssize_t		fileobj_pread(fileobj_t *, void *, size_t, off_t);
ssize_t		fileobj_pwrite(fileobj_t *, const void *, size_t, off_t);
int		fileobj_sync(fileobj_t *, int);
size_t		fileobj_getsize(fileobj_t *);
int		fileobj_setsize(fileobj_t *, size_t);

int		fileobj_stat(rvault_t *, const char *, struct stat *);

#endif
