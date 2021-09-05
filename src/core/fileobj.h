/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_FILEOBJ_H_
#define	_FILEOBJ_H_

struct fileref;
typedef struct fileref fileref_t;

struct fileobj;
typedef struct fileobj fileobj_t;

enum { FOBJ_WRITEBACK, FOBJ_FULLSYNC };

#define	FOBJ_OMASK	0644	// default file mask

fileref_t *	fileobj_open(rvault_t *, const char *, int, mode_t);
void		fileobj_close(fileref_t *);
ssize_t		fileobj_pread(fileref_t *, void *, size_t, off_t);
ssize_t		fileobj_pwrite(fileref_t *, const void *, size_t, off_t);
int		fileobj_sync(fileref_t *, int);
size_t		fileobj_getsize(fileref_t *);
int		fileobj_setsize(fileref_t *, size_t);

int		fileobj_stat(rvault_t *, const char *, struct stat *);

void		fileobj_close_full(fileobj_t *);

#endif
