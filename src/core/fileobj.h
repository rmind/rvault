/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_FILEOBJ_H_
#define	_FILEOBJ_H_

struct fileobj;
typedef struct fileobj fileobj_t;

fileobj_t *	fileobj_open(rvault_t *, const char *, int);
void		fileobj_close(fileobj_t *);
ssize_t		fileobj_pread(fileobj_t *, void *, size_t, off_t);
ssize_t		fileobj_pwrite(fileobj_t *, const void *, size_t, off_t);
size_t		fileobj_getsize(const fileobj_t *);
int		fileobj_setsize(fileobj_t *, size_t);
int		fileobj_stat(const fileobj_t *, struct stat *);

#endif
