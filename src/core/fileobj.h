/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_FILEOBJ_H_
#define	_FILEOBJ_H_

#define	FILEOBJ_INMEM	0x01	// data in-memory

/*
 * In-memory file object (think of a vnode).
 */
struct fileobj {
	rvault_t *	vault;
	unsigned	flags;
	int		fd;

	/* In-memory buffer and length. */
	unsigned char *	buf;
	size_t		len;

	/* Vault file-list entry. */
	LIST_ENTRY(fileobj) entry;
};

typedef struct fileobj fileobj_t;

fileobj_t *	fileobj_open(rvault_t *, const char *, int);
void		fileobj_close(fileobj_t *);
ssize_t		fileobj_pread(fileobj_t *, void *, size_t, off_t);
ssize_t		fileobj_pwrite(fileobj_t *, const void *, size_t, off_t);
size_t		fileobj_getsize(const fileobj_t *);
int		fileobj_setsize(fileobj_t *, size_t);

#endif
