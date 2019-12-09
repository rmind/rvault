/*
 * Copyright (c) 2016 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_SYS_H_
#define	_SYS_H_

#ifndef O_SYNC
#define	O_SYNC		0	// Darwin
#endif

ssize_t		fs_block_size(const char *);
ssize_t		fs_file_size(int);
ssize_t		fs_read(int, void *, size_t);
ssize_t		fs_write(int, const void *, size_t);
int		fs_sync_path(const char *);

typedef enum {
	MMAP_WRITEABLE	= 0x1,
	MMAP_ERASE	= 0x2,
} mmap_flag_t;

void *		safe_mmap(size_t, int, mmap_flag_t);
void		safe_munmap(void *, size_t, mmap_flag_t);

#endif
