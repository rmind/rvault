/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef	_BUFFER_H_
#define	_BUFFER_H_

/*
 * "Safe-buffer" API.
 */

typedef struct {
	void *	buf;		// buffer address
	size_t	buf_size;	// buffer (allocation) size
} sbuffer_t;

#define	SBUF_GROWEXP	0x01	// grow exponentially

void *	sbuffer_alloc(sbuffer_t *, size_t);
void *	sbuffer_move(sbuffer_t *, size_t, unsigned);
void	sbuffer_replace(sbuffer_t *, sbuffer_t *);
void	sbuffer_free(sbuffer_t *);

/*
 * LZ4 buffer compression.
 */

ssize_t	lz4_compress_buf(const void *, const size_t, sbuffer_t *);
ssize_t	lz4_decompress_buf(const void *, const size_t, sbuffer_t *);

#endif
