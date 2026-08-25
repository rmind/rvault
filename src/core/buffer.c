/*
 * Copyright (c) 2019-2026 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * Buffer management helpers.
 *
 * - The "secure" buffer (sbuffer_t) API takes extra care to erase the
 * data on destruction and abstracts buffer sizing/growing/shrinking.
 *
 * - Provides LZ4 compression routines for the buffers.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>

#if defined(USE_LZ4)
#include <lz4.h>
#endif

#include "rvault.h"
#include "storage.h"
#include "sys.h"
#include "utils.h"

/*
 * "Secure" buffer API.  Operates in page sizes.
 */

void *
sbuffer_alloc(sbuffer_t *sbuf, size_t len)
{
	void *buf;

	buf = safe_mmap(len, -1, MMAP_WRITEABLE);
	if (!buf) {
		return NULL;
	}
	sbuf->buf = buf;
	sbuf->buf_size = roundup2(len, sysconf(_SC_PAGESIZE));
	return buf;
}

size_t
sbuffer_get_size(const sbuffer_t *sbuf)
{
	ASSERT(sbuf->buf || sbuf->buf_size == 0);
	return sbuf->buf_size;
}

/*
 * sbuffer_move: "move" the buffer to a new size, if necessary, copying
 * over the contents to a new buffer (memory mapping).
 *
 * If SBUF_GROWEXP is set, then grow by page sizes exponentially.
 */
void *
sbuffer_move(sbuffer_t *sbuf, size_t newlen, unsigned flags)
{
	const size_t page_size = sysconf(_SC_PAGESIZE);
	size_t buf_nsize = roundup2(newlen, page_size);
	void *nbuf = NULL;

	/*
	 * If the new length is zero, then release the buffer.
	 * If the same number of pages, then nothing to do.
	 */
	if (buf_nsize == 0) {
		sbuffer_free(sbuf);
		return NULL;
	}
	if (sbuf->buf_size == buf_nsize) {
		return sbuf->buf;
	}

	// Shrink only if the new size is less than 50%.
	if ((sbuf->buf_size / buf_nsize) >= 2) {
		return sbuf->buf;
	}

	// Grow exponentially; check for overflow, though.
	if (buf_nsize > sbuf->buf_size && (flags & SBUF_GROWEXP) != 0) {
		buf_nsize = MAX(buf_nsize * 2, buf_nsize);
	}

	app_log(LOG_DEBUG, "%s: resizing sbuffer %p from [%zu] to [%zu]",
	    __func__, sbuf, sbuf->buf_size, buf_nsize);

	if ((nbuf = safe_mmap(buf_nsize, -1, MMAP_WRITEABLE)) == NULL) {
		return NULL;
	}
	if (sbuf->buf) {
		ASSERT(sbuf->buf_size > 0);
		memcpy(nbuf, sbuf->buf, MIN(sbuf->buf_size, newlen));
		safe_munmap(sbuf->buf, sbuf->buf_size, MMAP_ERASE);
	} else {
		ASSERT(sbuf->buf_size == 0);
	}
	sbuf->buf = nbuf;
	sbuf->buf_size = buf_nsize;
	return nbuf;
}

/*
 * sbuffer_replace: "replace" the destination buffer with the buffer from
 * the source.  The source buffer gets inherited, therefore it must not be
 * released sbuffer_free() again.
 *
 * This is to accommodate temporary buffers.
 */
void
sbuffer_replace(sbuffer_t *src, sbuffer_t *dst)
{
	if (dst->buf) {
		ASSERT(dst->buf_size > 0);
		sbuffer_free(dst);
	}
	memcpy(dst, src, sizeof(sbuffer_t));
}

void
sbuffer_free(sbuffer_t *sbuf)
{
	safe_munmap(sbuf->buf, sbuf->buf_size, MMAP_ERASE);
	sbuf->buf = NULL;
	sbuf->buf_size = 0;
}

/*
 * LZ4 buffer compression API.
 */

#if defined(USE_LZ4)

ssize_t
lz4_compress_buf(const void *inbuf, const size_t inlen, sbuffer_t *sbuf)
{
	ssize_t nbytes;
	size_t blen;
	void *buf;

	if (inlen > LZ4_MAX_INPUT_SIZE) {
		errno = EFBIG;
		return -1;
	}
	blen = LZ4_compressBound(inlen);
	if ((buf = sbuffer_alloc(sbuf, blen)) == NULL) {
		return -1;
	}
	nbytes = LZ4_compress_default(inbuf, buf, inlen, blen);
	if (nbytes <= 0) {
		app_log(LOG_ERR, "LZ4 compression failed");
		sbuffer_free(sbuf);
		errno = EBADMSG;
		return -1;
	}
	app_log(LOG_DEBUG, "compressed to %u%", (nbytes * 100) / inlen);
	return nbytes;
}

ssize_t
lz4_decompress_buf(const void *inbuf, const size_t inlen, sbuffer_t *sbuf)
{
	ssize_t nbytes;

	nbytes = LZ4_decompress_safe(inbuf, sbuf->buf, inlen, sbuf->buf_size);
	if (nbytes < 0) {
		errno = EBADMSG;
		return -1;
	}
	return nbytes;
}
#else

ssize_t
lz4_compress_buf(const void *, const size_t, sbuffer_t *)
{
	errno = ENOTSUP;
	return -1;
}

ssize_t
lz4_decompress_buf(const void *, const size_t, sbuffer_t *)
{
	errno = ENOTSUP;
	return -1;
}

#endif
