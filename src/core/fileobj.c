/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>

#include "rvault.h"
#include "fileobj.h"
#include "storage.h"
#include "crypto.h"
#include "sys.h"
#include "utils.h"

static int	fileobj_dataload(fileobj_t *);

fileobj_t *
fileobj_open(rvault_t *vault, const char *path, int flags)
{
	fileobj_t *fobj;

	if ((fobj = calloc(1, sizeof(fileobj_t))) == NULL) {
		return NULL;
	}
	fobj->vault = vault;
	LIST_INSERT_HEAD(&vault->file_list, fobj, entry);
	vault->file_count++;

	/*
	 * Open the data file.
	 */
	fobj->fd = open(path, flags, 0600);
	if (fobj->fd == -1) {
		fileobj_close(fobj);
		return NULL;
	}
	if (fileobj_dataload(fobj) == -1) {
		fileobj_close(fobj);
		return NULL;
	}
	app_log(LOG_DEBUG, "%s: %p data size %zu", __func__, fobj, fobj->len);
	return fobj;
}

static int
fileobj_dataload(fileobj_t *fobj)
{
	ssize_t flen;

	if (fobj->flags & FILEOBJ_INMEM) {
		return 0;
	}
	if ((flen = fs_file_size(fobj->fd)) == -1) {
		return -1;
	}

	/*
	 * Initial load of the data into the memory.
	 * Note: may return an empty buffer (if zero size)
	 */
	fobj->buf = storage_read_data(fobj->vault, fobj->fd, flen, &fobj->len);
	ASSERT(fobj->buf || fobj->len == 0);
	fobj->flags |= FILEOBJ_INMEM;
	return 0;
}

void
fileobj_close(fileobj_t *fobj)
{
	rvault_t *vault = fobj->vault;

	/* Remove itself from the file list. */
	LIST_REMOVE(fobj, entry);
	ASSERT(vault->file_count > 0);
	vault->file_count--;

	if (fobj->buf) {
		ASSERT(fobj->len > 0);
		sbuffer_free(fobj->buf, fobj->len);
	}
	if (fobj->fd > 0) {
		close(fobj->fd);
	}
	free(fobj);
}

ssize_t
fileobj_pread(fileobj_t *fobj, void *buf, size_t len, off_t offset)
{
	ssize_t nbytes;

	if (fobj->buf == NULL) {
		return 0;
	}
	if (offset >= (off_t)fobj->len) {
		return 0;
	}
	nbytes = MIN(fobj->len - offset, len);
	memcpy(buf, &fobj->buf[offset], nbytes);

	app_log(LOG_DEBUG, "%s: file %p, read [%jd:%zu] -> %zd",
	    __func__, fobj, (intmax_t)offset, len, nbytes);
	return (size_t)nbytes;
}

ssize_t
fileobj_pwrite(fileobj_t *fobj, const void *buf, size_t len, off_t offset)
{
	uint64_t endoff;
	ssize_t nbytes;

	endoff = offset + len;
	if (endoff < (uint64_t)offset) {
		/* Overflow. */
		errno = EINVAL;
		return -1;
	}

	/*
	 * Expand the memory buffer.
	 */
	if (endoff > fobj->len) {
		void *nbuf;

		nbuf = sbuffer_move(fobj->buf, fobj->len, endoff);
		if (nbuf == 0) {
			errno = ENOMEM;
			return -1;
		}
		fobj->buf = nbuf;
		fobj->len = endoff;
	}
	ASSERT(fobj->buf != NULL);

	/* Write the data. */
	nbytes = fobj->len - offset;
	memcpy(&fobj->buf[offset], buf, nbytes);

	/*
	 * Sync back the encrypted object.
	 */
	if (storage_write_data(fobj->vault, fobj->fd,
	    fobj->buf, fobj->len) == -1) {
		errno = EIO; // XXX
		return -1;
	}

	app_log(LOG_DEBUG, "%s: file %p, write [%jd:%zu] -> %zd",
	    __func__, fobj, (intmax_t)offset, len, nbytes);
	return (size_t)nbytes;
}

size_t
fileobj_getsize(const fileobj_t *fobj)
{
	ASSERT(fobj->buf || fobj->len == 0);
	app_log(LOG_DEBUG, "%s: file %p, size %zu", __func__, fobj, fobj->len);
	return fobj->len;
}

int
fileobj_setsize(fileobj_t *fobj, size_t len)
{
	void *buf;

	if (len == 0) {
		sbuffer_free(fobj->buf, fobj->len);
		buf = NULL;
		goto out;
	}
	if ((buf = sbuffer_move(fobj->buf, fobj->len, len)) == NULL) {
		return -1;
	}
out:
	fobj->buf = buf;
	fobj->len = len;

	app_log(LOG_DEBUG, "%s: file %p, size %zu", __func__, fobj, fobj->len);
	return 0;
}
