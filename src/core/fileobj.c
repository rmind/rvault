/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <sys/queue.h>
#include <sys/stat.h>
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

/*
 * In-memory file object (think of a vnode).
 */
struct fileobj {
	rvault_t *	vault;
	unsigned	flags;
	int		fd;

	char *		vpath;
	size_t		pathlen;

	/* In-memory buffer and length. */
	unsigned char *	buf;
	size_t		len;

	/* Vault file-list entry. */
	LIST_ENTRY(fileobj) entry;
};

#define	FILEOBJ_INMEM	0x01	// data in-memory
#define	FILEOBJ_DIRTY	0x02	// data needs to be synced

static int	fileobj_dataload(fileobj_t *);

fileobj_t *
fileobj_open(rvault_t *vault, const char *path, int flags, mode_t mode)
{
	fileobj_t *fobj;

	if ((fobj = calloc(1, sizeof(fileobj_t))) == NULL) {
		return NULL;
	}
	fobj->vpath = rvault_resolve_path(vault, path, &fobj->pathlen);
	if (!fobj->vpath) {
		free(fobj);
		return NULL;
	}
	fobj->vault = vault;
	LIST_INSERT_HEAD(&vault->file_list, fobj, entry);
	vault->file_count++;

	/*
	 * Open the data file.
	 */
	fobj->fd = open(fobj->vpath, flags, mode);
	if (fobj->fd == -1) {
		fileobj_close(fobj);
		return NULL;
	}
	app_log(LOG_DEBUG, "%s: vnode %p, data size %zu, vpath [%s]",
	    __func__, fobj, fobj->len, fobj->vpath);
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
		app_elog(LOG_DEBUG, "%s: fs_file_size() failed", __func__);
		return -1;
	}
	if (flen == 0) {
		fobj->flags |= FILEOBJ_INMEM;
		return 0;
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

/*
 * fileobj_sync: sync the data to the backing store.
 */
int
fileobj_sync(fileobj_t *fobj)
{
	rvault_t *vault = fobj->vault;
	char *fpath;
	int fd, e;

	/*
	 * Check if there is anything to sync.
	 */
	if ((fobj->flags & FILEOBJ_DIRTY) == 0) {
		return 0;
	}

	/*
	 * If truncating, then just wipe the whole file.
	 */
	if (!fobj->buf) {
		ASSERT(fobj->len == 0);
		return ftruncate(fobj->fd, 0);
	}

	/*
	 * Create a temporary file.
	 */
	if ((fpath = tmpfile_get_name(fobj->vpath)) == NULL) {
		return -1;
	}
	if ((fd = open(fpath, O_CREAT | O_EXCL | O_RDWR, FOBJ_OMASK)) == -1) {
		app_elog(LOG_ERR, "%s: open() at `%s' failed", __func__, fpath);
		free(fpath);
		return -1;
	}

	/*
	 * Sync back the encrypted store.
	 *
	 * Note: must sync the directory too.
	 */
	if (storage_write_data(vault, fd, fobj->buf, fobj->len) == -1) {
		app_elog(LOG_DEBUG, "%s: storage_write_data() failed", __func__);
		errno = EIO;
		goto err;
	}
	if (rename(fpath, fobj->vpath) == -1) {
		app_elog(LOG_ERR, "%s: rename() failed", __func__);
		goto err;
	}
	fs_sync(fd, fobj->vpath);
	free(fpath);

	/*
	 * Update the file descriptor; mark the object as no longer dirty.
	 */
	fobj->flags &= ~FILEOBJ_DIRTY;
	close(fobj->fd);
	fobj->fd = fd;

	return 0;
err:
	e = errno;
	if (fpath) {
		unlink(fpath);
		free(fpath);
	}
	close(fd);
	errno = e;
	return -1;
}

int
fileobj_stat(rvault_t *vault, const char *path, struct stat *st)
{
	int fd, ret = -1;
	char *vpath;

	if ((vpath = rvault_resolve_path(vault, path, NULL)) == NULL) {
		return -1;
	}
	if ((fd = open(vpath, O_RDONLY)) == -1) {
		app_log(LOG_DEBUG, "%s: open `%s' failed", __func__, vpath);
		free(vpath);
		return -1;
	}
	free(vpath);

	if (fstat(fd, st) == -1) {
		app_log(LOG_DEBUG, "%s: fstat `%s' failed", __func__, vpath);
		goto err;
	}

	/*
	 * We support only directories and regular files.
	 */
	if (((st->st_mode & S_IFMT) & ~(S_IFDIR | S_IFREG)) != 0) {
		errno = ENOENT;
		goto err;
	}

	/*
	 * Regular and non-empty files are encrypted.
	 */
	if ((st->st_mode & S_IFMT) == S_IFREG && st->st_size > 0) {
		ssize_t size;

		if ((size = storage_read_length(vault, fd)) == -1) {
			goto err;
		}
		st->st_size = size;
	}
	app_log(LOG_DEBUG, "%s: path `%s', size %zu",
	    __func__, path, st->st_size);
	ret = 0;
err:
	close(fd);
	return ret;
}

void
fileobj_close(fileobj_t *fobj)
{
	rvault_t *vault = fobj->vault;
	unsigned retry = 3;

	app_log(LOG_DEBUG, "%s: vnode %p", __func__, fobj);

	/* Sync any data before closing. */
	while (retry-- && fileobj_sync(fobj) == -1) {
		usleep(1); // best effort
	}

	/* Remove itself from the file list. */
	LIST_REMOVE(fobj, entry);
	ASSERT(vault->file_count > 0);
	vault->file_count--;

	if (fobj->vpath) {
		ASSERT(fobj->pathlen > 0);
		crypto_memzero(fobj->vpath, fobj->pathlen);
		free(fobj->vpath);
	}
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
	size_t nbytes;

	if (offset < 0) {
		errno = EINVAL;
		return -1;
	}
	if (fileobj_dataload(fobj) == -1) {
		errno = EIO;
		return -1;
	}
	if (fobj->buf == NULL || offset >= (off_t)fobj->len) {
		return 0;
	}

	nbytes = MIN(fobj->len - offset, len);
	memcpy(buf, &fobj->buf[offset], nbytes);

	app_log(LOG_DEBUG, "%s: vnode %p, read [%jd:%zu] -> %zd",
	    __func__, fobj, (intmax_t)offset, len, nbytes);
	return (size_t)nbytes;
}

ssize_t
fileobj_pwrite(fileobj_t *fobj, const void *buf, size_t len, off_t offset)
{
	uint64_t endoff;

	endoff = offset + len - 1;
	if (offset < 0 || endoff < (uint64_t)offset) {
		/* Overflow. */
		errno = EINVAL;
		return -1;
	}
	if (len == 0) {
		return 0;
	}
	if (fileobj_dataload(fobj) == -1) {
		errno = EIO;
		return -1;
	}

	/*
	 * Expand the memory buffer.
	 */
	if (endoff >= fobj->len) {
		const size_t nlen = endoff + 1;
		void *nbuf;

		nbuf = sbuffer_move(fobj->buf, fobj->len, nlen);
		if (nbuf == 0) {
			errno = ENOMEM;
			return -1;
		}
		fobj->buf = nbuf;
		fobj->len = nlen;
	}
	ASSERT(fobj->buf != NULL);

	/*
	 * Write the data to the buffer.
	 */
	memcpy(&fobj->buf[offset], buf, len);
	fobj->flags |= FILEOBJ_DIRTY;

	app_log(LOG_DEBUG, "%s: vnode %p, write [%jd:%zu]",
	    __func__, fobj, (intmax_t)offset, len);
	return (size_t)len;
}

size_t
fileobj_getsize(fileobj_t *fobj)
{
	app_log(LOG_DEBUG, "%s: vnode %p, size %zu", __func__, fobj, fobj->len);
	if (fileobj_dataload(fobj) == -1) {
		errno = EIO;
		return -1;
	}
	ASSERT(fobj->buf || fobj->len == 0);
	return fobj->len;
}

int
fileobj_setsize(fileobj_t *fobj, size_t len)
{
	void *buf = NULL;

	if (fileobj_dataload(fobj) == -1) {
		app_elog(LOG_DEBUG, "%s: fileobj_dataload() failed", __func__);
		errno = EIO;
		return -1;
	}

	/*
	 * Note: if new length is zero, then sbuffer_move() will free the
	 * old buffer and will return NULL.
	 */
	if (len && (buf = sbuffer_move(fobj->buf, fobj->len, len)) == NULL) {
		app_elog(LOG_DEBUG, "%s: sbuffer_move() failed", __func__);
		return -1;
	}
	fobj->buf = buf;
	fobj->len = len;

	if (fileobj_sync(fobj) == -1) {
		app_elog(LOG_DEBUG, "%s: fileobj_sync() failed", __func__);
		return -1;
	}

	app_log(LOG_DEBUG, "%s: vnode %p, size %zu", __func__, fobj, fobj->len);
	return 0;
}
