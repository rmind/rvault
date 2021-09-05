/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * File objects.
 *
 * Abstracts file handles/descriptors within a vault.  Provides an API
 * for UNIX-style operations such as open/read/write/close.
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
#include <time.h>
#include <errno.h>

#include "rvault.h"
#include "fileobj.h"
#include "storage.h"
#include "crypto.h"
#include "sys.h"
#include "utils.h"

/*
 * File reference (think of descriptor/handle).
 */
struct fileref {
	fileobj_t *	fobj;
	LIST_ENTRY(fileref) entry;
};

/*
 * In-memory file object (think of a vnode).
 */
struct fileobj {
	rvault_t *	vault;
	unsigned	flags;
	int		fd;

	/* Resolved vault path and its length. */
	char *		vpath;
	size_t		pathlen;

	/* In-memory buffer, allocation size and data length. */
	sbuffer_t	sbuf;
	size_t		len;

	/* Last sync time. */
	time_t		last_stime;

	/* File reference list. */
	unsigned	refcnt;
	LIST_HEAD(, fileref) reflist;

	/* Vault file-list entry. */
	LIST_ENTRY(fileobj) entry;
};

#define	FOBJ_INMEM		0x01	// data in-memory
#define	FOBJ_DIRTY		0x02	// data needs to be synced
#define	FOBJ_NEED_FSYNC		0x04	// need a full fsync()
#define	FOBJ_ALWAYS_FSYNC	0x08	// always sync / O_SYNC

#define	FOBJ_MIN_SYNC_TIME	3	// in seconds

static int	fileobj_dataload(fileobj_t *);
static int	fileobj_syncnode(fileobj_t *, int);
static void	fileobj_free(fileobj_t *);

static fileobj_t *
fileobj_alloc(rvault_t *vault, char *vpath, const size_t pathlen,
    const int flags, const mode_t mode)
{
	fileobj_t *fobj;

	if ((fobj = calloc(1, sizeof(fileobj_t))) == NULL) {
		return NULL;
	}
	fobj->vault = vault;
	fobj->vpath = vpath;
	fobj->pathlen = pathlen;
	LIST_INSERT_HEAD(&vault->file_list, fobj, entry);
	vault->file_count++;

	if ((flags & (O_SYNC|O_DSYNC)) != 0 || !vault->weak_sync) {
		fobj->flags |= FOBJ_ALWAYS_FSYNC;
	}

	/*
	 * Open the data file.
	 */
	fobj->fd = open(fobj->vpath, flags, mode);
	if (fobj->fd == -1) {
		fileobj_free(fobj);
		return NULL;
	}
	app_log(LOG_DEBUG, "%s: vnode %p, data length %zu, vpath [%s]",
	    __func__, fobj, fobj->len, fobj->vpath);
	return fobj;
}

fileref_t *
fileobj_open(rvault_t *vault, const char *path, int flags, mode_t mode)
{
	fileobj_t *fobj;
	fileref_t *fref;
	size_t pathlen;
	char *vpath;

	/* Get the file reference structure ready. */
	if ((fref = calloc(1, sizeof(fileref_t))) == NULL) {
		return NULL;
	}

	/*
	 * Resolve the path and lookup the file object.
	 */
	if ((vpath = rvault_resolve_path(vault, path, &pathlen)) == NULL) {
		free(fref);
		return NULL;
	}
	if ((fobj = rhashmap_get(vault->file_map, vpath, pathlen)) != NULL) {
		/* Already in the map -- just get the file referenve. */
		free(vpath);
		goto retfd;
	}

	/*
	 * Open the file, loading the file object.  Enter the path into
	 * the map, associating it with this file object.
	 */
	fobj = fileobj_alloc(vault, vpath, pathlen, flags, mode);
	if (fobj == NULL) {
		free(vpath);
		free(fref);
		return NULL;
	}
	rhashmap_put(vault->file_map, vpath, pathlen, fobj);
retfd:
	/*
	 * Initialize and add the file reference.
	 */
	fref->fobj = fobj;
	LIST_INSERT_HEAD(&fobj->reflist, fref, entry);
	fobj->refcnt++;
	return fref;
}

static int
fileobj_dataload(fileobj_t *fobj)
{
	ssize_t flen, nbytes;

	if (fobj->flags & FOBJ_INMEM) {
		return 0;
	}
	if ((flen = fs_file_size(fobj->fd)) == -1) {
		app_elog(LOG_DEBUG, "%s: fs_file_size() failed", __func__);
		return -1;
	}
	if (flen == 0) {
		fobj->flags |= FOBJ_INMEM;
		return 0;
	}

	/*
	 * Initial load of the data into the memory.
	 * Note: may return an empty buffer (if zero size)
	 */
	nbytes = storage_read_data(fobj->vault, fobj->fd, flen, &fobj->sbuf);
	if (nbytes == -1) {
		app_elog(LOG_ERR, "%s: storage_read_data() failed", __func__);
		return -1;
	}
	ASSERT(fobj->len == 0 || fobj->sbuf.buf);
	fobj->len = nbytes;
	fobj->flags |= FOBJ_INMEM;
	return 0;
}

/*
 * fileobj_syncnode: sync the data to the backing store.
 */
static int
fileobj_syncnode(fileobj_t *fobj, int stype)
{
	rvault_t *vault = fobj->vault;
	char *fpath;
	int fd, e;

	/*
	 * Check if there is anything to sync.
	 */
	if ((fobj->flags & FOBJ_DIRTY) == 0) {
		goto out;
	}

	/*
	 * If truncating, then just wipe the whole file.
	 */
	if (fobj->len == 0) {
		if (ftruncate(fobj->fd, 0) == -1) {
			return -1;
		}
		goto out;
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
	if (storage_write_data(vault, fd, fobj->sbuf.buf, fobj->len) == -1) {
		app_elog(LOG_DEBUG, "%s: storage_write_data() failed", __func__);
		errno = EIO;
		goto err;
	}
	if (rename(fpath, fobj->vpath) == -1) {
		app_elog(LOG_ERR, "%s: rename() failed", __func__);
		goto err;
	}
	free(fpath);

	/*
	 * Update the file descriptor; mark the object as no longer dirty.
	 */
	fobj->flags &= ~FOBJ_DIRTY;
	close(fobj->fd);
	fobj->fd = fd;

	app_log(LOG_DEBUG, "%s: vnode %p write-back complete", __func__, fobj);
out:
	if (stype == FOBJ_FULLSYNC && (fobj->flags & FOBJ_NEED_FSYNC) != 0) {
		fs_sync(fobj->fd, fobj->vpath);
		fobj->flags &= ~FOBJ_NEED_FSYNC;
		app_log(LOG_DEBUG, "%s: vnode %p full-sync", __func__, fobj);
	}
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
fileobj_sync(fileref_t *fref, int stype)
{
	fileobj_t *fobj = fref->fobj;
	return fileobj_syncnode(fobj, stype);
}

int
fileobj_stat(rvault_t *vault, const char *path, struct stat *st)
{
	int ret = -1;
	char *vpath;

	if ((vpath = rvault_resolve_path(vault, path, NULL)) == NULL) {
		return -1;
	}
	if (lstat(vpath, st) == -1) {
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
		int fd;

		/*
		 * It is necessary to open the file to read its real size
		 * stored in the header.
		 *
		 * WARNING: Some applications create files with mode = 0.
		 * Therefore we try to reduce the error rate by executing
		 * this path only if st_size is non-zero.
		 */
		if ((fd = open(vpath, O_RDONLY)) == -1) {
			app_log(LOG_DEBUG,
			    "%s: open `%s' failed", __func__, vpath);
			goto err;
		}
		if ((size = storage_read_length(vault, fd)) == -1) {
			close(fd);
			goto err;
		}
		st->st_size = size;
		close(fd);
	}
	app_log(LOG_DEBUG, "%s: path `%s', size %zu",
	    __func__, path, st->st_size);
	ret = 0;
err:
	free(vpath);
	return ret;
}

static void
fileobj_free(fileobj_t *fobj)
{
	rvault_t *vault = fobj->vault;
	unsigned retry = 3;
	void *ret __unused;

	app_log(LOG_DEBUG, "%s: vnode %p", __func__, fobj);

	/* Sync any data before closing. */
	while (fileobj_syncnode(fobj, FOBJ_FULLSYNC) == -1 && retry--) {
		usleep(1);  // best effort
	}

	/*
	 * Remove from the map.
	 */
	ASSERT(fobj->refcnt == 0);
	ASSERT(LIST_EMPTY(&fobj->reflist));

	ret = rhashmap_del(vault->file_map, fobj->vpath, fobj->pathlen);
	ASSERT(fobj == ret);

	/* Remove itself from the file list. */
	LIST_REMOVE(fobj, entry);
	ASSERT(vault->file_count > 0);
	vault->file_count--;

	if (fobj->vpath) {
		ASSERT(fobj->pathlen > 0);
		crypto_memzero(fobj->vpath, fobj->pathlen);
		free(fobj->vpath);
	}
	if (fobj->len) {
		ASSERT(fobj->sbuf.buf != NULL);
		ASSERT(fobj->sbuf.buf_size >= fobj->len);
		sbuffer_free(&fobj->sbuf);
	}
	if (fobj->fd > 0) {
		close(fobj->fd);
	}
	free(fobj);
}

void
fileobj_close(fileref_t *fref)
{
	fileobj_t *fobj = fref->fobj;

	/*
	 * Remove, destroy the file reference and drop the counter.
	 */
	ASSERT(fobj->refcnt > 0);
	LIST_REMOVE(fref, entry);
	free(fref);

	/*
	 * Destroy the file object on last reference.
	 */
	if (--fobj->refcnt == 0) {
		fileobj_free(fobj);
	}
}

void
fileobj_close_full(fileobj_t *fobj)
{
	fileref_t *fref;

	while ((fref = LIST_FIRST(&fobj->reflist)) != NULL) {
		ASSERT(fobj->refcnt > 0);
		LIST_REMOVE(fref, entry);
		fobj->refcnt--;
		free(fref);
	}
	ASSERT(fobj->refcnt == 0);
	fileobj_free(fobj);
}

ssize_t
fileobj_pread(fileref_t *fref, void *buf, size_t len, off_t offset)
{
	fileobj_t *fobj = fref->fobj;
	size_t nbytes;
	uint8_t *fbuf;

	if (offset < 0) {
		errno = EINVAL;
		return -1;
	}
	if (fileobj_dataload(fobj) == -1) {
		errno = EIO;
		return -1;
	}
	if (fobj->len == 0 || offset >= (off_t)fobj->len) {
		return 0;
	}

	fbuf = fobj->sbuf.buf;
	nbytes = MIN(fobj->len - offset, len);
	memcpy(buf, &fbuf[offset], nbytes);

	app_log(LOG_DEBUG, "%s: vnode %p, read [%jd:%zu] -> %zd",
	    __func__, fobj, (intmax_t)offset, len, nbytes);
	return (size_t)nbytes;
}

ssize_t
fileobj_pwrite(fileref_t *fref, const void *buf, size_t len, off_t offset)
{
	fileobj_t *fobj = fref->fobj;
	uint64_t endoff;
	uint8_t *fbuf;

	endoff = offset + len - 1;
	if (offset < 0 || endoff < (uint64_t)offset || endoff > SIZE_MAX) {
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

		/*
		 * If we have enough space since the previous expansion,
		 * then merely bump the data length.  Otherwise, grow
		 * exponentially.
		 */
		if (endoff >= fobj->sbuf.buf_size &&
		    sbuffer_move(&fobj->sbuf, nlen, SBUF_GROWEXP) == NULL) {
			errno = ENOMEM;
			return -1;
		}
		app_log(LOG_DEBUG, "%s: vnode %p, grow to [%zu]",
		    __func__, fobj, nlen);
		fobj->len = nlen;
	}
	fbuf = fobj->sbuf.buf;
	ASSERT(fbuf != NULL);

	/*
	 * Write the data to the buffer.
	 */
	memcpy(&fbuf[offset], buf, len);
	fobj->flags |= (FOBJ_DIRTY | FOBJ_NEED_FSYNC);

	app_log(LOG_DEBUG, "%s: vnode %p, write [%jd:%ju]",
	    __func__, fobj, (intmax_t)offset, (uintmax_t)offset + len);

	if ((fobj->flags & FOBJ_ALWAYS_FSYNC) == 0) {
		/*
		 * Sync if more than N seconds passed since the last write.
		 */
		const time_t now = time(NULL);

		if ((now - fobj->last_stime) > FOBJ_MIN_SYNC_TIME) {
			if (fileobj_syncnode(fobj, FOBJ_WRITEBACK) == 0) {
				fobj->last_stime = now;
			}
		}
	} else {
		fileobj_syncnode(fobj, FOBJ_FULLSYNC);
	}

	return (size_t)len;
}

size_t
fileobj_getsize(fileref_t *fref)
{
	fileobj_t *fobj = fref->fobj;

	app_log(LOG_DEBUG, "%s: vnode %p, size %zu", __func__, fobj, fobj->len);

	if (fileobj_dataload(fobj) == -1) {
		errno = EIO;
		return -1;
	}
	ASSERT(fobj->len == 0 || fobj->sbuf.buf);
	return fobj->len;
}

int
fileobj_setsize(fileref_t *fref, size_t len)
{
	fileobj_t *fobj = fref->fobj;

	/*
	 * Only load the data if truncating to non-zero.
	 */
	if (len && fileobj_dataload(fobj) == -1) {
		app_elog(LOG_DEBUG, "%s: fileobj_dataload() failed", __func__);
		errno = EIO;
		return -1;
	}

	/*
	 * Note: if new length is zero, then sbuffer_move() will free the
	 * old buffer and will return NULL.
	 */
	if (sbuffer_move(&fobj->sbuf, len, 0) == NULL && len) {
		app_elog(LOG_DEBUG, "%s: sbuffer_move() failed", __func__);
		return -1;
	}
	fobj->len = len;
	fobj->flags |= (FOBJ_DIRTY | FOBJ_NEED_FSYNC);

	if (fileobj_syncnode(fobj, FOBJ_WRITEBACK) == -1) {
		app_elog(LOG_DEBUG, "%s: fileobj_syncnode() failed", __func__);
		return -1;
	}

	app_log(LOG_DEBUG, "%s: vnode %p, size %zu", __func__, fobj, fobj->len);
	return 0;
}
