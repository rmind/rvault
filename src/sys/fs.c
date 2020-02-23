/*
 * Copyright (c) 2016 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * Some file system helpers.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>

#include "sys.h"
#include "utils.h"

ssize_t
fs_file_size(int fd)
{
	struct stat st;

	if (fstat(fd, &st) == -1) {
		return -1;
	}
	if (st.st_size > SSIZE_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	ASSERT(st.st_size >= 0);
	return st.st_size;
}

ssize_t
fs_read(int fd, void *buf, size_t target)
{
	ssize_t toread = target;
	uint8_t *bufp = buf;

	while (toread) {
		ssize_t ret;
		if ((ret = read(fd, bufp, toread)) <= 0) {
			if (ret == -1 && errno == EINTR) {
				continue;
			}
			if (ret == 0) {
				break;
			}
			return ret;
		}
		bufp += ret;
		toread -= ret;
	}
	return target - toread;
}

ssize_t
fs_write(int fd, const void *buf, size_t target)
{
	const uint8_t *bufp = (const uint8_t *)buf;
	size_t towrite = target;

	while (towrite) {
		ssize_t ret;

		ret = write(fd, bufp, towrite);
		if (ret <= 0) {
			/*
			 * Cover the cases if this routine is used on
			 * non-regular files.
			 */
			if (ret == 0) {
				break;
			}
			switch (errno) {
			case EINTR:
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
				continue;
			default:
				break;
			}
			return -1;
		}
		towrite -= ret;
		bufp += ret;
	}
	return target - towrite;
}

static int
sys_fs_sync(int fd)
{
#if defined(F_FULLFSYNC)
	/*
	 * On Darwin, fsync() provides limited guarantees; it provides
	 * F_FULLFSYNC for a "real" fsync.
	 */
	if (fcntl(fd, F_FULLFSYNC, 0) == -1) {
		return -1;
	}
#else
	if (fsync(fd) == -1) {
		return -1;
	}
#endif
	return 0;
}

/*
 * fs_sync: perform effective fsync() on file descriptor and/or path.
 */
int
fs_sync(int fd, const char *path)
{
	int ret = 0;

	if (fd != -1 && sys_fs_sync(fd) == -1) {
		app_elog(LOG_WARNING, "%s() failed", __func__);
		return -1;
	}
	if (path) {
		char *cpath;

		if ((cpath = strdup(path)) == NULL) {
			app_elog(LOG_WARNING, "%s() failed", __func__);
			return -1;
		}
		fd = open(dirname(cpath), O_RDONLY);
		free(cpath);

		if (fd == -1) {
			app_elog(LOG_WARNING, "%s() failed", __func__);
			return -1;
		}
		ret = sys_fs_sync(fd);
		close(fd);
	}
	return ret;
}
