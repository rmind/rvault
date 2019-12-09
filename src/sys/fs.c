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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "sys.h"

/*
 * fs_block_size: return the file system block size.
 */
ssize_t
fs_block_size(const char *path)
{
	struct statvfs sfs;

	if (statvfs(path, &sfs) == -1) {
		return -1;
	}
	return sfs.f_bsize;
}

ssize_t
fs_file_size(int fd)
{
	struct stat st;

	if (fstat(fd, &st) == -1) {
		return -1;
	}
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

int
fs_sync_path(const char *path)
{
	int fd;

	if ((fd = open(path, O_RDONLY)) == -1)
		return -1;
	if (fsync(fd) == -1) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}
