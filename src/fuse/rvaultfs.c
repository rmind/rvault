/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "rvault.h"
#include "rvaultfs.h"
#include "fileobj.h"
#include "utils.h"

static rvault_t *
get_vault_ctx(void)
{
	struct fuse_context *fctx = fuse_get_context();
	rvault_t *vault = fctx->private_data;
	ASSERT(vault != NULL);
	return vault;
}

static char *
get_vault_path(rvault_t *vault, const char *path)
{
	char *fpath = NULL;

	if (asprintf(&fpath, "%s/%s", vault->base_path, path) == -1) {
		return NULL;
	}
	return fpath;
}

static void *
rvaultfs_init(struct fuse_conn_info *conn __unused)
{
	/* Must return the context. */
	return get_vault_ctx();
}

static int
rvaultfs_getattr(const char *path, struct stat *st)
{
	rvault_t *vault = get_vault_ctx();
	fileobj_t *fobj;
	char *vpath;
	int ret = 0;

	app_log(LOG_DEBUG, "%s: path `%s'", __func__, path);
	if ((vpath = get_vault_path(vault, path)) == NULL) {
		return -ENOMEM;
	}
	if (stat(vpath, st) == -1) {
		ret = -errno;
		goto out;
	}
	/* XXX: optimize */
	if ((fobj = fileobj_open(vault, vpath, O_RDONLY)) == NULL) {
		ret = -errno;
		goto out;
	}
	st->st_size = fileobj_getsize(fobj);
	fileobj_close(fobj);
out:
	free(vpath);
	return ret;
}

static int
rvaultfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset __unused, struct fuse_file_info *fi __unused)
{
	rvault_t *vault = get_vault_ctx();
	struct dirent *dp;
	DIR *dirp;

	app_log(LOG_DEBUG, "%s: path `%s'", __func__, path);
	if (strcmp(path, "/") != 0) {
		return -ENOENT;
	}
	dirp = opendir(vault->base_path);
	if (dirp == NULL) {
		return -errno;
	}
	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, APP_META_FILE) == 0) {
			continue;
		}
		filler(buf, dp->d_name, NULL, 0);
	}
	closedir(dirp);
	return 0;
}

static int
rvaultfs_truncate(const char *path, off_t size)
{
	rvault_t *vault = get_vault_ctx();
	fileobj_t *fobj;
	char *vpath;
	int ret = 0;

	app_log(LOG_DEBUG, "%s: path `%s', size %jd",
	    __func__, path, (intmax_t)size);

	if (size < 0) {
		return -EINVAL;
	}
	/*
	 * XXX: optimize
	 */
	if ((vpath = get_vault_path(vault, path)) == NULL) {
		return -ENOMEM;
	}
	if ((fobj = fileobj_open(vault, vpath, O_RDONLY)) == NULL) {
		ret = -errno;
		goto out;
	}
	if (fileobj_setsize(fobj, (size_t)size) == -1) {
		ret = -errno;
		fileobj_close(fobj);
		goto out;
	}
	fileobj_close(fobj);
out:
	free(vpath);
	return ret;
}

static int
rvaultfs_open(const char *path, struct fuse_file_info *fi)
{
	rvault_t *vault = get_vault_ctx();
	fileobj_t *fobj;
	char *vpath;
	int ret = 0;

	app_log(LOG_DEBUG, "%s: path `%s'", __func__, path);
	if ((vpath = get_vault_path(vault, path)) == NULL) {
		return -ENOMEM;
	}
	if ((fobj = fileobj_open(vault, vpath, fi->flags)) == NULL) {
		ret = -errno;
		goto out;
	}

	/* Associate the file object with the FUSE file handle. */
	static_assert(sizeof(fi->fh) >= sizeof(uintptr_t),
	    "fuse_file_info::fh is too small to fit a pointer value");
	fi->fh = (uintptr_t)fobj;
	app_log(LOG_DEBUG, "%s: `%s' -> %p", __func__, path, fobj);
out:
	free(vpath);
	return ret;
}

static int
rvaultfs_read(const char *path __unused, char *buf, size_t len,
    off_t offset, struct fuse_file_info *fi)
{
	fileobj_t *fobj = (void *)(uintptr_t)fi->fh;
	ssize_t ret;

	app_log(LOG_DEBUG, "%s: path `%s', handle %p, len %zu, offset %jd",
	    __func__, path, fobj, len, (intmax_t)offset);
	ASSERT(fobj != NULL);

	if (len == 0) {
		return 0;
	}
	if ((ret = fileobj_pread(fobj, buf, len, offset)) == -1) {
		return -errno;
	}
	return ret;
}

static int
rvaultfs_write(const char *path __unused, const char *buf, size_t len,
    off_t offset, struct fuse_file_info *fi)
{
	fileobj_t *fobj = (void *)(uintptr_t)fi->fh;
	ssize_t ret;

	app_log(LOG_DEBUG, "%s: path `%s', handle %p, len %zu, offset %jd",
	    __func__, path, fobj, len, (intmax_t)offset);
	ASSERT(fobj != NULL);

	if (len == 0) {
		return 0;
	}
	if ((ret = fileobj_pwrite(fobj, buf, len, offset)) == -1) {
		return -errno;
	}
	return ret;
}

static int
rvaultfs_release(const char *path __unused, struct fuse_file_info *fi)
{
	fileobj_t *fobj = (void *)(uintptr_t)fi->fh;

	app_log(LOG_DEBUG, "%s: path `%s', handle %p", __func__, path, fobj);
	ASSERT(fobj != NULL);
	fileobj_close(fobj);
	return 0;
}

static const struct fuse_operations rvaultfs_ops = {
	.init		= rvaultfs_init,
	.getattr	= rvaultfs_getattr,
	.readdir	= rvaultfs_readdir,
	.truncate	= rvaultfs_truncate,
	.open		= rvaultfs_open,
	.read		= rvaultfs_read,
	.write		= rvaultfs_write,
	.release	= rvaultfs_release,
};

int
rvaultfs_run(rvault_t *vault, const char *mountpoint)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_chan *chan;
	struct fuse *fuse;
	int ret;

	fuse_opt_add_arg(&args, APP_NAME);
	if ((chan = fuse_mount(mountpoint, &args)) == NULL) {
		return -1;
	}
	if ((fuse = fuse_new(chan, &args, &rvaultfs_ops,
	    sizeof(rvaultfs_ops), vault)) == NULL) {
		fuse_unmount(mountpoint, chan);
		return -1;
	}
	ret = fuse_loop(fuse);
	fuse_unmount(mountpoint, chan);
	fuse_destroy(fuse);
	return ret;
}
