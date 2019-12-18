/*
 * Copyright (c) 2019 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>

#define	FUSE_USE_VERSION	26
#include <fuse.h>

#include "rvault.h"
#include "rvaultfs.h"
#include "fileobj.h"
#include "utils.h"

#define	FUSE_MINIMUM_VERSION	29

static rvault_t *
get_vault_ctx(void)
{
	struct fuse_context *fctx = fuse_get_context();
	rvault_t *vault = fctx->private_data;
	ASSERT(vault != NULL);
	return vault;
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
	const int ret = fileobj_stat(vault, path, st);
	app_log(LOG_DEBUG, "%s: path `%s', retval %d", __func__, path, ret);
	return (ret == -1) ? -errno : 0;
}

static int
rvaultfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset __unused, struct fuse_file_info *fi __unused)
{
	rvault_t *vault = get_vault_ctx();
	struct dirent *dp;
	char *vpath;
	DIR *dirp;

	app_log(LOG_DEBUG, "%s: path `%s'", __func__, path);

	if ((vpath = rvault_resolve_path(vault, path, NULL)) == NULL) {
		return -errno;
	}
	dirp = opendir(vpath);
	if (dirp == NULL) {
		free(vpath);
		return -errno;
	}
	free(vpath);

	while ((dp = readdir(dirp)) != NULL) {
		char *name;

		if (!strncmp(dp->d_name, "rvault.", sizeof("rvault.") - 1)) {
			continue;
		}
		name = rvault_resolve_vname(vault, dp->d_name, NULL);
		if (name == NULL) {
			const int ret = -errno;
			closedir(dirp);
			return ret;
		}
		filler(buf, name, NULL, 0);
		free(name);
	}
	closedir(dirp);
	return 0;
}

static int
rvaultfs_truncate(const char *path, off_t size)
{
	rvault_t *vault = get_vault_ctx();
	fileobj_t *fobj;

	app_log(LOG_DEBUG, "%s: path `%s', size %jd",
	    __func__, path, (intmax_t)size);

	if (size < 0) {
		return -EINVAL;
	}
	if ((fobj = fileobj_open(vault, path, O_WRONLY, FOBJ_OMASK)) == NULL) {
		return -errno;
	}
	if (fileobj_setsize(fobj, (size_t)size) == -1) {
		const int ret = -errno;
		fileobj_close(fobj);
		return ret;
	}
	fileobj_close(fobj);
	return 0;
}

static int
rvaultfs_open_raw(const char *path, struct fuse_file_info *fi, mode_t mode)
{
	rvault_t *vault = get_vault_ctx();
	fileobj_t *fobj;

	if ((fobj = fileobj_open(vault, path, fi->flags, mode)) == NULL) {
		return -errno;
	}

	/* Just use direct I/O i.e. bypass page cache. */
	fi->direct_io = true;
	fi->keep_cache = false;

	/* Associate the file object with the FUSE file handle. */
	static_assert(sizeof(fi->fh) >= sizeof(uintptr_t),
	    "fuse_file_info::fh is too small to fit a pointer value");
	fi->fh = (uintptr_t)fobj;
	app_log(LOG_DEBUG, "%s: `%s' -> %p", __func__, path, fobj);
	return 0;
}

static int
rvaultfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	return rvaultfs_open_raw(path, fi, mode);
}

static int
rvaultfs_open(const char *path, struct fuse_file_info *fi)
{
	return rvaultfs_open_raw(path, fi, FOBJ_OMASK);
}

static int
rvaultfs_read(const char *path __unused, char *buf, size_t len,
    off_t offset, struct fuse_file_info *fi)
{
	fileobj_t *fobj = (void *)(uintptr_t)fi->fh;
	ssize_t ret;

	app_log(LOG_DEBUG, "%s: path `%s', vnode %p, len %zu, offset %jd",
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

	app_log(LOG_DEBUG, "%s: path `%s', vnode %p, len %zu, offset %jd",
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

	app_log(LOG_DEBUG, "%s: path `%s', vnode %p", __func__, path, fobj);
	ASSERT(fobj != NULL);
	fileobj_close(fobj);
	return 0;
}

static int
rvaultfs_unlink(const char *path)
{
	rvault_t *vault = get_vault_ctx();
	char *vpath;
	int ret;

	app_log(LOG_DEBUG, "%s: path `%s'", __func__, path);
	if ((vpath = rvault_resolve_path(vault, path, NULL)) == NULL) {
		return -errno;
	}
	ret = unlink(vpath);
	free(vpath);

	return (ret == -1) ? -errno : 0;
}

static int
rvaultfs_rename(const char *from, const char *to)
{
	rvault_t *vault = get_vault_ctx();
	char *vpath_from = NULL, *vpath_to = NULL;
	int ret = -1;

	app_log(LOG_DEBUG, "%s: from `%s' to `%s'", __func__, from, to);
	if ((vpath_from = rvault_resolve_path(vault, from, NULL)) == NULL) {
		goto err;
	}
	if ((vpath_to = rvault_resolve_path(vault, to, NULL)) == NULL) {
		goto err;
	}
	ret = rename(vpath_from, vpath_to);
err:
	free(vpath_from);
	free(vpath_to);
	return (ret == -1) ? -errno : 0;
}

static int
rvaultfs_mkdir(const char *path, mode_t mode)
{
	rvault_t *vault = get_vault_ctx();
	char *vpath;
	int ret;

	app_log(LOG_DEBUG, "%s: path `%s', mode 0%o", __func__, path, mode);
	if ((vpath = rvault_resolve_path(vault, path, NULL)) == NULL) {
		return -errno;
	}
	ret = mkdir(vpath, mode);
	free(vpath);
	return (ret == -1) ? -errno : 0;
}

static int
rvaultfs_rmdir(const char *path)
{
	rvault_t *vault = get_vault_ctx();
	char *vpath;
	int ret;

	app_log(LOG_DEBUG, "%s: path `%s'", __func__, path);
	if ((vpath = rvault_resolve_path(vault, path, NULL)) == NULL) {
		return -errno;
	}
	ret = rmdir(vpath);
	free(vpath);
	return (ret == -1) ? -errno : 0;
}

static const struct fuse_operations rvaultfs_ops = {
	.init		= rvaultfs_init,
	.getattr	= rvaultfs_getattr,
	.readdir	= rvaultfs_readdir,
	.truncate	= rvaultfs_truncate,
	.create		= rvaultfs_create,
	.open		= rvaultfs_open,
	.read		= rvaultfs_read,
	.write		= rvaultfs_write,
	.release	= rvaultfs_release,
	.unlink		= rvaultfs_unlink,
	.rename		= rvaultfs_rename,
	.mkdir		= rvaultfs_mkdir,
	.rmdir		= rvaultfs_rmdir,
};

int
rvaultfs_run(rvault_t *vault, const char *mountpoint)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	struct fuse_chan *chan;
	struct fuse *fuse;
	int ret;

	if (fuse_version() < FUSE_MINIMUM_VERSION) {
		warnx("FUSE version %d found; please upgrade to at least %d",
		    fuse_version(), FUSE_MINIMUM_VERSION);
		return -1;
	}

	/*
	 * Note: force 'default_permissions' option.  No need to check the
	 * permissions in readdir(); access() operation will not be called
	 * by FUSE either.
	 */
	fuse_opt_add_arg(&args, APP_NAME);
	fuse_opt_add_arg(&args, "-ofsname="APP_NAME);
	fuse_opt_add_arg(&args, "-odefault_permissions");
	// fuse_opt_add_arg(&args, "-oauto_unmount");
#ifdef FUSE_DEBUG
	fuse_opt_add_arg(&args, "-odebug");
#endif
	if ((chan = fuse_mount(mountpoint, &args)) == NULL) {
		return -1;
	}
	if ((fuse = fuse_new(chan, &args, &rvaultfs_ops,
	    sizeof(rvaultfs_ops), vault)) == NULL) {
		fuse_unmount(mountpoint, chan);
		return -1;
	}
	ret = fuse_loop(fuse);
	app_log(LOG_DEBUG, "%s: exited fuse_loop() with %d", __func__, ret);
	fuse_unmount(mountpoint, chan);
	fuse_destroy(fuse);
	return ret;
}
