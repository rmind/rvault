/*
 * Copyright (c) 2019-2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

/*
 * rvault FUSE operations.
 */

#include <sys/types.h>
#include <sys/xattr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
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

#define	FUSE_MINIMUM_VERSION	26

static rvault_t *
get_vault_ctx(void)
{
	struct fuse_context *fctx = fuse_get_context();
	rvault_t *vault = fctx->private_data;
	ASSERT(vault != NULL);
	return vault;
}

static ssize_t
get_vault_path(const char *path, char *buf, size_t len)
{
	rvault_t *vault = get_vault_ctx();
	char *vpath;
	ssize_t ret;

	if ((vpath = rvault_resolve_path(vault, path, NULL)) == NULL) {
		return -1;
	}
	ret = snprintf(buf, len, "%s", vpath);
	free(vpath);

	if (ret < 0 || (size_t)ret >= len) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return ret;
}

static void *
rvaultfs_init(struct fuse_conn_info *conn __unused)
{
	/* Must return the context. */
	return get_vault_ctx();
}

static int
rvaultfs_statfs(const char *path, struct statvfs *stbuf)
{
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = statvfs(vpath, stbuf);
	return (ret == -1) ? -errno : ret;
}

static int
rvaultfs_getattr(const char *path, struct stat *st)
{
	rvault_t *vault = get_vault_ctx();
	const int ret = fileobj_stat(vault, path, st);
	app_log(LOG_DEBUG, "%s: path `%s', retval %d", __func__, path, ret);
	return (ret == -1) ? -errno : ret;
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

	/*
	 * Note: use O_RDWR instead of O_WRONLY, since the data might have
	 * to be loaded before truncation (e.g. in order decompress and
	 * determine the correct offset).
	 */
	if ((fobj = fileobj_open(vault, path, O_RDWR, FOBJ_OMASK)) == NULL) {
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

	/*
	 * Use direct I/O i.e. bypass the page cache for extra security.
	 * This causes abnormal behaviour on Darwin, though; we use the
	 * '-noubc' parameter there instead.
	 */
#if !defined(__APPLE__)
	fi->direct_io = true;
#endif

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
	app_log(LOG_DEBUG, "%s: `%s' mode 0%o", __func__, path, mode);
	return rvaultfs_open_raw(path, fi, mode);
}

static int
rvaultfs_open(const char *path, struct fuse_file_info *fi)
{
	app_log(LOG_DEBUG, "%s: `%s'", __func__, path);
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
rvaultfs_flush(const char *path __unused, struct fuse_file_info *fi)
{
	fileobj_t *fobj = (void *)(uintptr_t)fi->fh;

	app_log(LOG_DEBUG, "%s: path `%s', vnode %p", __func__, path, fobj);
	ASSERT(fobj != NULL);
	return fileobj_sync(fobj, FOBJ_FULLSYNC) == -1 ? -errno : 0;
}

static int
rvaultfs_fsync(const char *path __unused, int isdatasync __unused,
    struct fuse_file_info *fi)
{
	fileobj_t *fobj = (void *)(uintptr_t)fi->fh;

	app_log(LOG_DEBUG, "%s: path `%s', vnode %p", __func__, path, fobj);
	ASSERT(fobj != NULL);
	return fileobj_sync(fobj, FOBJ_FULLSYNC) == -1 ? -errno : 0;
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
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = unlink(vpath);
	return (ret == -1) ? -errno : ret;
}

static int
rvaultfs_rename(const char *from, const char *to)
{
	char vpath_from[PATH_MAX], vpath_to[PATH_MAX];
	int ret;

	app_log(LOG_DEBUG, "%s: from `%s' to `%s'", __func__, from, to);

	if (get_vault_path(from, vpath_from, sizeof(vpath_from)) == -1) {
		return -errno;
	}
	if (get_vault_path(to, vpath_to, sizeof(vpath_to)) == -1) {
		return -errno;
	}
	ret = rename(vpath_from, vpath_to);
	return (ret == -1) ? -errno : ret;
}

static int
rvaultfs_mkdir(const char *path, mode_t mode)
{
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = mkdir(vpath, mode);
	return (ret == -1) ? -errno : ret;
}

static int
rvaultfs_rmdir(const char *path)
{
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = rmdir(vpath);
	return (ret == -1) ? -errno : ret;
}

struct rvaultfs_readdir_iter_ctx {
	fuse_fill_dir_t	filler;
	void *		buf;
};

static void
rvaultfs_readdir_iter(void *arg0, const char *name, struct dirent *dp __unused)
{
	struct rvaultfs_readdir_iter_ctx *arg = arg0;
	arg->filler(arg->buf, name, NULL, 0);
}

static int
rvaultfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset __unused, struct fuse_file_info *fi __unused)
{
	struct rvaultfs_readdir_iter_ctx arg = { .filler = filler, .buf = buf };
	rvault_t *vault = get_vault_ctx();

	app_log(LOG_DEBUG, "%s: path `%s'", __func__, path);

	if (rvault_iter_dir(vault, path, &arg, rvaultfs_readdir_iter) == -1) {
		return -errno;
	}
	return 0;
}

static int
rvaultfs_chmod(const char *path, mode_t mode)
{
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = chmod(vpath, mode);
	app_log(LOG_DEBUG, "%s: path `%s', retval %d", __func__, path, ret);
	return (ret == -1) ? -errno : ret;
}

static int
rvaultfs_chown(const char *path, uid_t uid, gid_t gid)
{
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = chown(vpath, uid, gid);
	app_log(LOG_DEBUG, "%s: path `%s', retval %d", __func__, path, ret);
	return (ret == -1) ? -errno : ret;
}

static int
rvaultfs_utimens(const char *path, const struct timespec ts[2])
{
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = utimensat(-1, vpath, ts, AT_SYMLINK_NOFOLLOW);
	app_elog(LOG_DEBUG, "%s: path `%s', retval %d", __func__, path, ret);
	return (ret == -1) ? -errno : ret;
}

static int
rvaultfs_listxattr(const char *path, char *list, size_t size)
{
	char vpath[PATH_MAX];
	ssize_t ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
#ifdef __APPLE__
	ret = listxattr(vpath, list, size, XATTR_NOFOLLOW);
#else
	ret = listxattr(vpath, list, size);
#endif
	return ret == -1 ? -errno : ret;
}

#ifdef __APPLE__

static int
rvaultfs_getxattr(const char *path, const char *name, char *value,
    size_t size, uint32_t pos)
{
	char vpath[PATH_MAX];
	ssize_t ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = getxattr(vpath, name, value, size, pos, XATTR_NOFOLLOW);
	return (ret == -1) ? -errno : ret;
}

static int
rvaultfs_setxattr(const char *path, const char *name, const char *val,
    size_t size, int ops __unused, uint32_t pos)
{
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = setxattr(vpath, name, val, size, pos, XATTR_NOFOLLOW);
	return (ret == -1) ? -errno : ret;
}

#else

static int
rvaultfs_getxattr(const char *path, const char *name, char *val,
    size_t size)
{
	char vpath[PATH_MAX];
	ssize_t ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = getxattr(vpath, name, val, size);
	return (ret == -1) ? -errno : ret;
}

static int
rvaultfs_setxattr(const char *path, const char *name, const char *val,
    size_t size, int flags)
{
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
	ret = lsetxattr(vpath, name, val, size, flags);
	return (ret == -1) ? -errno : ret;
}

#endif

static int
rvaultfs_removexattr(const char *path, const char *name)
{
	char vpath[PATH_MAX];
	int ret;

	if (get_vault_path(path, vpath, sizeof(vpath)) == -1) {
		return -errno;
	}
#ifdef __APPLE__
	ret = removexattr(vpath, name, XATTR_NOFOLLOW);
#else
	ret = removexattr(vpath, name);
#endif
	return (ret == -1) ? -errno : ret;
}

static const struct fuse_operations rvaultfs_ops = {
	.init		= rvaultfs_init,
	.statfs		= rvaultfs_statfs,
	.getattr	= rvaultfs_getattr,
	.readdir	= rvaultfs_readdir,
	.truncate	= rvaultfs_truncate,
	.create		= rvaultfs_create,
	.open		= rvaultfs_open,
	.read		= rvaultfs_read,
	.write		= rvaultfs_write,
	.flush		= rvaultfs_flush,
	.fsync		= rvaultfs_fsync,
	.release	= rvaultfs_release,
	.unlink		= rvaultfs_unlink,
	.rename		= rvaultfs_rename,
	.mkdir		= rvaultfs_mkdir,
	.rmdir		= rvaultfs_rmdir,
	.chmod		= rvaultfs_chmod,
	.chown		= rvaultfs_chown,
	.utimens	= rvaultfs_utimens,

	.listxattr	= rvaultfs_listxattr,
	.getxattr	= rvaultfs_getxattr,
	.setxattr	= rvaultfs_setxattr,
	.removexattr	= rvaultfs_removexattr,
};

int
rvaultfs_run(rvault_t *vault, const char *mountpoint, bool fg, bool debug)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
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
#ifdef __APPLE__
	fuse_opt_add_arg(&args, "-oiosize=16777216"); // 16 MB
	fuse_opt_add_arg(&args, "-onoubc");
	// fuse_opt_add_arg(&args, "-oauto_xattr");
#endif
	// fuse_opt_add_arg(&args, "-oauto_unmount");
	if (debug) {
		fuse_opt_add_arg(&args, "-odebug");
	}
#if defined(__NetBSD__)
	fuse = fuse_new(&args, &rvaultfs_ops, sizeof(rvaultfs_ops), vault);
	if (fuse == NULL) {
		return -1;
	}
	if (fuse_mount(fuse, mountpoint) == -1) {
		fuse_destroy(fuse);
		return -1;
	}
	if (!fg) {
		(void)fuse_daemonize(fuse);
	}
	ret = fuse_loop(fuse);
	app_log(LOG_DEBUG, "%s: exited fuse_loop() with %d", __func__, ret);
	fuse_unmount(fuse);
#else
	struct fuse_chan *chan;

	if ((chan = fuse_mount(mountpoint, &args)) == NULL) {
		return -1;
	}
	if ((fuse = fuse_new(chan, &args, &rvaultfs_ops,
	    sizeof(rvaultfs_ops), vault)) == NULL) {
		fuse_unmount(mountpoint, chan);
		return -1;
	}
	(void)fuse_daemonize(fg);
	ret = fuse_loop(fuse);
	app_log(LOG_DEBUG, "%s: exited fuse_loop() with %d", __func__, ret);
	fuse_unmount(mountpoint, chan);
#endif
	fuse_destroy(fuse);
	fuse_opt_free_args(&args);
	return ret;
}
