#define _ATFILE_SOURCE
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "finchfs.h"

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;

#define FINCH_FD_SHIFT 28

char *prefix = "/finchfs";
int prefix_len = 8;

static long
hook_read(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	void *buf = a3;
	size_t count = a4;
	ssize_t ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_read(fd ^ (1 << FINCH_FD_SHIFT), buf, count);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_write(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	void *buf = a3;
	size_t count = a4;
	ssize_t ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_write(fd ^ (1 << FINCH_FD_SHIFT), buf, count);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_open(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *pathname = (char *)a2;
	int flags = a3;
	mode_t mode = a4;
	if (strncmp(pathname, prefix, prefix_len) == 0) {
		pathname += prefix_len;
		int ret;
		if (flags & O_CREAT) {
			ret = finchfs_create(pathname, flags, mode);
		} else {
			ret = finchfs_open(pathname, flags);
		}
		if (ret >= 0) {
			return ret | (1 << FINCH_FD_SHIFT);
		}
		return -errno;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_close(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	int ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_close(fd ^ (1 << FINCH_FD_SHIFT));
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_stat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	struct stat *buf = (struct stat *)a3;
	int ret;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		ret = finchfs_stat(path, buf);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_fstat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	struct stat *buf = (struct stat *)a3;
	int ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_fstat(fd ^ (1 << FINCH_FD_SHIFT), buf);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_lstat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	struct stat *buf = (struct stat *)a3;
	int ret;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		ret = finchfs_stat(path, buf);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_lseek(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	off_t offset = (off_t)a3;
	int whence = (int)a4;
	off_t ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_seek(fd ^ (1 << FINCH_FD_SHIFT), offset, whence);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_pread64(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	void *buf = (void *)a3;
	size_t count = (size_t)a4;
	off_t offset = (off_t)a5;
	ssize_t ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_pread(fd ^ (1 << FINCH_FD_SHIFT), buf, count,
				    offset);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_pwrite64(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	void *buf = (void *)a3;
	size_t count = (size_t)a4;
	off_t offset = (off_t)a5;
	ssize_t ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_pwrite(fd ^ (1 << FINCH_FD_SHIFT), buf, count,
				     offset);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_access(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	int mode = (int)a3;
	int ret;
	if (strncmp(path, prefix, prefix_len) == 0) {
		struct stat st;
		int ret;
		path += prefix_len;
		ret = finchfs_stat(path, &st);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_clone(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	long ret;
	finchfs_term();
	ret = next_sys_call(a1, a2, a3, a4, a5, a6, a7);
	if ((ret = finchfs_init(NULL))) {
		fprintf(stderr, "finchfs_init failed at %s\n", strerror(errno));
		exit(-1);
	}
	return ret;
}

static long
hook_execve(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	finchfs_term();
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_exit(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	finchfs_term();
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_fsync(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	int ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_fsync(fd ^ (1 << FINCH_FD_SHIFT));
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_truncate(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	if (strncmp(path, prefix, prefix_len) == 0) {
		// FINCHFS doen't support truncate
		return -EIO;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_ftruncate(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		// FINCHFS doen't support truncate
		return -EIO;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_getdents(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	unsigned int fd = (unsigned int)a2;
	void *dirp = (void *)a3;
	unsigned int count = (unsigned int)a4;
	ssize_t ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_getdents(fd ^ (1 << FINCH_FD_SHIFT), dirp, count);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_rename(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *oldpath = (char *)a2;
	char *newpath = (char *)a3;
	int ret;
	if (strncmp(oldpath, prefix, prefix_len) == 0 &&
	    strncmp(newpath, prefix, prefix_len) == 0) {
		oldpath += prefix_len;
		newpath += prefix_len;
		ret = finchfs_rename(oldpath, newpath);
		return ret < 0 ? -errno : ret;
	}
	if (strncmp(oldpath, prefix, prefix_len) != 0 &&
	    strncmp(newpath, prefix, prefix_len) != 0) {
		return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
	}
	return -EIO;
}

static long
hook_mkdir(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	mode_t mode = (mode_t)a3;
	int ret;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		ret = finchfs_mkdir(path, mode);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_rmdir(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	int ret;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		ret = finchfs_rmdir(path);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_creat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	mode_t mode = (mode_t)a3;
	int ret;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		ret = finchfs_create(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_unlink(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		return finchfs_unlink(path);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_getdents64(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	void *dirp = (void *)a3;
	size_t count = (size_t)a4;
	ssize_t ret;
	if ((fd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_getdents(fd ^ (1 << FINCH_FD_SHIFT), dirp, count);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_openat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int dirfd = (int)a2;
	char *path = (char *)a3;
	int flags = (int)a4;
	mode_t mode = (mode_t)a5;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		int ret;
		if (flags & O_CREAT) {
			ret = finchfs_create(path, flags, mode);
		} else {
			ret = finchfs_open(path, flags);
		}
		if (ret >= 0) {
			return ret | (1 << FINCH_FD_SHIFT);
		}
		return -errno;
	}
	if ((dirfd >> FINCH_FD_SHIFT) == 1) {
		int ret;
		if (flags & O_CREAT) {
			ret = finchfs_createat(dirfd ^ (1 << FINCH_FD_SHIFT),
					       path, flags, mode);
		} else {
			ret = finchfs_openat(dirfd ^ (1 << FINCH_FD_SHIFT),
					     path, flags);
		}
		if (ret >= 0) {
			return ret | (1 << FINCH_FD_SHIFT);
		}
		return -errno;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_mkdirat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int dirfd = (int)a2;
	char *path = (char *)a3;
	mode_t mode = (mode_t)a4;
	int ret;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		ret = finchfs_mkdir(path, mode);
		return ret < 0 ? -errno : ret;
	}
	if ((dirfd >> FINCH_FD_SHIFT) == 1) {
		ret =
		    finchfs_mkdirat(dirfd ^ (1 << FINCH_FD_SHIFT), path, mode);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_newfstatat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int dirfd = (int)a2;
	char *pathname = (char *)a3;
	struct stat *st = (struct stat *)a4;
	int flags = (int)a5;
	int ret;
	if (strncmp(pathname, prefix, prefix_len) == 0) {
		pathname += prefix_len;
		ret = finchfs_stat(pathname, st);
		return ret < 0 ? -errno : ret;
	}
	if ((dirfd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_fstatat(dirfd ^ (1 << FINCH_FD_SHIFT), pathname,
				      st, flags);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_unlinkat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int dirfd = (int)a2;
	char *path = (char *)a3;
	int flags = (int)a4;
	int ret;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		if (flags & AT_REMOVEDIR) {
			ret = finchfs_rmdir(path);
		} else {
			ret = finchfs_unlink(path);
		}
		return ret < 0 ? -errno : ret;
	}
	if ((dirfd >> FINCH_FD_SHIFT) == 1) {
		ret = finchfs_unlinkat(dirfd ^ (1 << FINCH_FD_SHIFT), path,
				       flags);
		return ret < 0 ? -errno : ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_renameat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int olddirfd = (int)a2;
	char *oldpath = (char *)a3;
	int newdirfd = (int)a4;
	char *newpath = (char *)a5;
	int ret;
	if (strncmp(oldpath, prefix, prefix_len) == 0 &&
	    strncmp(newpath, prefix, prefix_len) == 0) {
		oldpath += prefix_len;
		newpath += prefix_len;
		ret = finchfs_rename(oldpath, newpath);
		return ret < 0 ? -errno : ret;
	}
	if ((olddirfd >> FINCH_FD_SHIFT) == 1 &&
	    (newdirfd >> FINCH_FD_SHIFT) == 1) {
		ret =
		    finchfs_renameat(olddirfd ^ (1 << FINCH_FD_SHIFT), oldpath,
				     newdirfd ^ (1 << FINCH_FD_SHIFT), newpath);
		return ret < 0 ? -errno : ret;
	}
	if (strncmp(oldpath, prefix, prefix_len) == 0 &&
	    (newdirfd >> FINCH_FD_SHIFT) == 1) {
		oldpath += prefix_len;
		ret =
		    finchfs_renameat(olddirfd, oldpath,
				     newdirfd ^ (1 << FINCH_FD_SHIFT), newpath);
		return ret < 0 ? -errno : ret;
	}
	if ((olddirfd >> FINCH_FD_SHIFT) == 1 &&
	    strncmp(newpath, prefix, prefix_len) == 0) {
		newpath += prefix_len;
		ret = finchfs_renameat(olddirfd ^ (1 << FINCH_FD_SHIFT),
				       oldpath, newdirfd, newpath);
		return ret < 0 ? -errno : ret;
	}
	if ((olddirfd >> FINCH_FD_SHIFT) == 1 ||
	    (newdirfd >> FINCH_FD_SHIFT) == 1 ||
	    strncmp(oldpath, prefix, prefix_len) == 0 ||
	    strncmp(newpath, prefix, prefix_len) == 0) {
		return -EIO;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_statx(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int dirfd = (int)a2;
	char *pathname = (char *)a3;
	int flags = (int)a4;
	unsigned int mask = (unsigned int)a5;
	struct statx *stx = (struct statx *)a6;
	if (strncmp(pathname, prefix, prefix_len) == 0) {
		pathname += prefix_len;
		struct stat st;
		int ret = finchfs_stat(pathname, &st);
		if (ret < 0)
			return (-errno);
		stx->stx_dev_major = st.st_dev;
		stx->stx_ino = st.st_ino;
		stx->stx_mode = st.st_mode;
		stx->stx_nlink = st.st_nlink;
		stx->stx_uid = st.st_uid;
		stx->stx_gid = st.st_gid;
		stx->stx_rdev_major = st.st_rdev;
		stx->stx_size = st.st_size;
		stx->stx_blksize = st.st_blksize;
		stx->stx_atime.tv_sec = st.st_atime;
		stx->stx_mtime.tv_sec = st.st_mtime;
		stx->stx_ctime.tv_sec = st.st_ctime;
		return (0);
	}
	if ((dirfd >> FINCH_FD_SHIFT) == 1) {
		struct stat st;
		int ret = finchfs_fstatat(dirfd ^ (1 << FINCH_FD_SHIFT),
					  pathname, &st, flags);
		if (ret < 0)
			return (-errno);
		stx->stx_dev_major = st.st_dev;
		stx->stx_ino = st.st_ino;
		stx->stx_mode = st.st_mode;
		stx->stx_nlink = st.st_nlink;
		stx->stx_uid = st.st_uid;
		stx->stx_gid = st.st_gid;
		stx->stx_rdev_major = st.st_rdev;
		stx->stx_size = st.st_size;
		stx->stx_blksize = st.st_blksize;
		stx->stx_atime.tv_sec = st.st_atime;
		stx->stx_mtime.tv_sec = st.st_mtime;
		stx->stx_ctime.tv_sec = st.st_ctime;
		return (0);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_function(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	long ret;
	switch (a1) {
	case SYS_read:
		ret = hook_read(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_write:
		ret = hook_write(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_open:
		ret = hook_open(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_close:
		ret = hook_close(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_stat:
		ret = hook_stat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_fstat:
		ret = hook_fstat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_lstat:
		ret = hook_lstat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_pread64:
		ret = hook_pread64(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_pwrite64:
		ret = hook_pwrite64(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_access:
		ret = hook_access(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_clone:
		ret = hook_clone(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_execve:
		ret = hook_execve(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_exit:
		ret = hook_exit(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_fsync:
		ret = hook_fsync(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_truncate:
		ret = hook_truncate(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_ftruncate:
		ret = hook_ftruncate(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_getdents:
		ret = hook_getdents(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_rename:
		ret = hook_rename(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_mkdir:
		ret = hook_mkdir(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_rmdir:
		ret = hook_rmdir(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_creat:
		ret = hook_creat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_unlink:
		ret = hook_unlink(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_getdents64:
		ret = hook_getdents64(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_openat:
		ret = hook_openat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_mkdirat:
		ret = hook_mkdirat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_newfstatat:
		ret = hook_newfstatat(a1, a2, a3, a4, a5, a6, a7);
		break;
		break;
	case SYS_unlinkat:
		ret = hook_unlinkat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_renameat:
		ret = hook_renameat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_statx:
		ret = hook_statx(a1, a2, a3, a4, a5, a6, a7);
		break;
	default:
		ret = next_sys_call(a1, a2, a3, a4, a5, a6, a7);
		break;
	}
	return ret;
}

int
__hook_init(long placeholder __attribute__((unused)), void *sys_call_hook_ptr)
{
	int ret;
	next_sys_call = *((syscall_fn_t *)sys_call_hook_ptr);
	*((syscall_fn_t *)sys_call_hook_ptr) = hook_function;
	if ((ret = finchfs_init(NULL))) {
		fprintf(stderr, "finchfs_init failed at %s\n", strerror(errno));
		exit(-1);
	}
	return 0;
}

void __hook_cleanup(void) __attribute__((destructor));

void
__hook_cleanup(void)
{
	finchfs_term();
}
