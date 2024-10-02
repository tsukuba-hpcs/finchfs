#define _ATFILE_SOURCE
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

#define FINCH_FD_SHFT 28

char *prefix = "/finchfs/";
int prefix_len = 9;

static long
hook_read(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	void *buf = a3;
	size_t count = a4;
	if ((fd >> FINCH_FD_SHFT) == 1) {
		return finchfs_read(fd ^ (1 << FINCH_FD_SHFT), buf, count);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_write(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	void *buf = a3;
	size_t count = a4;
	if ((fd >> FINCH_FD_SHFT) == 1) {
		return finchfs_write(fd ^ (1 << FINCH_FD_SHFT), buf, count);
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
			return ret | (1 << FINCH_FD_SHFT);
		}
		return ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_close(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	if ((fd >> FINCH_FD_SHFT) == 1) {
		return finchfs_close(fd ^ (1 << FINCH_FD_SHFT));
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_stat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	struct stat *buf = (struct stat *)a3;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		return finchfs_stat(path, buf);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_fstat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	struct stat *buf = (struct stat *)a3;
	if ((fd >> FINCH_FD_SHFT) == 1) {
		return finchfs_fstat(fd ^ (1 << FINCH_FD_SHFT), buf);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_lstat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	struct stat *buf = (struct stat *)a3;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		return finchfs_stat(path, buf);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_lseek(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = (int)a2;
	off_t offset = (off_t)a3;
	int whence = (int)a4;
	if ((fd >> FINCH_FD_SHFT) == 1) {
		return finchfs_seek(fd ^ (1 << FINCH_FD_SHFT), offset, whence);
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
	if ((fd >> FINCH_FD_SHFT) == 1) {
		return finchfs_pread(fd ^ (1 << FINCH_FD_SHFT), buf, count,
				     offset);
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
	if ((fd >> FINCH_FD_SHFT) == 1) {
		return finchfs_pwrite(fd ^ (1 << FINCH_FD_SHFT), buf, count,
				      offset);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_access(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	int mode = (int)a3;
	if (strncmp(path, prefix, prefix_len) == 0) {
		struct stat st;
		int ret;
		path += prefix_len;
		return finchfs_stat(path, &st);
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
	if ((fd >> FINCH_FD_SHFT) == 1) {
		return finchfs_fsync(fd ^ (1 << FINCH_FD_SHFT));
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
	if ((fd >> FINCH_FD_SHFT) == 1) {
		// FINCHFS doen't support truncate
		return -EIO;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_rename(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *oldpath = (char *)a2;
	char *newpath = (char *)a3;
	if (strncmp(oldpath, prefix, prefix_len) == 0 &&
	    strncmp(newpath, prefix, prefix_len) == 0) {
		oldpath += prefix_len;
		newpath += prefix_len;
		return finchfs_rename(oldpath, newpath);
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
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		return finchfs_mkdir(path, mode);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_rmdir(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		return finchfs_rmdir(path);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_creat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a2;
	mode_t mode = (mode_t)a3;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		return finchfs_create(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
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
hook_openat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
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
			return ret | (1 << FINCH_FD_SHFT);
		}
		return ret;
	}
}

static long
hook_mkdirat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a3;
	mode_t mode = (mode_t)a4;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		return finchfs_mkdir(path, mode);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_unlinkat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *path = (char *)a3;
	int flags = (int)a4;
	if (strncmp(path, prefix, prefix_len) == 0) {
		path += prefix_len;
		if (flags & AT_REMOVEDIR) {
			return finchfs_rmdir(path);
		} else {
			return finchfs_unlink(path);
		}
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_renameat(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	char *oldpath = (char *)a3;
	char *newpath = (char *)a5;
	if (strncmp(oldpath, prefix, prefix_len) == 0 &&
	    strncmp(newpath, prefix, prefix_len) == 0) {
		oldpath += prefix_len;
		newpath += prefix_len;
		return finchfs_rename(oldpath, newpath);
	}
	if (strncmp(oldpath, prefix, prefix_len) != 0 &&
	    strncmp(newpath, prefix, prefix_len) != 0) {
		return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
	}
	return -EIO;
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
	case SYS_openat:
		ret = hook_openat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_mkdirat:
		ret = hook_mkdirat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_unlinkat:
		ret = hook_unlinkat(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_renameat:
		ret = hook_renameat(a1, a2, a3, a4, a5, a6, a7);
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
