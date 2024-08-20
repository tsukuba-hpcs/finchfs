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

#define FINCH_FD_MASK (1 << 28)

char *prefix = "/finchfs/";
int prefix_len = 9;

static long
hook_read(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	void *buf = a3;
	size_t count = a4;
	if (fd & FINCH_FD_MASK) {
		return finchfs_read(fd ^ FINCH_FD_MASK, buf, count);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_write(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	void *buf = a3;
	size_t count = a4;
	if (fd & FINCH_FD_MASK) {
		return finchfs_write(fd ^ FINCH_FD_MASK, buf, count);
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
			return ret | FINCH_FD_MASK;
		}
		return ret;
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

static long
hook_close(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	int fd = a2;
	if (fd & FINCH_FD_MASK) {
		return finchfs_close(fd ^ FINCH_FD_MASK);
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
	case SYS_execve:
		ret = hook_execve(a1, a2, a3, a4, a5, a6, a7);
		break;
	case SYS_clone:
		ret = hook_clone(a1, a2, a3, a4, a5, a6, a7);
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
