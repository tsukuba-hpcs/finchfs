#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "finchfs.h"

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;

static long
hook_function(long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	long ret;
	ret = next_sys_call(a1, a2, a3, a4, a5, a6, a7);
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
