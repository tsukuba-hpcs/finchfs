#include <stdint.h>
#include "finchfs.h"
#include "fs_rpc.h"
#include "log.h"

int
finchfs_init(const char *addrfile)
{
	if (fs_client_init((char *)addrfile)) {
		return (-1);
	}
	return 0;
}

int
finchfs_term()
{
	return 0;
}

int
finchfs_open(const char *path, int32_t flags)
{
	return 0;
}

int
finchfs_close(int fd)
{
	return 0;
}
