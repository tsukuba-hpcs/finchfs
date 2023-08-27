#include <stdint.h>
#include <ucp/api/ucp.h>
#include <fcntl.h>
#include "finchfs.h"
#include "fs_rpc.h"
#include "path.h"
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

int
finchfs_mkdir(const char *path, mode_t mode)
{
	char *p = canonical_path(path);
	if (p == NULL) {
		return (-1);
	}
	return fs_rpc_mkdir(p, mode);
}

int
finchfs_rmdir(const char *path)
{
	return 0;
}
