#include <stdint.h>
#include <ucp/api/ucp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include "finchfs.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "path.h"
#include "log.h"

static size_t finchfs_chunk_size = 65536;

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
	return fs_client_term();
}

int
finchfs_create(const char *path, int32_t flags, mode_t mode)
{
	return finchfs_create_chunk_size(path, flags, mode, finchfs_chunk_size);
}

int
finchfs_create_chunk_size(const char *path, int32_t flags, mode_t mode,
			  size_t chunk_size)
{
	char *p = canonical_path(path);
	int ret;
	mode |= S_IFREG;
	ret = fs_rpc_inode_create(p, mode, chunk_size);
	free(p);
	if (ret) {
		return (-1);
	}
	return (0);
}

int
finchfs_open(const char *path, int32_t flags)
{
	char *p = canonical_path(path);
	int ret;
	fs_stat_t st;
	ret = fs_rpc_inode_stat(p, &st);
	free(p);
	if (ret) {
		return (-1);
	}
	log_debug("finchfs_open() called path=%s inode=%d", path, st.i_ino);
	return (0);
}

int
finchfs_close(int fd)
{
	return 0;
}

int
finchfs_mkdir(const char *path, mode_t mode)
{
	int ret;
	char *p = canonical_path(path);
	mode |= S_IFDIR;
	ret = fs_rpc_mkdir(p, mode);
	free(p);
	return (ret);
}

int
finchfs_rmdir(const char *path)
{
	return 0;
}
