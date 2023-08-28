#include <stdint.h>
#include <ucp/api/ucp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "finchfs.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "path.h"
#include "log.h"

static size_t finchfs_chunk_size = 65536;
static const int fd_table_size = 1024;
static struct fd_table {
	char *path;
	mode_t mode;
	size_t chunk_size;
	off_t pos;
	uint32_t i_ino;
} *fd_table;

int
finchfs_init(const char *addrfile)
{
	if (fs_client_init((char *)addrfile)) {
		return (-1);
	}
	fd_table = malloc(sizeof(struct fd_table) * fd_table_size);
	for (int i = 0; i < fd_table_size; ++i) {
		fd_table[i].path = NULL;
	}
	return 0;
}

int
finchfs_term()
{
	for (int i = 0; i < fd_table_size; ++i) {
		if (fd_table[i].path) {
			free(fd_table[i].path);
		}
	}
	free(fd_table);
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
	int fd;
	for (fd = 0; fd < fd_table_size; ++fd) {
		if (fd_table[fd].path == NULL) {
			break;
		}
	}
	if (fd == fd_table_size) {
		errno = EMFILE;
		return (-1);
	}
	fd_table[fd].path = p;
	fd_table[fd].mode = mode;
	fd_table[fd].chunk_size = chunk_size;
	fd_table[fd].pos = 0;

	mode |= S_IFREG;
	ret = fs_rpc_inode_create(p, mode, chunk_size, &fd_table[fd].i_ino);
	if (ret) {
		free(fd_table[fd].path);
		fd_table[fd].path = NULL;
		return (-1);
	}
	return (fd);
}

int
finchfs_open(const char *path, int32_t flags)
{
	char *p = canonical_path(path);
	int ret;
	int fd;
	for (fd = 0; fd < fd_table_size; ++fd) {
		if (fd_table[fd].path == NULL) {
			break;
		}
	}
	if (fd == fd_table_size) {
		errno = EMFILE;
		return (-1);
	}
	fd_table[fd].path = p;
	fd_table[fd].pos = 0;
	fs_stat_t st;
	ret = fs_rpc_inode_stat(p, &st);
	if (ret) {
		free(fd_table[fd].path);
		fd_table[fd].path = NULL;
		return (-1);
	}
	fd_table[fd].i_ino = st.i_ino;
	fd_table[fd].mode = st.mode;
	fd_table[fd].chunk_size = st.chunk_size;
	log_debug("finchfs_open() called path=%s inode=%d", path, st.i_ino);
	return (fd);
}

int
finchfs_close(int fd)
{
	if (fd < 0 || fd >= fd_table_size) {
		errno = EBADF;
		return (-1);
	}
	if (fd_table[fd].path) {
		free(fd_table[fd].path);
		fd_table[fd].path = NULL;
	}
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
