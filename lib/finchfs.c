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

#define IS_NULL_STRING(str) (str == NULL || str[0] == '\0')

int
finchfs_init(const char *addrfile)
{
	char *log_level;
	char *chunk_size;
	if (fs_client_init((char *)addrfile)) {
		return (-1);
	}
	fd_table = malloc(sizeof(struct fd_table) * fd_table_size);
	for (int i = 0; i < fd_table_size; ++i) {
		fd_table[i].path = NULL;
	}
	log_level = getenv("FINCHFS_LOG_LEVEL");
	if (!IS_NULL_STRING(log_level)) {
		log_set_level(log_level);
	}
	chunk_size = getenv("FINCHFS_CHUNK_SIZE");
	if (!IS_NULL_STRING(chunk_size)) {
		finchfs_chunk_size = strtoul(chunk_size, NULL, 10);
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
	fd_table[fd].i_ino = 0;

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
	if (S_ISDIR(st.mode)) {
		log_error("directory open is not supported");
		free(fd_table[fd].path);
		fd_table[fd].path = NULL;
		return (-1);
	}
	fd_table[fd].i_ino = st.i_ino;
	fd_table[fd].mode = st.mode;
	fd_table[fd].chunk_size = st.chunk_size;
	log_debug("finchfs_open() called path=%s inode=%d chunk_size=%zu", path,
		  st.i_ino, st.chunk_size);
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

ssize_t
finchfs_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
	ssize_t ret;
	uint32_t index;
	off_t local_pos;
	size_t chunk_size;
	size_t tot;
	int nchunks;
	void **hdles;
	void *buf_p;
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	if (offset < 0) {
		errno = EINVAL;
		return (-1);
	}
	if (size == 0) {
		return (0);
	}
	chunk_size = fd_table[fd].chunk_size;
	index = offset / chunk_size;
	local_pos = offset % chunk_size;
	nchunks = (local_pos + size + chunk_size - 1) / chunk_size;
	hdles = malloc(sizeof(void *) * nchunks);
	ret = 0;
	tot = 0;
	buf_p = (void *)buf;
	for (int i = 0; i < nchunks; ++i) {
		size_t local_size = chunk_size - local_pos;
		if (local_size > size - tot) {
			local_size = size - tot;
		}
		tot += local_size;
		hdles[i] =
		    fs_async_rpc_inode_write(fd_table[fd].i_ino, index + i,
					     local_pos, local_size, buf_p);
		if (hdles[i] == NULL) {
			log_debug("fs_async_rpc_inode_write failed at=%d", i);
			errno = EIO;
			ret = -1;
		}
		local_pos = 0;
		buf_p += local_size;
	}
	if (ret < 0) {
		int nreq = 0;
		for (int i = 0; i < nchunks; ++i) {
			if (hdles[i]) {
				hdles[nreq++] = hdles[i];
			}
		}
		fs_async_rpc_inode_write_wait(hdles, nreq);
		free(hdles);
		return (ret);
	}
	ret = fs_async_rpc_inode_write_wait(hdles, nchunks);
	log_debug("fs_async_rpc_inode_write_wait succeeded ret=%d", ret);
	free(hdles);
	return (ret);
}

ssize_t
finchfs_write(int fd, const void *buf, size_t size)
{
	ssize_t ret;
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	ret = finchfs_pwrite(fd, buf, size, fd_table[fd].pos);
	if (ret >= 0) {
		fd_table[fd].pos += ret;
	}
	return (ret);
}

ssize_t
finchfs_pread(int fd, void *buf, size_t size, off_t offset)
{
	ssize_t ret;
	uint32_t index;
	off_t local_pos;
	size_t chunk_size;
	size_t tot;
	int nchunks;
	void **hdles;
	void *buf_p;
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	if (offset < 0) {
		errno = EINVAL;
		return (-1);
	}
	if (size == 0) {
		return (0);
	}
	chunk_size = fd_table[fd].chunk_size;
	index = offset / chunk_size;
	local_pos = offset % chunk_size;
	nchunks = (local_pos + size + chunk_size - 1) / chunk_size;
	hdles = malloc(sizeof(void *) * nchunks);
	ret = 0;
	tot = 0;
	buf_p = (void *)buf;
	for (int i = 0; i < nchunks; ++i) {
		size_t local_size = chunk_size - local_pos;
		if (local_size > size - tot) {
			local_size = size - tot;
		}
		tot += local_size;
		hdles[i] =
		    fs_async_rpc_inode_read(fd_table[fd].i_ino, index + i,
					    local_pos, local_size, buf_p);
		if (hdles[i] == NULL) {
			log_debug("fs_async_rpc_inode_read failed at=%d", i);
			errno = EIO;
			ret = -1;
		}
		local_pos = 0;
		buf_p += local_size;
	}
	if (ret < 0) {
		int nreq = 0;
		for (int i = 0; i < nchunks; ++i) {
			if (hdles[i]) {
				hdles[nreq++] = hdles[i];
			}
		}
		fs_async_rpc_inode_write_wait(hdles, nreq);
		free(hdles);
		return (ret);
	}
	ret = fs_async_rpc_inode_read_wait(hdles, nchunks);
	log_debug("fs_async_rpc_inode_read_wait succeeded ret=%d", ret);
	free(hdles);
	return (ret);
}

ssize_t
finchfs_read(int fd, void *buf, size_t size)
{
	ssize_t ret;
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	ret = finchfs_pread(fd, buf, size, fd_table[fd].pos);
	if (ret >= 0) {
		fd_table[fd].pos += ret;
	}
	return (ret);
}

int
finchfs_unlink(const char *path)
{
	int ret;
	uint32_t i_ino;
	char *p = canonical_path(path);
	ret = fs_rpc_inode_unlink(p, &i_ino);
	free(p);
	return (ret);
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
	int ret;
	char *p = canonical_path(path);
	ret = fs_rpc_inode_unlink_all(p);
	free(p);
	return (ret);
}

int
finchfs_rename(const char *oldpath, const char *newpath)
{
	int ret;
	char *oldp = canonical_path(oldpath);
	char *newp = canonical_path(newpath);
	fs_stat_t st;
	ret = fs_rpc_inode_stat(oldp, &st);
	if (ret) {
		free(oldp);
		free(newp);
		return (-1);
	}
	if (S_ISDIR(st.mode)) {
		int ret;
		ret = fs_rpc_dir_move(oldp, newp);
		free(oldp);
		free(newp);
		return (ret);
	}
	log_debug("finchfs_rename() called oldpath=%s newpath=%s inode=%d",
		  oldpath, newpath, st.i_ino);
	ret = fs_rpc_inode_unlink(oldp, &st.i_ino);
	if (ret) {
		free(oldp);
		free(newp);
		return (-1);
	}
	log_debug("finchfs_rename(): unlink inode=%d", st.i_ino);
	ret = fs_rpc_inode_create(newp, st.mode, st.chunk_size, &st.i_ino);
	free(oldp);
	free(newp);
	return (ret);
}
