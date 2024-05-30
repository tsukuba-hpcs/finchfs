#include <stdint.h>
#include <ucp/api/ucp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "config.h"
#include "finchfs.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "path.h"
#include "log.h"

static size_t finchfs_chunk_size = 65536;
static const int fd_table_size = 1024;
static struct fd_table {
	char *path;
	uint8_t access;
	mode_t mode;
	size_t chunk_size;
	off_t pos;
	size_t size;
	uint64_t i_ino;
	uint64_t eid;
} *fd_table;

#define IS_NULL_STRING(str) (str == NULL || str[0] == '\0')

int
finchfs_init(const char *addrfile)
{
	char *log_level;
	char *chunk_size;
	log_level = getenv("FINCHFS_LOG_LEVEL");
	if (!IS_NULL_STRING(log_level)) {
		log_set_level(log_level);
	}
	chunk_size = getenv("FINCHFS_CHUNK_SIZE");
	if (!IS_NULL_STRING(chunk_size)) {
		finchfs_chunk_size = strtoul(chunk_size, NULL, 10);
	}
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

const char *
finchfs_version()
{
	return (VERSION);
}

void
finchfs_set_chunk_size(size_t chunk_size)
{
	finchfs_chunk_size = chunk_size;
}

int
finchfs_create(const char *path, int32_t flags, mode_t mode)
{
	log_debug("finchfs_create_chunk_size() called path=%s", path);
	return finchfs_create_chunk_size(path, flags, mode, finchfs_chunk_size);
}

int
finchfs_create_chunk_size(const char *path, int32_t flags, mode_t mode,
			  size_t chunk_size)
{
	log_debug("finchfs_create_chunk_size() called path=%s chunk_size=%zu",
		  path, chunk_size);
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
	fd_table[fd].access = flags & 0b11;
	fd_table[fd].mode = mode;
	fd_table[fd].chunk_size = chunk_size;
	fd_table[fd].pos = 0;
	fd_table[fd].i_ino = 0;
	fd_table[fd].size = 0;
	fd_table[fd].eid = 0;

	mode |= S_IFREG;
	ret = fs_rpc_inode_create(p, flags & 0b11, mode, chunk_size,
				  &fd_table[fd].i_ino, &fd_table[fd].size,
				  &fd_table[fd].eid);
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
	log_debug("finchfs_open() called path=%s", path);
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
	fd_table[fd].access = flags & 0b11;
	fd_table[fd].pos = 0;
	fs_stat_t st;
	ret = fs_rpc_inode_stat(p, &st, (fd_table[fd].access << 1) + 1);
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
	fd_table[fd].size = st.size;
	fd_table[fd].eid = st.eid;
	log_debug("finchfs_open() called path=%s inode=%d chunk_size=%zu", path,
		  st.i_ino, st.chunk_size);
	return (fd);
}

int
finchfs_close(int fd)
{
	log_debug("finchfs_close() called fd=%d", fd);
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	int ret;
	ret = fs_rpc_inode_close(fd_table[fd].path, fd_table[fd].eid,
				 fd_table[fd].access, fd_table[fd].size);
	free(fd_table[fd].path);
	fd_table[fd].path = NULL;
	return (ret);
}

ssize_t
finchfs_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
	ssize_t ret;
	uint64_t index;
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
	if (fd_table[fd].access == O_RDONLY) {
		errno = EPERM;
		return (-1);
	}
	if (size == 0) {
		return (0);
	}
	log_debug("finchfs_pwrite() called ino=%zu size=%zu offset=%ld",
		  fd_table[fd].i_ino, size, offset);
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
	if (ret < size) {
		log_debug("finchfs_pwrite() wrote less than requested req=%zu "
			  "ret=%zu",
			  (size_t)size, ret);
	}
	free(hdles);
	if (ret >= 0 && offset + ret > fd_table[fd].size) {
		fd_table[fd].size = offset + ret;
	}
	return (ret);
}

ssize_t
finchfs_write(int fd, const void *buf, size_t size)
{
	log_debug("finchfs_write() called fd=%d size=%zu", fd, size);
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
	uint64_t index;
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
	if (fd_table[fd].access == O_WRONLY) {
		errno = EPERM;
		return (-1);
	}
	if (size == 0) {
		return (0);
	}
	log_debug("finchfs_pread() called ino=%zu size=%zu offset=%ld",
		  fd_table[fd].i_ino, size, offset);
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
		fs_async_rpc_inode_read_wait(hdles, nreq, fd_table[fd].size);
		free(hdles);
		return (ret);
	}
	ret = fs_async_rpc_inode_read_wait(hdles, nchunks, fd_table[fd].size);
	log_debug("fs_async_rpc_inode_read_wait succeeded ret=%d", ret);
	free(hdles);
	if (ret < size) {
		log_debug("finchfs_pread() read less than requested req=%zu "
			  "ret=%zu",
			  (size_t)size, ret);
	}
	if (ret >= 0 && offset + ret > fd_table[fd].size) {
		fd_table[fd].size = offset + ret;
	}
	return (ret);
}

ssize_t
finchfs_read(int fd, void *buf, size_t size)
{
	log_debug("finchfs_read() called fd=%d size=%zu", fd, size);
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

off_t
finchfs_seek(int fd, off_t offset, int whence)
{
	log_debug("finchfs_seek() called fd=%d offset=%ld whence=%d", fd,
		  offset, whence);
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	switch (whence) {
	case SEEK_SET:
		fd_table[fd].pos = offset;
		break;
	case SEEK_CUR:
		fd_table[fd].pos += offset;
		break;
	case SEEK_END:
		fd_table[fd].pos = fd_table[fd].size + offset;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	return (fd_table[fd].pos);
}

int
finchfs_fsync(int fd)
{
	log_debug("finchfs_fsync() called fd=%d", fd);
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	int ret;
	ret = fs_rpc_inode_fsync(fd_table[fd].path, fd_table[fd].eid,
				 &fd_table[fd].size);
	return (ret);
}

int
finchfs_unlink(const char *path)
{
	log_debug("finchfs_unlink() called path=%s", path);
	int ret;
	uint64_t i_ino;
	char *p = canonical_path(path);
	ret = fs_rpc_inode_unlink(p, &i_ino);
	free(p);
	return (ret);
}

int
finchfs_mkdir(const char *path, mode_t mode)
{
	log_debug("finchfs_mkdir() called path=%s", path);
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
	log_debug("finchfs_rmdir() called path=%s", path);
	int ret;
	char *p = canonical_path(path);
	ret = fs_rpc_inode_unlink_all(p);
	free(p);
	return (ret);
}

int
finchfs_stat(const char *path, struct stat *st)
{
	log_debug("finchfs_stat() called path=%s", path);
	char *p = canonical_path(path);
	fs_stat_t fst;
	int ret;
	ret = fs_rpc_inode_stat(p, &fst, 0);
	if (ret) {
		free(p);
		return (-1);
	}
	st->st_mode = fst.mode;
	st->st_uid = getuid();
	st->st_gid = getgid();
	st->st_size = fst.size;
	st->st_mtim = fst.mtime;
	st->st_ctim = fst.ctime;
	st->st_nlink = 1;
	st->st_ino = fst.i_ino;
	st->st_blksize = fst.chunk_size;
	st->st_blocks = NUM_BLOCKS(fst.size);
	free(p);
	return (0);
}

int
finchfs_readdir(const char *path, void *buf,
		void (*filler)(void *, const char *, const struct stat *))
{
	log_debug("finchfs_readdir() called path=%s", path);
	int ret;
	char *p = canonical_path(path);
	ret = fs_rpc_readdir(p, buf, filler);
	free(p);
	return (ret);
}

int
finchfs_rename(const char *oldpath, const char *newpath)
{
	log_debug("finchfs_rename() called oldpath=%s newpath=%s", oldpath,
		  newpath);
	int ret;
	char *oldp = canonical_path(oldpath);
	char *newp = canonical_path(newpath);
	fs_stat_t st;
	uint64_t eid;
	ret = fs_rpc_inode_stat(oldp, &st, 0);
	if (ret) {
		free(oldp);
		free(newp);
		return (-1);
	}
	if (S_ISDIR(st.mode)) {
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
	ret = fs_rpc_inode_create(newp, 0, st.mode, st.chunk_size, &st.i_ino,
				  &st.size, &eid);
	free(oldp);
	free(newp);
	return (ret);
}

int
finchfs_find(const char *path, const char *query,
	     struct finchfs_find_param *param, void *buf,
	     void (*filler)(void *, const char *))
{
	log_debug("finchfs_find() called path=%s query=%s", path, query);
	int ret;
	char *p = canonical_path(path);
	ret = fs_rpc_find(p, query, param, buf, filler);
	free(p);
	return (ret);
}
