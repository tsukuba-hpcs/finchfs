#define _ATFILE_SOURCE
#define _GNU_SOURCE
#include <stdint.h>
#include <ucp/api/ucp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <poll.h>
#include <sys/mman.h>
#include <string.h>
#include "config.h"
#include "finchfs.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "path.h"
#include "log.h"

static size_t finchfs_chunk_size = 65536;
static const int fd_table_size = 1024;
static int nvprocs = 1;
static long uffd;
static struct fd_table {
	char *path;
	uint8_t access;
	mode_t mode;
	size_t chunk_size;
	off_t pos;
	size_t size;
	uint64_t i_ino;
	struct timespec mtime;
	struct timespec ctime;
	uint64_t *eid;
	uint32_t nlink;
	struct {
		int rank;
		uint64_t pos;
	} getdents_state;
} *fd_table;
#define IS_NULL_STRING(str) (str == NULL || str[0] == '\0')

#ifdef FINCH_MMAP_SUPPORT
struct mmap_item;

typedef struct mmap_item {
	uint64_t addr;
	size_t len;
	uint64_t i_ino;
	size_t chunk_size;
	off_t offset;
	size_t *size;
	struct mmap_item *prev;
	struct mmap_item *next;
} mmap_item_t;

struct mmap_manager {
	mmap_item_t *head;
	mmap_item_t *tail;
} mm_mng;

void
add_mmap_item(mmap_item_t *item)
{
	item->prev = mm_mng.tail;
	item->next = NULL;
	if (mm_mng.tail) {
		mm_mng.tail->next = item;
	} else {
		mm_mng.head = item;
	}
	mm_mng.tail = item;
}

int
del_mmap_item(uint64_t addr, size_t len)
{
	mmap_item_t *cur;
	cur = mm_mng.head;
	while (cur) {
		if (cur->addr == addr && cur->len == len) {
			if (cur->prev) {
				cur->prev->next = cur->next;
			} else {
				mm_mng.head = cur->next;
			}
			if (cur->next) {
				cur->next->prev = cur->prev;
			} else {
				mm_mng.tail = cur->prev;
			}
			free(cur);
			return (0);
		}
		cur = cur->next;
	}
	return (1);
}

mmap_item_t *
query_mmap(uint64_t fault_addr)
{
	mmap_item_t *cur;
	cur = mm_mng.tail;
	while (cur) {
		if (cur->addr <= fault_addr &&
		    fault_addr < cur->addr + cur->len) {
			return cur;
		}
		cur = cur->prev;
	}
	return (NULL);
}

static void *
fault_handler_thread(void *arg)
{
	uint64_t page_size;
	uint8_t *page;
	page_size = sysconf(_SC_PAGE_SIZE);
	page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) {
		log_error("mmap failed");
		exit(1);
	}
	while (1) {
		struct pollfd pollfd;
		struct uffdio_copy uffdio_copy;
		int nready, nchunks;
		ssize_t nread, ret;
		struct uffd_msg msg;
		mmap_item_t *item;
		uint64_t base, index;
		off_t offset, local_pos;
		size_t size, tot;
		void *buf_p, **hdles;
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		nready = poll(&pollfd, 1, -1);
		if (nready == -1) {
			log_error("poll failed");
			exit(1);
		}
		nread = read(uffd, &msg, sizeof(msg));
		if (nread == 0) {
			log_error("EOF on userfaultfd!\n");
			exit(1);
		}
		if (nread < 0) {
			log_error("read error");
			exit(1);
		}
		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			log_error("Unexpected event on userfaultfd");
			exit(1);
		}
		if ((item = query_mmap(msg.arg.pagefault.address)) == NULL) {
			log_error("mapped area not found");
			exit(1);
		}
		memset(page, 0, page_size);
		base = (uint64_t)msg.arg.pagefault.address & ~(page_size - 1);
		offset = base - item->addr + item->offset;
		buf_p = (void *)page;
		size = page_size;
		if (offset < 0) {
			buf_p = page - offset;
			size = page_size + offset;
		}
		index = offset / item->chunk_size;
		local_pos = offset % item->chunk_size;
		nchunks = (local_pos + size + item->chunk_size - 1) /
			  item->chunk_size;
		hdles = malloc(sizeof(void *) * nchunks);
		tot = 0;
		for (int i = 0; i < nchunks; ++i) {
			size_t local_size;
			local_size = item->chunk_size - local_pos;
			if (local_size > size - tot) {
				local_size = size - tot;
			}
			tot += local_size;
			hdles[i] = fs_async_rpc_inode_read(item->i_ino,
							   index + i, local_pos,
							   local_size, buf_p);
			if (hdles[i] == NULL) {
				log_error(
				    "fs_async_rpc_inode_read failed at=%d", i);
				exit(1);
			}
			local_pos = 0;
			buf_p += local_size;
		}
		ret = fs_async_rpc_inode_read_wait(hdles, nchunks, *item->size);
		free(hdles);
		if (ret < 0) {
			log_error("fs_async_rpc_inode_read_wait failed");
			exit(1);
		}
		uffdio_copy.src =
		    offset < 0 ? (uint64_t)page - offset : (uint64_t)page;
		uffdio_copy.dst = offset < 0 ? base - offset : base;
		uffdio_copy.len = offset < 0 ? page_size + offset : page_size;
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;
		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) < 0) {
			log_error("ioctl error");
			exit(1);
		}
	}
}
#endif

int
finchfs_init(const char *addrfile)
{
	char *log_level, *chunk_size;
	struct uffdio_api uffdio_api;
	pthread_t fault_handler;
	log_level = getenv("FINCHFS_LOG_LEVEL");
	if (!IS_NULL_STRING(log_level)) {
		log_set_level(log_level);
	}
	chunk_size = getenv("FINCHFS_CHUNK_SIZE");
	if (!IS_NULL_STRING(chunk_size)) {
		finchfs_chunk_size = strtoul(chunk_size, NULL, 10);
	}
	if (fs_client_init((char *)addrfile, &nvprocs)) {
		return (-1);
	}
	fd_table = malloc(sizeof(struct fd_table) * fd_table_size);
	for (int i = 0; i < fd_table_size; ++i) {
		fd_table[i].path = NULL;
		fd_table[i].eid = malloc(sizeof(uint64_t) * nvprocs);
	}
#ifdef FINCH_MMAP_SUPPORT
	if ((uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK)) < 0) {
		log_error("NOTE: /proc/sys/vm/unprivileged_userfaultfd should "
			  "be set 1");
		goto init_err;
	}
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &uffdio_api) < 0) {
		log_error("ioctl(UFFDIO_API) failed");
		goto init_err;
	}
	if (pthread_create(&fault_handler, NULL, fault_handler_thread, NULL)) {
		log_error("pthread_create failed");
		goto init_err;
	}
#endif
	return (0);
init_err:
	finchfs_term();
	return (-1);
}

int
finchfs_term()
{
	for (int i = 0; i < fd_table_size; ++i) {
		if (fd_table[i].path) {
			free(fd_table[i].path);
		}
		free(fd_table[i].eid);
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
	log_debug("finchfs_create() called path=%s", path);
	return finchfs_create_chunk_size(path, flags, mode, finchfs_chunk_size);
}

int
finchfs_create_chunk_size(const char *path, int32_t flags, mode_t mode,
			  size_t chunk_size)
{
	char *p;
	int ret, fd;
	log_debug("finchfs_create_chunk_size() called path=%s chunk_size=%zu",
		  path, chunk_size);
	p = canonical_path(path);
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
	timespec_get(&fd_table[fd].mtime, TIME_UTC);
	timespec_get(&fd_table[fd].ctime, TIME_UTC);
	fd_table[fd].eid[0] = 0;

	mode |= S_IFREG;
	ret = fs_rpc_inode_create(
	    NULL, p, (flags & 0b11) + (((flags & O_TRUNC) != 0) << 2), mode,
	    chunk_size, &fd_table[fd].i_ino, &fd_table[fd].size,
	    fd_table[fd].eid);
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
	char *p;
	int ret, fd;
	fs_stat_t st;
	log_debug("finchfs_open() called path=%s", path);
	p = canonical_path(path);
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
	if (flags & __O_DIRECTORY) {
		ret = fs_rpc_inode_open_dir(NULL, p, fd_table[fd].eid, &st,
					    1 << 4);
		if (ret) {
			free(fd_table[fd].path);
			fd_table[fd].path = NULL;
			return (-1);
		}
		fd_table[fd].getdents_state.rank = 0;
		fd_table[fd].getdents_state.pos = 0;
	} else {
		ret = fs_rpc_inode_stat(NULL, p, &st,
					(((flags & O_TRUNC) != 0) << 3) +
					    (fd_table[fd].access << 1) + 1);
		if (ret) {
			free(fd_table[fd].path);
			fd_table[fd].path = NULL;
			return (-1);
		}
		if (S_ISDIR(st.mode)) {
			log_error(
			    "To open directory, please set flag __O_DIRECTORY");
			free(fd_table[fd].path);
			fd_table[fd].path = NULL;
			return (-1);
		}
		fd_table[fd].eid[0] = st.eid;
	}
	fd_table[fd].i_ino = st.i_ino;
	fd_table[fd].mode = st.mode;
	fd_table[fd].chunk_size = st.chunk_size;
	fd_table[fd].size = st.size;
	fd_table[fd].mtime = st.mtime;
	fd_table[fd].ctime = st.ctime;
	fd_table[fd].nlink = st.nlink;
	log_debug("finchfs_open() called path=%s inode=%d chunk_size=%zu", path,
		  st.i_ino, st.chunk_size);
	return (fd);
}

int
finchfs_close(int fd)
{
	int ret;
	log_debug("finchfs_close() called fd=%d", fd);
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	ret = 0;
	if (!S_ISDIR(fd_table[fd].mode)) {
		ret =
		    fs_rpc_inode_close(fd_table[fd].path, fd_table[fd].eid[0],
				       fd_table[fd].access, fd_table[fd].size);
	}
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
	size_t chunk_size, tot;
	int nchunks;
	void *buf_p, **hdles;
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
		size_t local_size;
		local_size = chunk_size - local_pos;
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
		int nreq;
		nreq = 0;
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
	ssize_t ret;
	log_debug("finchfs_write() called fd=%d size=%zu", fd, size);
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
	size_t chunk_size, tot;
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
		size_t local_size;
		local_size = chunk_size - local_pos;
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
		int nreq;
		nreq = 0;
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
	ssize_t ret;
	log_debug("finchfs_read() called fd=%d size=%zu", fd, size);
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
	int ret;
	log_debug("finchfs_fsync() called fd=%d", fd);
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	ret = fs_rpc_inode_fsync(fd_table[fd].i_ino, fd_table[fd].eid[0],
				 &fd_table[fd].size);
	return (ret);
}

int
finchfs_unlink(const char *path)
{
	int ret;
	char *p;
	log_debug("finchfs_unlink() called path=%s", path);
	p = canonical_path(path);
	ret = fs_rpc_inode_unlink(NULL, p);
	free(p);
	return (ret);
}

int
finchfs_mkdir(const char *path, mode_t mode)
{
	int ret;
	char *p;
	log_debug("finchfs_mkdir() called path=%s", path);
	p = canonical_path(path);
	mode |= S_IFDIR;
	ret = fs_rpc_mkdir(NULL, p, mode);
	free(p);
	return (ret);
}

int
finchfs_rmdir(const char *path)
{
	int ret;
	char *p;
	log_debug("finchfs_rmdir() called path=%s", path);
	p = canonical_path(path);
	ret = fs_rpc_inode_unlink_all(NULL, p);
	free(p);
	return (ret);
}

int
finchfs_stat(const char *path, struct stat *st)
{
	char *p;
	fs_stat_t fst;
	int ret;
	log_debug("finchfs_stat() called path=%s", path);
	p = canonical_path(path);
	ret = fs_rpc_inode_stat(NULL, p, &fst, 0);
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
	st->st_nlink = fst.nlink;
	st->st_ino = fst.i_ino;
	st->st_blksize = fst.chunk_size;
	st->st_blocks = NUM_BLOCKS(fst.size);
	free(p);
	return (0);
}

int
finchfs_fstat(int fd, struct stat *st)
{
	log_debug("finchfs_fstat() called fd=%d", fd);
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	st->st_mode = fd_table[fd].mode;
	st->st_uid = getuid();
	st->st_gid = getgid();
	st->st_size = fd_table[fd].size;
	st->st_mtim = fd_table[fd].mtime;
	st->st_ctim = fd_table[fd].ctime;
	st->st_nlink = fd_table[fd].nlink;
	st->st_ino = fd_table[fd].i_ino;
	st->st_blksize = fd_table[fd].chunk_size;
	st->st_blocks = NUM_BLOCKS(fd_table[fd].size);
	return (0);
}

int
finchfs_readdir(const char *path, void *buf,
		void (*filler)(void *, const char *, const struct stat *))
{
	int ret;
	char *p;
	log_debug("finchfs_readdir() called path=%s", path);
	p = canonical_path(path);
	ret = fs_rpc_readdir(p, buf, filler);
	free(p);
	return (ret);
}

int
finchfs_rename(const char *oldpath, const char *newpath)
{
	int ret;
	char *oldp, *newp;
	log_debug("finchfs_rename() called oldpath=%s newpath=%s", oldpath,
		  newpath);
	oldp = canonical_path(oldpath);
	newp = canonical_path(newpath);
	ret = fs_rpc_file_rename(NULL, oldp, NULL, newp);
	if (ret) {
		if (errno == ENOTSUP || errno == EISDIR) {
			ret = fs_rpc_dir_rename(NULL, oldp, NULL, newp);
		}
	}
	if (ret) {
		free(oldp);
		free(newp);
		return (-1);
	}
	free(oldp);
	free(newp);
	return (0);
}

int
finchfs_link(const char *oldpath, const char *newpath)
{
	int ret;
	char *oldp, *newp;
	log_debug("finchfs_link() called oldpath=%s newpath=%s", oldpath,
		  newpath);
	oldp = canonical_path(oldpath);
	newp = canonical_path(newpath);
	ret = fs_rpc_file_link(NULL, oldp, NULL, newp);
	if (ret) {
		if (errno == ENOTSUP || errno == EISDIR) {
			ret = fs_rpc_dir_link(NULL, oldp, NULL, newp);
		}
	}
	if (ret) {
		free(oldp);
		free(newp);
		return (-1);
	}
	free(oldp);
	free(newp);
	return (0);
}

int
finchfs_find(const char *path, const char *query,
	     struct finchfs_find_param *param, void *buf,
	     void (*filler)(void *, const char *))
{
	int ret;
	char *p;
	log_debug("finchfs_find() called path=%s query=%s", path, query);
	p = canonical_path(path);
	ret = fs_rpc_find(p, query, param, buf, filler);
	free(p);
	return (ret);
}

int
finchfs_createat(int dirfd, const char *pathname, int flags, mode_t mode)
{
	log_debug("finchfs_createat() called dirfd=%d path=%s", dirfd,
		  pathname);
	return finchfs_createat_chunk_size(dirfd, pathname, flags, mode,
					   finchfs_chunk_size);
}

int
finchfs_createat_chunk_size(int dirfd, const char *pathname, int flags,
			    mode_t mode, size_t chunk_size)
{
	uint64_t *eid;
	char *p;
	int ret, fd;
	log_debug("finchfs_createat_chunk_size() called dirfd=%d path=%s "
		  "chunk_size=%zu",
		  dirfd, pathname, chunk_size);
	if (dirfd == AT_FDCWD) {
		eid = NULL;
	} else if (dirfd < 0 || dirfd >= fd_table_size ||
		   fd_table[dirfd].path == NULL) {
		errno = EBADF;
		return (-1);
	} else {
		eid = fd_table[dirfd].eid;
	}
	p = canonical_path(pathname);
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
	fd_table[fd].eid[0] = 0;

	mode |= S_IFREG;
	ret = fs_rpc_inode_create(
	    eid, p, (flags & 0b11) + (((flags & O_TRUNC) != 0) << 2), mode,
	    chunk_size, &fd_table[fd].i_ino, &fd_table[fd].size,
	    fd_table[fd].eid);
	if (ret) {
		free(fd_table[fd].path);
		fd_table[fd].path = NULL;
		return (-1);
	}
	return (fd);
}

int
finchfs_openat(int dirfd, const char *pathname, int flags)
{
	uint64_t *eid;
	char *p;
	int ret, fd;
	fs_stat_t st;
	log_debug("finchfs_openat() called dirfd=%d path=%s", dirfd, pathname);
	if (dirfd == AT_FDCWD) {
		eid = NULL;
	} else if (dirfd < 0 || dirfd >= fd_table_size ||
		   fd_table[dirfd].path == NULL) {
		errno = EBADF;
		return (-1);
	} else {
		eid = fd_table[dirfd].eid;
	}
	p = canonical_path(pathname);
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
	if (flags & __O_DIRECTORY) {
		ret = fs_rpc_inode_open_dir(eid, p, fd_table[fd].eid, &st,
					    1 << 4);
		if (ret) {
			free(fd_table[fd].path);
			fd_table[fd].path = NULL;
			return (-1);
		}
	} else {
		ret = fs_rpc_inode_stat(eid, p, &st,
					(((flags & O_TRUNC) != 0) << 3) +
					    (fd_table[fd].access << 1) + 1);
		if (ret) {
			free(fd_table[fd].path);
			fd_table[fd].path = NULL;
			return (-1);
		}
		if (S_ISDIR(st.mode)) {
			log_error(
			    "To open directory, please set flag __O_DIRECTORY");
			free(fd_table[fd].path);
			fd_table[fd].path = NULL;
			return (-1);
		}
		fd_table[fd].eid[0] = st.eid;
	}
	fd_table[fd].i_ino = st.i_ino;
	fd_table[fd].mode = st.mode;
	fd_table[fd].chunk_size = st.chunk_size;
	fd_table[fd].size = st.size;
	log_debug("finchfs_openat() called path=%s inode=%d chunk_size=%zu", p,
		  st.i_ino, st.chunk_size);
	return (fd);
}

int
finchfs_fstatat(int dirfd, const char *pathname, struct stat *st, int flags)
{
	uint64_t *eid;
	char *p;
	fs_stat_t fst;
	int ret;
	log_debug("finchfs_fstatat() called dirfd=%d path=%s", dirfd, pathname);
	if (dirfd == AT_FDCWD) {
		eid = NULL;
	} else if (dirfd < 0 || dirfd >= fd_table_size ||
		   fd_table[dirfd].path == NULL) {
		errno = EBADF;
		return (-1);
	} else if (flags & AT_EMPTY_PATH) {
		return finchfs_fstat(dirfd, st);
	} else {
		eid = fd_table[dirfd].eid;
	}
	p = canonical_path(pathname);
	ret = fs_rpc_inode_stat(eid, p, &fst, 0);
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
finchfs_mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	uint64_t *eid;
	int ret;
	char *p;
	log_debug("finchfs_mkdirat() called dirfd=%d path=%s", dirfd, pathname);
	if (dirfd == AT_FDCWD) {
		eid = NULL;
	} else if (dirfd < 0 || dirfd >= fd_table_size ||
		   fd_table[dirfd].path == NULL) {
		errno = EBADF;
		return (-1);
	} else {
		eid = fd_table[dirfd].eid;
	}
	p = canonical_path(pathname);
	mode |= S_IFDIR;
	ret = fs_rpc_mkdir(eid, p, mode);
	free(p);
	return (ret);
}

int
finchfs_unlinkat(int dirfd, const char *pathname, int flags)
{
	uint64_t *eid;
	int ret;
	char *p;
	log_debug("finchfs_unlinkat() called dirfd=%d path=%s", dirfd,
		  pathname);
	if (dirfd == AT_FDCWD) {
		eid = NULL;
	} else if (dirfd < 0 || dirfd >= fd_table_size ||
		   fd_table[dirfd].path == NULL) {
		errno = EBADF;
		return (-1);
	} else {
		eid = fd_table[dirfd].eid;
	}
	p = canonical_path(pathname);
	if (flags & AT_REMOVEDIR) {
		ret = fs_rpc_inode_unlink_all(eid, p);
	} else {
		ret = fs_rpc_inode_unlink(eid, p);
	}
	free(p);
	return (ret);
}

int
finchfs_renameat(int olddirfd, const char *oldpath, int newdirfd,
		 const char *newpath)
{
	uint64_t *oldeid, *neweid;
	int ret;
	char *oldp, *newp;
	fs_stat_t st;
	log_debug("finchfs_renameat() called olddirfd=%d oldpath=%s "
		  "newdirfd=%d newpath=%s",
		  olddirfd, oldpath, newdirfd, newpath);
	if (olddirfd == AT_FDCWD) {
		oldeid = NULL;
	} else if (olddirfd < 0 || olddirfd >= fd_table_size ||
		   fd_table[olddirfd].path == NULL) {
		errno = EBADF;
		return (-1);
	} else {
		oldeid = fd_table[olddirfd].eid;
	}
	if (newdirfd == AT_FDCWD) {
		neweid = NULL;
	} else if (newdirfd < 0 || newdirfd >= fd_table_size ||
		   fd_table[newdirfd].path == NULL) {
		errno = EBADF;
		return (-1);
	} else {
		neweid = fd_table[newdirfd].eid;
	}
	oldp = canonical_path(oldpath);
	newp = canonical_path(newpath);
	ret = fs_rpc_inode_stat(oldeid, oldp, &st, 0);
	if (ret) {
		free(oldp);
		free(newp);
		return (-1);
	}
	if (S_ISDIR(st.mode)) {
		ret = fs_rpc_dir_rename(oldeid, oldp, neweid, newp);
		free(oldp);
		free(newp);
		return (ret);
	} else {
		ret = fs_rpc_file_rename(oldeid, oldp, neweid, newp);
		free(oldp);
		free(newp);
		return (ret);
	}
}

int
finchfs_linkat(int olddirfd, const char *oldpath, int newdirfd,
	       const char *newpath)
{
	uint64_t *oldeid, *neweid;
	int ret;
	char *oldp, *newp;
	log_debug("finchfs_linkat() called olddirfd=%d oldpath=%s "
		  "newdirfd=%d newpath=%s",
		  olddirfd, oldpath, newdirfd, newpath);
	if (olddirfd == AT_FDCWD) {
		oldeid = NULL;
	} else if (olddirfd < 0 || olddirfd >= fd_table_size ||
		   fd_table[olddirfd].path == NULL) {
		errno = EBADF;
		return (-1);
	} else {
		oldeid = fd_table[olddirfd].eid;
	}
	if (newdirfd == AT_FDCWD) {
		neweid = NULL;
	} else if (newdirfd < 0 || newdirfd >= fd_table_size ||
		   fd_table[newdirfd].path == NULL) {
		errno = EBADF;
		return (-1);
	} else {
		neweid = fd_table[newdirfd].eid;
	}
	oldp = canonical_path(oldpath);
	newp = canonical_path(newpath);
	ret = fs_rpc_file_link(oldeid, oldp, neweid, newp);
	if (ret) {
		if (errno == ENOTSUP || errno == EISDIR) {
			ret = fs_rpc_dir_link(oldeid, oldp, neweid, newp);
		}
	}
	if (ret) {
		free(oldp);
		free(newp);
		return (-1);
	}
	free(oldp);
	free(newp);
	return (0);
}

ssize_t
finchfs_getdents(int fd, void *dirp, size_t count)
{
	int ret;
	size_t c;
	log_debug("finchfs_getdents() called fd=%d", fd);
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	if (!S_ISDIR(fd_table[fd].mode)) {
		errno = ENOTDIR;
		return (-1);
	}
	c = count;
	while (fd_table[fd].getdents_state.rank < nvprocs) {
		ret = fs_rpc_getdents(
		    fd_table[fd].getdents_state.rank, fd_table[fd].eid,
		    &fd_table[fd].getdents_state.pos, dirp, &c);
		switch (ret) {
		case FINCH_ENOENT:
			fd_table[fd].getdents_state.rank++;
			fd_table[fd].getdents_state.pos = 0;
			c = count;
			continue;
		case FINCH_INPROGRESS:
			return (c);
		case FINCH_OK:
			fd_table[fd].getdents_state.rank++;
			fd_table[fd].getdents_state.pos = 0;
			return (c);
		default:
			errno = -ret;
			return (-1);
		}
	}
	return (0);
}

void *
finchfs_mmap(void *addr, size_t length, int prot, int flags, int fd,
	     off_t offset)
{
#ifdef FINCH_MMAP_SUPPORT
	struct uffdio_register uffdio_register;
	mmap_item_t *item;
	if (fd < 0 || fd >= fd_table_size || fd_table[fd].path == NULL) {
		errno = EBADF;
		return (MAP_FAILED);
	}
	if (S_ISDIR(fd_table[fd].mode)) {
		errno = EISDIR;
		return (MAP_FAILED);
	}
	if ((flags & MAP_SHARED) || (flags & MAP_PRIVATE) == 0) {
		errno = ENOTSUP;
		return (MAP_FAILED);
	}
	if (flags & MAP_ANONYMOUS) {
		errno = ENOTSUP;
		return (MAP_FAILED);
	}
	addr = mmap(addr, length, prot, flags | MAP_ANONYMOUS, -1, offset);
	if (addr == MAP_FAILED) {
		return (MAP_FAILED);
	}
	uffdio_register.range.start = (unsigned long)addr;
	uffdio_register.range.len = length;
	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) < 0) {
		log_error("ioctl failed");
		return (MAP_FAILED);
	}
	item = malloc(sizeof(mmap_item_t));
	item->addr = (uint64_t)addr;
	item->i_ino = fd_table[fd].i_ino;
	item->chunk_size = fd_table[fd].chunk_size;
	item->len = length;
	item->size = &fd_table[fd].size;
	item->offset = offset;
	add_mmap_item(item);
	return (addr);
#endif
	errno = ENOTSUP;
	return (MAP_FAILED);
}

int
finchfs_munmap(void *addr, size_t length)
{
#ifdef FINCH_MMAP_SUPPORT
	struct uffdio_range uffdio_range;
	uffdio_range.start = (uint64_t)addr;
	uffdio_range.len = length;

	if (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_range) < 0) {
		return (-1);
	}
	if (del_mmap_item((uint64_t)addr, length)) {
		return (-1);
	}
	if (munmap(addr, length)) {
		return (-1);
	}
	return (0);
#endif
	errno = ENOTSUP;
	return (-1);
}
