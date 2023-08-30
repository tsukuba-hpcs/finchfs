#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include "log.h"
#include "fs_types.h"
#include "fs.h"

void
fs_inode_init(char *db_dir)
{
	int ret;
	ret = chdir(db_dir);
	if (ret == -1 && errno == ENOENT) {
		ret = mkdir(db_dir, 0755);
		if (ret == 0)
			ret = chdir(db_dir);
	}
	if (ret == -1) {
		log_fatal("%s: %s", db_dir, strerror(errno));
	}
	ret = mkdir(".finch_data", 0755);
	if (ret == -1 && errno != EEXIST) {
		log_fatal("%s/.finch_data: %s", db_dir, strerror(errno));
	}
	log_debug("fs_inode_init() called db_dir=%s", db_dir);
}

int
fs_inode_create(char *path, mode_t mode, size_t chunk_size, uint32_t i_ino)
{
	if (S_ISREG(mode)) {
		int fd;
		int ret;
		log_debug("fs_inode_create() called path=%s mode=%o "
			  "chunk_size=%zu i_ino=%u",
			  path, mode, chunk_size, i_ino);
		fd = creat(path, mode);
		if (fd < 0) {
			log_error("creat() failed: %s", strerror(errno));
			return (-1);
		}
		ret = write(fd, &chunk_size, sizeof(chunk_size));
		if (ret != sizeof(chunk_size)) {
			log_error("write() failed: %s", strerror(errno));
			close(fd);
			return (-1);
		}
		ret = write(fd, &i_ino, sizeof(i_ino));
		if (ret != sizeof(i_ino)) {
			log_error("write() failed: %s", strerror(errno));
			close(fd);
			return (-1);
		}
		close(fd);
	} else if (S_ISDIR(mode)) {
		int ret;
		ret = mkdir(path, mode);
		if (ret == -1 && errno != EEXIST) {
			log_error("mkdir() failed: %s", strerror(errno));
			return (-1);
		}
	} else {
		log_error("unknown mode %o", mode);
		return (-1);
	}
	return (0);
}

int
fs_inode_stat(char *path, fs_stat_t *st)
{
	log_debug("fs_inode_stat() called path=%s", path);
	struct stat sb;
	int ret;
	ret = lstat(path, &sb);
	if (ret == -1) {
		log_error("fs_inode_stat stat() failed: %s", strerror(errno));
		return (-1);
	}
	int fd;
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_error("fs_inode_stat open() failed: %s", strerror(errno));
		return (-1);
	}
	ret = read(fd, &st->chunk_size, sizeof(st->chunk_size));
	if (ret != sizeof(st->chunk_size)) {
		log_error("fs_inode_stat read() failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}
	ret = read(fd, &st->i_ino, sizeof(st->i_ino));
	if (ret != sizeof(st->i_ino)) {
		log_error("fs_inode_stat read() failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}
	close(fd);
	st->mode = sb.st_mode;
	st->mtime = sb.st_mtim;
	st->ctime = sb.st_ctim;
	return (0);
}

ssize_t
fs_inode_write(uint32_t i_ino, uint32_t index, off_t offset, size_t size,
	       const void *buf)
{
	log_debug("fs_inode_write() called i_ino=%u index=%u offset=%ld "
		  "size=%zu",
		  i_ino, index, offset, size);
	char buffer[128];
	snprintf(buffer, sizeof(buffer), ".finch_data/%u.%u", i_ino, index);
	int fd;
	fd = open(buffer, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		log_error("fs_inode_write open() failed: %s", strerror(errno));
		return (-1);
	}
	int ret;
	ret = pwrite(fd, buf, size, offset);
	if (ret != size) {
		log_error("fs_inode_write pwrite() failed: %s",
			  strerror(errno));
		close(fd);
		return (ssize_t)(-1);
	}
	close(fd);
	return (ssize_t)(ret);
}

ssize_t
fs_inode_read(uint32_t i_ino, uint32_t index, off_t offset, size_t size,
	      void *buf)
{
	log_debug(
	    "fs_inode_read() called i_ino=%u index=%u offset=%ld size=%zu",
	    i_ino, index, offset, size);
	char buffer[128];
	snprintf(buffer, sizeof(buffer), ".finch_data/%u.%u", i_ino, index);
	int fd;
	fd = open(buffer, O_RDONLY);
	if (fd < 0) {
		log_error("fs_inode_read open() failed: %s", strerror(errno));
		return (-1);
	}
	int ret;
	ret = pread(fd, buf, size, offset);
	if (ret < 0) {
		log_error("fs_inode_read pread() failed: %s", strerror(errno));
		close(fd);
		return (ssize_t)(-1);
	}
	close(fd);
	return (ssize_t)(ret);
}
