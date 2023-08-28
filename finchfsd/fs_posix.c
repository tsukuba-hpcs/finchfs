#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
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
	log_debug("fs_inode_init() called db_dir=%s", db_dir);
}

int
fs_inode_create(char *path, mode_t mode, size_t chunk_size, uint32_t i_ino)
{
	if (S_ISREG(mode)) {
		int fd;
		int ret;
		size_t size = 0;
		log_debug("fs_inode_create() called path=%s mode=%o "
			  "chunk_size=%zu i_ino=%u",
			  path, mode, chunk_size, i_ino);
		fd = creat(path, mode);
		if (fd < 0) {
			log_error("creat() failed: %s", strerror(errno));
			return (-1);
		}
		ret = write(fd, &size, sizeof(size));
		if (ret != sizeof(size)) {
			log_error("write() failed: %s", strerror(errno));
			close(fd);
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
		if (ret == -1) {
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
	ret = read(fd, &st->size, sizeof(st->size));
	if (ret != sizeof(st->size)) {
		log_error("fs_inode_stat read() failed: %s", strerror(errno));
		close(fd);
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
