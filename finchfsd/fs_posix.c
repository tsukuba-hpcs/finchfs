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

#define INODE_SPLIT_SIZE 1023

struct fs_ctx {
	char db_dir[128];
};

struct fs_ctx *
fs_inode_init(char *db_dir, size_t db_size, int lrank)
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
	} else {
		char buffer[128];
		for (uint64_t i = 0; i < INODE_SPLIT_SIZE; i++) {
			snprintf(buffer, sizeof(buffer), "%lu", i);
			ret = mkdir(buffer, 0755);
			if (ret == -1 && errno != EEXIST) {
				log_fatal("%s: %s", buffer, strerror(errno));
			}
		}
	}
	log_debug("fs_inode_init() called db_dir=%s", db_dir);
	struct fs_ctx *ctx = malloc(sizeof(struct fs_ctx));
	strcpy(ctx->db_dir, db_dir);
	return (ctx);
}

void
fs_inode_term(struct fs_ctx *ctx)
{
	free(ctx);
}

ssize_t
fs_inode_write(struct fs_ctx *ctx, uint64_t i_ino, uint64_t index, off_t offset,
	       size_t size, const void *buf)
{
	log_debug("fs_inode_write() called i_ino=%lu index=%lu offset=%ld "
		  "size=%zu",
		  i_ino, index, offset, size);
	char buffer[128];
	snprintf(buffer, sizeof(buffer), "%lu/%lu.%lu",
		 i_ino % INODE_SPLIT_SIZE, i_ino, index);
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
fs_inode_read(struct fs_ctx *ctx, uint64_t i_ino, uint64_t index, off_t offset,
	      size_t size, void *buf)
{
	log_debug(
	    "fs_inode_read() called i_ino=%lu index=%lu offset=%ld size=%zu",
	    i_ino, index, offset, size);
	char buffer[128];
	snprintf(buffer, sizeof(buffer), "%lu/%lu.%lu",
		 i_ino % INODE_SPLIT_SIZE, i_ino, index);
	int fd;
	fd = open(buffer, O_RDONLY);
	if (fd < 0) {
		log_info("fs_inode_read open() failed: %s", strerror(errno));
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
