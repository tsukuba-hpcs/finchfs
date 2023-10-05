#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <libpmemkv.h>
#include "log.h"
#include "fs_types.h"
#include "fs.h"

struct fs_ctx {
	pmemkv_db *db;
};

struct fs_ctx *
fs_inode_init(char *db_dir, size_t db_size, int trank)
{
	int s;
	struct stat st;
	struct fs_ctx *ctx = malloc(sizeof(struct fs_ctx));
	ctx->db = NULL;
	pmemkv_config *cfg = pmemkv_config_new();
	char dir[64];
	snprintf(dir, sizeof(dir), db_dir, trank);
	char path[128];
	snprintf(path, sizeof(path), "%s/kv.db", dir);
	if (stat(dir, &st)) {
		log_fatal("%s: %s", db_dir, strerror(errno));
	}
	if (!S_ISDIR(st.st_mode)) {
		strcpy(path, dir);
	}
	log_debug("fs_inode_init() called db_dir=%s trank=%d", path, trank);

	if ((s = pmemkv_config_put_path(cfg, path)) != PMEMKV_STATUS_OK) {
		log_fatal("pmemkv_config_put_path() failed: %s",
			  pmemkv_errormsg());
	}
	if ((s = pmemkv_config_put_size(cfg, db_size)) != PMEMKV_STATUS_OK) {
		log_fatal("pmemkv_config_put_size() failed: %s",
			  pmemkv_errormsg());
	}
	if ((s = pmemkv_config_put_create_if_missing(cfg, true)) !=
	    PMEMKV_STATUS_OK) {
		log_fatal("pmemkv_config_put_create_if_missing() failed: %s",
			  pmemkv_errormsg());
	}
	if ((s = pmemkv_open("cmap", cfg, &ctx->db)) != PMEMKV_STATUS_OK) {
		log_fatal("pmemkv_open() failed: %s", pmemkv_errormsg());
	}
	return (ctx);
}

void
fs_inode_term(struct fs_ctx *ctx)
{
	if (ctx->db != NULL) {
		pmemkv_close(ctx->db);
	}
	free(ctx);
}

typedef enum {
	OK = 0,
	RECREATE = 1,
} pmem_status_t;

struct pmem_arg {
	void *buf;
	size_t size;
	off_t offset;
	void *newbuf;
	pmem_status_t st;
};

static void
write_cb(const char *v, size_t size, void *a)
{
	struct pmem_arg *arg = (struct pmem_arg *)a;
	if (arg->size + arg->offset <= size) {
		arg->st = OK;
		memcpy((char *)v + arg->offset, arg->buf, arg->size);
	} else {
		arg->st = RECREATE;
		arg->newbuf = calloc(arg->size + arg->offset, 1);
		size_t s = size;
		if (s > arg->offset) {
			s = arg->offset;
		}
		memcpy(arg->newbuf, v, s);
		memcpy(arg->newbuf + arg->offset, arg->buf, arg->size);
	}
}

ssize_t
fs_inode_write(struct fs_ctx *ctx, uint64_t i_ino, uint64_t index, off_t offset,
	       size_t size, const void *buf)
{
	log_debug(
	    "fs_inode_write() called i_ino=%lu index=%lu offset=%ld size=%zu",
	    i_ino, index, offset, size);
	int s;
	char key[128];
	snprintf(key, sizeof(key), "%lu.%lu", i_ino, index);
	struct pmem_arg arg = {
	    .buf = (void *)buf,
	    .size = size,
	    .offset = offset,
	    .newbuf = NULL,
	};
	s = pmemkv_get(ctx->db, key, strlen(key), write_cb, &arg);
	if (s == PMEMKV_STATUS_NOT_FOUND) {
		if (arg.offset > 0) {
			arg.newbuf = calloc(arg.size + arg.offset, 1);
			memcpy(arg.newbuf + arg.offset, arg.buf, arg.size);
			s = pmemkv_put(ctx->db, key, strlen(key), arg.newbuf,
				       arg.size + arg.offset);
			free(arg.newbuf);
			if (s == PMEMKV_STATUS_OUT_OF_MEMORY) {
				errno = ENOMEM;
				return (-1);
			} else if (s == PMEMKV_STATUS_OK) {
				return (arg.size);
			} else {
				errno = EIO;
				return (-1);
			}
		} else {
			s = pmemkv_put(ctx->db, key, strlen(key), arg.buf,
				       arg.size);
			if (s == PMEMKV_STATUS_OUT_OF_MEMORY) {
				errno = ENOMEM;
				return (-1);
			} else if (s == PMEMKV_STATUS_OK) {
				return (arg.size);
			} else {
				errno = EIO;
				return (-1);
			}
		}
	} else if (s == PMEMKV_STATUS_OK) {
		if (arg.st == OK) {
			return (arg.size);
		} else if (arg.st == RECREATE) {
			s = pmemkv_put(ctx->db, key, strlen(key), arg.newbuf,
				       arg.size + arg.offset);
			free(arg.newbuf);
			if (s == PMEMKV_STATUS_OUT_OF_MEMORY) {
				errno = ENOMEM;
				return (-1);
			} else if (s == PMEMKV_STATUS_OK) {
				return (arg.size);
			}
			errno = EIO;
			return (-1);
		}
	}
	errno = EIO;
	return (-1);
}

static void
read_cb(const char *v, size_t size, void *a)
{
	struct pmem_arg *arg = (struct pmem_arg *)a;
	size_t s = arg->size;
	if (arg->offset + arg->size > size) {
		if (size > arg->offset) {
			s = size - arg->offset;
		} else {
			s = 0;
		}
	}
	memcpy(arg->buf, v + arg->offset, s);
	arg->size = s;
}

ssize_t
fs_inode_read(struct fs_ctx *ctx, uint64_t i_ino, uint64_t index, off_t offset,
	      size_t size, void *buf)
{
	log_debug(
	    "fs_inode_read() called i_ino=%lu index=%lu offset=%ld size=%zu",
	    i_ino, index, offset, size);
	int s;
	char key[128];
	snprintf(key, sizeof(key), "%lu.%lu", i_ino, index);
	struct pmem_arg arg = {
	    .buf = buf,
	    .size = size,
	    .offset = offset,
	    .newbuf = NULL,
	};
	s = pmemkv_get(ctx->db, key, strlen(key), read_cb, &arg);
	if (s == PMEMKV_STATUS_NOT_FOUND) {
		errno = ENOENT;
		return (-1);
	} else if (s == PMEMKV_STATUS_OK) {
		if (arg.size == 0) {
			errno = ENOENT;
			return (-1);
		}
		return (arg.size);
	}
	errno = EIO;
	return (-1);
}
