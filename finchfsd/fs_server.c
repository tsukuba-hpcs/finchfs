#include <ucp/api/ucp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <lmdb.h>
#include <sys/mman.h>
#include <unistd.h>
#include "finchfs.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "fs.h"
#include "log.h"
#include "config.h"

struct dentry_key {
	uint64_t i_ino;
	char name[64];
};
typedef struct dentry_key dentry_key_t;

struct inode {
	mode_t mode;
	size_t chunk_size;
	uint64_t i_ino;
	struct timespec mtime;
	struct timespec ctime;
	size_t size;
	uint32_t i_count;
	uint32_t i_nlink;
};

typedef struct inode inode_t;

struct worker_ctx {
	int rank;
	int nprocs;
	uint64_t *i_ino;
	ucp_context_h ucp_context;
	ucp_worker_h ucp_worker;
	ucp_ep_h ucp_next_ep;
	int *shutdown;
	struct fs_ctx *fs;
	struct inode *inodes;
	MDB_env *mdb_env;
	MDB_dbi dbi;
} ctx;

typedef struct {
	void *header;
	int n;
	ucp_dt_iov_t iov[];
} iov_req_t;

typedef struct {
	void *header;
	void *buf;
} contig_req_t;

typedef struct {
	void *header;
	void *buf;
	size_t size;
	ucp_ep_h reply_ep;
	struct fs_ctx *fs;
} req_rndv_t;

static inline uint64_t
alloc_ino(struct worker_ctx *ctx)
{
	uint64_t i_ino = *ctx->i_ino;
	*ctx->i_ino += ctx->nprocs;
	return (i_ino);
}

static inline inode_t *
get_parent_and_filename(uint64_t base, char *filename, const char *path,
			struct worker_ctx *ctx)
{
	inode_t *e = (base == 0) ? &ctx->inodes[0] : &ctx->inodes[base];
	MDB_txn *txn;
	MDB_val key, data;
	char *prev = (char *)path;
	char *p = prev;
	int path_len = strlen(path) + 1;
	dentry_key_t dkey;
	if (mdb_txn_begin(ctx->mdb_env, NULL, MDB_RDONLY, &txn)) {
		log_error(
		    "get_parent_and_filename() mdb_txn_begin() failed: %s",
		    strerror(errno));
		return (NULL);
	}
	dkey.i_ino = e->i_ino;
	key.mv_data = &dkey;
	key.mv_size = sizeof(dentry_key_t);

	while ((p = strchr(p, '/')) != NULL) {
		memcpy(dkey.name, prev, p - prev);
		for (int i = p - prev; i < sizeof(dkey.name); i++)
			dkey.name[i] = '\0';
		log_debug("get_parent_and_filename(): looking up '%s'",
			  dkey.name);
		prev = ++p;
		if (!mdb_get(txn, ctx->dbi, &key, &data))
			dkey.i_ino = *(uint64_t *)data.mv_data;
		else {
			log_error(
			    "get_parent_and_filename() path=%s does not exist",
			    path);
			e = NULL;
			goto out;
		}
		e = &ctx->inodes[dkey.i_ino];
		if (!S_ISDIR(e->mode)) {
			log_error("get_parent_and_filename() path=%s is not a "
				  "directory",
				  path);
			e = NULL;
			goto out;
		}
	}
	size_t final_len = strlen(prev);
	memcpy(filename, prev, final_len);
	filename[final_len] = '\0';
out:
	mdb_txn_abort(txn);
	return (e);
}

static inline inode_t *
get_dir_entry(uint64_t base, const char *path, struct worker_ctx *ctx)
{
	inode_t *e = (base == 0) ? &ctx->inodes[0] : &ctx->inodes[base];
	MDB_txn *txn;
	MDB_val key, data;
	dentry_key_t dkey;
	if (strcmp(path, "") == 0) {
		return (e);
	}
	char *prev = (char *)path;
	char *p = prev;
	int path_len = strlen(path) + 1;
	if (mdb_txn_begin(ctx->mdb_env, NULL, MDB_RDONLY, &txn)) {
		log_error(
		    "get_parent_and_filename() mdb_txn_begin() failed: %s",
		    strerror(errno));
		return (NULL);
	}

	dkey.i_ino = e->i_ino;
	key.mv_data = &dkey;
	key.mv_size = sizeof(dentry_key_t);
	while ((p = strchr(p, '/')) != NULL) {
		memcpy(dkey.name, prev, p - prev);
		for (int i = p - prev; i < sizeof(dkey.name); i++)
			dkey.name[i] = '\0';
		prev = ++p;
		if (!mdb_get(txn, ctx->dbi, &key, &data))
			dkey.i_ino = *(uint64_t *)data.mv_data;
		else {
			log_error("get_dir() path=%s does not exist", path);
			errno = ENOENT;
			e = NULL;
			goto out;
		}
		e = &ctx->inodes[dkey.i_ino];
		if (!S_ISDIR(e->mode)) {
			log_error("get_dir() path=%s is not a directory", path);
			errno = ENOTDIR;
			e = NULL;
			goto out;
		}
	}
	size_t final_len = strlen(prev);
	memcpy(dkey.name, prev, final_len);
	for (int i = final_len; i < sizeof(dkey.name); i++)
		dkey.name[i] = '\0';
	if (!mdb_get(txn, ctx->dbi, &key, &data))
		dkey.i_ino = *(uint64_t *)data.mv_data;
	else {
		log_error("get_dir() path=%s does not exist", path);
		errno = ENOENT;
		e = NULL;
		goto out;
	}
	e = &ctx->inodes[dkey.i_ino];
	if (!S_ISDIR(e->mode)) {
		log_error("get_dir() path=%s is not a directory", path);
		errno = ENOTDIR;
		e = NULL;
		goto out;
	}
out:
	mdb_txn_abort(txn);
	return (e);
}

static void
fs_rpc_iov_reply_cb(void *request, ucs_status_t status, void *user_data)
{
	log_debug("fs_rpc_iov_reply_cb() called status=%s",
		  ucs_status_string(status));
	ucp_request_free(request);
	iov_req_t *iov_req = user_data;
	free(iov_req->header);
	for (int i = 0; i < iov_req->n; i++) {
		free(iov_req->iov[i].buffer);
	}
	free(iov_req);
}

static ucs_status_t
post_iov_req(ucp_ep_h reply_ep, int id, iov_req_t *user_data,
	     size_t header_length)
{
	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_CALLBACK |
		UCP_OP_ATTR_FIELD_FLAGS | UCP_OP_ATTR_FIELD_USER_DATA,
	    .cb =
		{
		    .send = fs_rpc_iov_reply_cb,
		},
	    .flags = UCP_AM_SEND_FLAG_EAGER,
	    .datatype = UCP_DATATYPE_IOV,
	    .user_data = user_data,
	};
	ucs_status_ptr_t req =
	    ucp_am_send_nbx(reply_ep, id, user_data->header, header_length,
			    user_data->iov, user_data->n, &rparam);
	if (req == NULL) {
		free(user_data->header);
		for (int i = 0; i < user_data->n; i++) {
			free(user_data->iov[i].buffer);
		}
		free(user_data);
	} else if (UCS_PTR_IS_ERR(req)) {
		log_error("ucp_am_send_nbx() failed: %s",
			  ucs_status_string(UCS_PTR_STATUS(req)));
		free(user_data->header);
		for (int i = 0; i < user_data->n; i++) {
			free(user_data->iov[i].buffer);
		}
		free(user_data);
		ucs_status_t status = UCS_PTR_STATUS(req);
		ucp_request_free(req);
		return (status);
	}
	return (UCS_OK);
}

static void
fs_rpc_contig_reply_cb(void *request, ucs_status_t status, void *user_data)
{
	log_debug("fs_rpc_contig_reply_cb() called status=%s",
		  ucs_status_string(status));
	ucp_request_free(request);
	contig_req_t *contig_req = user_data;
	free(contig_req->header);
	free(contig_req->buf);
	free(contig_req);
}

ucs_status_t
fs_rpc_mkdir_recv(void *arg, const void *header, size_t header_length,
		  void *data, size_t length, const ucp_am_recv_param_t *param)
{
	uint64_t base;
	mode_t mode;
	char *path;
	ring_header_t *h = (ring_header_t *)header;
	char *p = (char *)data;
	base = *(uint64_t *)p;
	p += sizeof(base);
	mode = *(mode_t *)p;
	p += sizeof(mode);
	path = (char *)p;

	log_debug("fs_rpc_mkdir_recv() called path=%s ring=%u dino=%zu", path,
		  h->ring, h->relay_ino);

	if (h->ring == ctx.nprocs) {
		iov_req_t *user_data =
		    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->n = 1;
		user_data->iov[0].buffer = malloc(sizeof(int));
		user_data->iov[0].length = sizeof(int);
		ring_header_t *rh = (ring_header_t *)user_data->header;
		log_debug("fs_rpc_mkdir_recv() finishing ring=%u relay_ret=%d",
			  h->ring, rh->relay_ret);
		*(int *)(user_data->iov[0].buffer) = rh->relay_ret;
		ucs_status_t status;
		status = post_iov_req(rh->reply_ep, RPC_RET_REP, user_data,
				      header_length);
		return (status);
	}

	if (h->ring == 0)
		h->reply_ep = param->reply_ep;

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 3);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 3;
	user_data->iov[0].buffer = malloc(sizeof(uint64_t));
	user_data->iov[0].length = sizeof(uint64_t);
	memcpy(user_data->iov[0].buffer, &base, sizeof(uint64_t));
	user_data->iov[1].buffer = malloc(sizeof(mode_t));
	user_data->iov[1].length = sizeof(mode_t);
	memcpy(user_data->iov[1].buffer, &mode, sizeof(mode_t));
	user_data->iov[2].buffer = malloc(strlen(path) + 1);
	user_data->iov[2].length = strlen(path) + 1;
	memcpy(user_data->iov[2].buffer, path, strlen(path) + 1);
	ring_header_t *rh = (ring_header_t *)user_data->header;

	char dirname[128];
	inode_t *parent = get_parent_and_filename(base, dirname, path, &ctx);

	if (parent == NULL) {
		log_debug("fs_rpc_mkdir_recv() parent path=%s does not exist",
			  path);
		rh->relay_ret = FINCH_ENOENT;
	} else {
		dentry_key_t dkey;
		MDB_txn *txn;
		MDB_val key, data;
		dkey.i_ino = parent->i_ino;
		key.mv_data = &dkey;
		key.mv_size = sizeof(dentry_key_t);
		memcpy(dkey.name, dirname, strlen(dirname) + 1);
		for (int i = strlen(dirname) + 1; i < sizeof(dkey.name); i++)
			dkey.name[i] = '\0';
		if (mdb_txn_begin(ctx.mdb_env, NULL, 0, &txn)) {
			log_error("get_parent_and_filename() mdb_txn_begin() "
				  "failed: %s",
				  strerror(errno));
			h->relay_ret = rh->relay_ret = FINCH_EIO;
			goto out;
		}

		if (!mdb_get(txn, ctx.dbi, &key, &data)) {
			dkey.i_ino = *(uint64_t *)data.mv_data;
			rh->relay_ret = FINCH_EEXIST;
			log_debug("fs_rpc_mkdir_recv() path=%s already exists",
				  path);
		} else {
			uint64_t ino =
			    (h->ring == 0) ? alloc_ino(&ctx) : h->relay_ino;
			rh->relay_ino = ino;
			inode_t *new_inode = &ctx.inodes[ino];
			data.mv_data = &ino;
			data.mv_size = sizeof(uint64_t);
			int rc = mdb_put(txn, ctx.dbi, &key, &data, 0);
			log_debug("fs_rpc_mkdir_recv() create path=%s "
				  "inode=%lu rc=%d",
				  path, ino, rc);
			new_inode->i_ino = ino;
			new_inode->mode = mode;
			new_inode->chunk_size = 0;
			new_inode->size = 0;
			new_inode->i_count = 0;
			new_inode->i_nlink = 1;
			timespec_get(&new_inode->mtime, TIME_UTC);
			timespec_get(&new_inode->ctime, TIME_UTC);
			rh->relay_ret = FINCH_OK;
		}
		mdb_txn_commit(txn);
	}
out:
	rh->ring++;
	if (ctx.nprocs == 1 || (h->ring == 0 && rh->relay_ret != FINCH_OK)) {
		iov_req_t *old = user_data;
		user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->n = 1;
		user_data->iov[0].buffer = malloc(sizeof(int));
		user_data->iov[0].length = sizeof(int);
		*(int *)(user_data->iov[0].buffer) = rh->relay_ret;
		ucs_status_t status;
		status = post_iov_req(param->reply_ep, RPC_RET_REP, user_data,
				      header_length);
		free(old->header);
		for (int i = 0; i < old->n; i++) {
			free(old->iov[i].buffer);
		}
		free(old);
		return (status);
	}
	if (h->ring > 0 && rh->relay_ret != h->relay_ret) {
		log_fatal("fs_rpc_mkdir_recv() inconsistent relay_ret ring=%u "
			  "relay_ret=%d header_relay_ret=%d",
			  h->ring, rh->relay_ret, h->relay_ret);
	}
	ucs_status_t status;
	status = post_iov_req(ctx.ucp_next_ep, RPC_MKDIR_REQ, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_inode_create_recv(void *arg, const void *header, size_t header_length,
			 void *data, size_t length,
			 const ucp_am_recv_param_t *param)
{
	uint64_t base;
	char *path;
	uint8_t flags;
	mode_t mode;
	size_t chunk_size;
	char *p = (char *)data;
	base = *(uint64_t *)p;
	p += sizeof(base);
	path = (char *)p;
	p += strlen(path) + 1;
	flags = *(uint8_t *)p;
	p += sizeof(flags);
	mode = *(mode_t *)p;
	p += sizeof(mode);
	chunk_size = *(size_t *)p;

	log_debug("fs_rpc_inode_create_recv() called path=%s", path);

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 3);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 3;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);
	user_data->iov[1].buffer = malloc(sizeof(uint64_t));
	user_data->iov[1].length = sizeof(uint64_t);
	user_data->iov[2].buffer = malloc(sizeof(void *));
	user_data->iov[2].length = sizeof(void *);

	char filename[128];
	inode_t *parent = get_parent_and_filename(base, filename, path, &ctx);

	if (parent == NULL) {
		log_debug(
		    "fs_rpc_inode_create_recv() parent path=%s does not exist",
		    path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		dentry_key_t dkey;
		MDB_txn *txn;
		MDB_val key, data;
		dkey.i_ino = parent->i_ino;
		key.mv_data = &dkey;
		key.mv_size = sizeof(dentry_key_t);
		memcpy(dkey.name, filename, strlen(filename) + 1);
		for (int i = strlen(filename) + 1; i < sizeof(dkey.name); i++)
			dkey.name[i] = '\0';
		if (mdb_txn_begin(ctx.mdb_env, NULL, 0, &txn)) {
			log_error("fs_rpc_inode_create_recv() mdb_txn_begin() "
				  "failed: %s",
				  strerror(errno));
			*(int *)(user_data->iov[0].buffer) = FINCH_EIO;
			goto out;
		}

		if (!mdb_get(txn, ctx.dbi, &key, &data)) {
			uint64_t ino = *(uint64_t *)data.mv_data;
			inode_t *inode = &ctx.inodes[ino];
			inode->i_count++;
			*(uint64_t *)(user_data->iov[1].buffer) = inode->i_ino;
			*(void **)(user_data->iov[2].buffer) = inode;
		} else {
			uint64_t ino = alloc_ino(&ctx);
			inode_t *new_inode = &ctx.inodes[ino];
			data.mv_data = &ino;
			data.mv_size = sizeof(uint64_t);
			mdb_put(txn, ctx.dbi, &key, &data, 0);
			new_inode->i_ino = ino;
			new_inode->mode = mode;
			new_inode->chunk_size = chunk_size;
			new_inode->size = 0;
			new_inode->i_count = 1;
			new_inode->i_nlink = 1;
			timespec_get(&new_inode->mtime, TIME_UTC);
			timespec_get(&new_inode->ctime, TIME_UTC);
			log_debug("fs_rpc_inode_create_recv() create path=%s "
				  "inode=%lu",
				  path, new_inode->i_ino);
			*(uint64_t *)(user_data->iov[1].buffer) =
			    new_inode->i_ino;
			*(void **)(user_data->iov[2].buffer) = new_inode;
		}
		*(int *)(user_data->iov[0].buffer) = FINCH_OK;
		mdb_txn_commit(txn);
	}
out:
	ucs_status_t status;
	status = post_iov_req(param->reply_ep, RPC_INODE_REP, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_file_unlink_recv(void *arg, const void *header, size_t header_length,
			void *data, size_t length,
			const ucp_am_recv_param_t *param)
{
	uint64_t base;
	char *path;
	char *p = (char *)data;
	base = *(uint64_t *)p;
	p += sizeof(base);
	path = (char *)p;
	log_debug("fs_rpc_file_unlink_recv() called path=%s", path);

	iov_req_t *user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 1;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);

	char filename[128];
	inode_t *parent = get_parent_and_filename(base, filename, path, &ctx);

	if (parent == NULL) {
		log_debug(
		    "fs_rpc_inode_unlink_recv() parent path=%s does not exist",
		    path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		dentry_key_t dkey;
		MDB_txn *txn;
		MDB_val key, data;
		dkey.i_ino = parent->i_ino;
		key.mv_data = &dkey;
		key.mv_size = sizeof(dentry_key_t);
		memcpy(dkey.name, filename, strlen(filename) + 1);
		for (int i = strlen(filename) + 1; i < sizeof(dkey.name); i++)
			dkey.name[i] = '\0';
		if (mdb_txn_begin(ctx.mdb_env, NULL, 0, &txn)) {
			log_error("fs_rpc_inode_unlink_recv() mdb_txn_begin() "
				  "failed: %s",
				  strerror(errno));
			*(int *)(user_data->iov[0].buffer) = FINCH_EIO;
			goto out;
		}

		if (!mdb_get(txn, ctx.dbi, &key, &data)) {
			uint64_t ino = *(uint64_t *)data.mv_data;
			inode_t *inode = &ctx.inodes[ino];
			inode->i_nlink--;
			mdb_del(txn, ctx.dbi, &key, NULL);
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
		} else {
			log_debug(
			    "fs_rpc_inode_unlink_recv() path=%s does not exist",
			    path);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
		}
		mdb_txn_commit(txn);
	}
out:
	ucs_status_t status;
	status = post_iov_req(param->reply_ep, RPC_RET_REP, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_dir_unlink_recv(void *arg, const void *header, size_t header_length,
		       void *data, size_t length,
		       const ucp_am_recv_param_t *param)
{
	uint64_t base;
	char *path;
	ring_header_t *h = (ring_header_t *)header;
	char *p = (char *)data;
	base = *(uint64_t *)p;
	p += sizeof(base);
	path = (char *)p;

	log_debug("fs_rpc_inode_unlink_recv() called path=%s ring=%d", path,
		  h->ring);

	if (h->ring == ctx.nprocs) {
		iov_req_t *user_data =
		    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->n = 1;
		user_data->iov[0].buffer = malloc(sizeof(int));
		user_data->iov[0].length = sizeof(int);
		ring_header_t *rh = (ring_header_t *)user_data->header;
		*(int *)(user_data->iov[0].buffer) = rh->relay_ret;
		ucs_status_t status;
		log_debug("fs_rpc_dir_unlink_recv() finished ring=%d "
			  "relay_ret=%d",
			  h->ring, rh->relay_ret);
		status = post_iov_req(rh->reply_ep, RPC_RET_REP, user_data,
				      header_length);
		return (status);
	}

	if (h->ring == 0)
		h->reply_ep = param->reply_ep;

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 2);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 2;
	user_data->iov[0].buffer = malloc(sizeof(uint64_t));
	user_data->iov[0].length = sizeof(uint64_t);
	memcpy(user_data->iov[0].buffer, &base, sizeof(uint64_t));
	user_data->iov[1].buffer = malloc(strlen(path) + 1);
	user_data->iov[1].length = strlen(path) + 1;
	memcpy(user_data->iov[1].buffer, path, strlen(path) + 1);
	ring_header_t *rh = (ring_header_t *)user_data->header;

	char filename[128];
	inode_t *parent = get_parent_and_filename(base, filename, path, &ctx);

	if (parent == NULL) {
		log_debug(
		    "fs_rpc_inode_unlink_recv() parent path=%s does not exist",
		    path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		dentry_key_t dkey;
		MDB_txn *txn;
		MDB_val key, data;
		dkey.i_ino = parent->i_ino;
		key.mv_data = &dkey;
		key.mv_size = sizeof(dentry_key_t);
		memcpy(dkey.name, filename, strlen(filename) + 1);
		for (int i = strlen(filename) + 1; i < sizeof(dkey.name); i++)
			dkey.name[i] = '\0';
		if (mdb_txn_begin(ctx.mdb_env, NULL, 0, &txn)) {
			log_error("fs_rpc_inode_unlink_recv() mdb_txn_begin() "
				  "failed: %s",
				  strerror(errno));
			rh->relay_ret = FINCH_EIO;
			goto out;
		}

		if (!mdb_get(txn, ctx.dbi, &key, &data)) {
			uint64_t ino = *(uint64_t *)data.mv_data;
			inode_t *inode = &ctx.inodes[ino];
			inode->i_nlink--;
			mdb_del(txn, ctx.dbi, &key, NULL);
			rh->relay_ret = FINCH_OK;
		} else {
			log_debug(
			    "fs_rpc_inode_unlink_recv() path=%s does not exist",
			    path);
			rh->relay_ret = FINCH_ENOENT;
		}
		mdb_txn_commit(txn);
	}
out:
	rh->ring++;
	if (ctx.nprocs == 1 || (h->ring == 0 && rh->relay_ret != FINCH_OK)) {
		iov_req_t *old = user_data;
		user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->n = 1;
		user_data->iov[0].buffer = malloc(sizeof(int));
		user_data->iov[0].length = sizeof(int);
		*(int *)(user_data->iov[0].buffer) = rh->relay_ret;
		ucs_status_t status;
		status = post_iov_req(param->reply_ep, RPC_RET_REP, user_data,
				      header_length);
		free(old->header);
		for (int i = 0; i < old->n; i++) {
			free(old->iov[i].buffer);
		}
		free(old);
		return (status);
	}
	if (h->ring > 0 && rh->relay_ret != h->relay_ret) {
		log_fatal("fs_rpc_inode_unlink_recv() inconsistent relay_ret "
			  "ring=%u relay_ret=%d header_relay_ret=%d",
			  h->ring, rh->relay_ret, h->relay_ret);
	}
	ucs_status_t status;
	status = post_iov_req(ctx.ucp_next_ep, RPC_DIR_UNLINK_REQ, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_inode_stat_recv(void *arg, const void *header, size_t header_length,
		       void *data, size_t length,
		       const ucp_am_recv_param_t *param)
{
	uint64_t base;
	uint8_t open;
	char *path;
	char *p = (char *)data;
	base = *(uint64_t *)p;
	p += sizeof(base);
	open = *(uint8_t *)p;
	p += sizeof(open);
	path = (char *)p;

	log_debug("fs_rpc_inode_stat_recv() called path=%s open=%d", path,
		  open);

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 2);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 2;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);
	user_data->iov[1].buffer = malloc(sizeof(fs_stat_t));
	user_data->iov[1].length = sizeof(fs_stat_t);

	fs_stat_t *st = (fs_stat_t *)user_data->iov[1].buffer;

	char filename[128];
	inode_t *parent = get_parent_and_filename(base, filename, path, &ctx);

	if (parent == NULL) {
		log_debug(
		    "fs_rpc_inode_stat_recv() parent path=%s does not exist",
		    path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else if (strcmp(filename, "") == 0) {
		inode_t *inode = (base == 0) ? &ctx.inodes[0] : (inode_t *)base;
		st->chunk_size = inode->chunk_size;
		st->i_ino = inode->i_ino;
		st->mode = inode->mode;
		st->mtime = inode->mtime;
		st->ctime = inode->ctime;
		st->size = inode->size;
		st->nlink = inode->i_nlink;
		*(int *)(user_data->iov[0].buffer) = FINCH_OK;
		if (open & 1) {
			inode->i_count++;
		}
	} else {
		dentry_key_t dkey;
		MDB_txn *txn;
		MDB_val key, data;
		dkey.i_ino = parent->i_ino;
		key.mv_data = &dkey;
		key.mv_size = sizeof(dentry_key_t);
		memcpy(dkey.name, filename, strlen(filename) + 1);
		for (int i = strlen(filename) + 1; i < sizeof(dkey.name); i++)
			dkey.name[i] = '\0';
		if (mdb_txn_begin(ctx.mdb_env, NULL, MDB_RDONLY, &txn)) {
			log_error("fs_rpc_inode_stat_recv() mdb_txn_begin() "
				  "failed: %s",
				  strerror(errno));
			*(int *)(user_data->iov[0].buffer) = FINCH_EIO;
			goto out;
		}

		if (!mdb_get(txn, ctx.dbi, &key, &data)) {
			uint64_t ino = *(uint64_t *)data.mv_data;
			inode_t *inode = &ctx.inodes[ino];

			st->chunk_size = inode->chunk_size;
			st->i_ino = inode->i_ino;
			st->mode = inode->mode;
			st->mtime = inode->mtime;
			st->ctime = inode->ctime;
			st->size = inode->size;
			st->nlink = inode->i_nlink;
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
			if (open & 1) {
				inode->i_count++;
			}
		} else {
			log_debug(
			    "fs_rpc_inode_stat_recv() path=%s does not exist",
			    path);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
		}
		mdb_txn_abort(txn);
	}
out:
	ucs_status_t status;
	status = post_iov_req(param->reply_ep, RPC_INODE_STAT_REP, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_inode_stat_update_recv(void *arg, const void *header,
			      size_t header_length, void *data, size_t length,
			      const ucp_am_recv_param_t *param)
{
	uint64_t i_ino;
	size_t ssize;
	inode_t *inode;
	char *p = (char *)data;
	i_ino = *(uint64_t *)p;
	p += sizeof(i_ino);
	ssize = *(size_t *)p;
	inode = &ctx.inodes[i_ino];

	log_debug("fs_rpc_inode_stat_update_recv() called i_ino=%zu size=%zu",
		  i_ino, ssize >> 3);

	if (ssize & 1) {
		inode->i_count--;
		if (inode->size < (ssize >> 3)) {
			inode->size = ssize >> 3;
		}
		timespec_get(&inode->mtime, TIME_UTC);
	} else {
		if (inode->size < (ssize >> 3)) {
			inode->size = ssize >> 3;
		}
		timespec_get(&inode->mtime, TIME_UTC);

		iov_req_t *user_data =
		    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 2);
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->n = 2;
		user_data->iov[0].buffer = malloc(sizeof(int));
		user_data->iov[0].length = sizeof(int);
		user_data->iov[1].buffer = malloc(sizeof(size_t));
		user_data->iov[1].length = sizeof(size_t);

		*(int *)(user_data->iov[0].buffer) = FINCH_OK;
		*(size_t *)(user_data->iov[1].buffer) = inode->size;

		ucs_status_t status;
		status = post_iov_req(param->reply_ep, RPC_INODE_FSYNC_REP,
				      user_data, header_length);
		return (status);
	}

	return (UCS_OK);
}

static int
fs_rpc_inode_write_internal(uint64_t i_ino, uint64_t index, off_t offset,
			    size_t size, const void *buf, ucp_ep_h reply_ep,
			    void *handle, struct fs_ctx *fs)
{
	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 2);
	user_data->header = malloc(sizeof(void *));
	*(void **)(user_data->header) = handle;
	user_data->n = 2;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);
	user_data->iov[1].buffer = malloc(sizeof(ssize_t));
	user_data->iov[1].length = sizeof(ssize_t);

	*(ssize_t *)user_data->iov[1].buffer =
	    fs_inode_write(fs, i_ino, index, offset, size, buf);
	if (*(ssize_t *)user_data->iov[1].buffer < 0) {
		*(int *)(user_data->iov[0].buffer) = -errno;
	} else {
		*(int *)(user_data->iov[0].buffer) = FINCH_OK;
	}
	ucs_status_t status;
	status = post_iov_req(reply_ep, RPC_INODE_WRITE_REP, user_data,
			      sizeof(void *));
	if (status != UCS_OK) {
		return (1);
	}
	return (0);
}

static void
fs_rpc_write_rndv_cb(void *request, ucs_status_t status, size_t length,
		     void *user_data)
{
	log_debug("fs_rpc_write_rndv_cb() called status=%s",
		  ucs_status_string(status));
	ucp_request_free(request);
	req_rndv_t *req_rndv = user_data;
	inode_write_header_t *header = req_rndv->header;
	int ret;
	ret = fs_rpc_inode_write_internal(
	    header->i_ino, header->index, header->offset, req_rndv->size,
	    req_rndv->buf, req_rndv->reply_ep, header->handle, req_rndv->fs);
	if (ret) {
		log_error("fs_rpc_inode_write_internal() failed");
	}
	free(req_rndv->header);
	free(req_rndv->buf);
	free(req_rndv);
}

ucs_status_t
fs_rpc_inode_write_recv(void *arg, const void *header, size_t header_length,
			void *data, size_t length,
			const ucp_am_recv_param_t *param)
{
	inode_write_header_t *hdr = (inode_write_header_t *)header;
	log_debug("fs_rpc_inode_write_recv() called i_ino=%lu index=%lu "
		  "offset=%ld length=%zu",
		  hdr->i_ino, hdr->index, hdr->offset, length);

	if (param->recv_attr & UCP_AM_RECV_ATTR_FLAG_RNDV) {
		req_rndv_t *user_data = malloc(sizeof(req_rndv_t));
		log_debug("fs_rpc_inode_write_recv() rndv start");
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->size = length;
		user_data->buf = malloc(length);
		user_data->reply_ep = param->reply_ep;
		user_data->fs = ctx.fs;
		ucp_request_param_t rparam = {
		    .op_attr_mask = UCP_OP_ATTR_FIELD_DATATYPE |
				    UCP_OP_ATTR_FIELD_CALLBACK |
				    UCP_OP_ATTR_FIELD_USER_DATA,
		    .cb =
			{
			    .recv_am = fs_rpc_write_rndv_cb,
			},
		    .datatype = ucp_dt_make_contig(sizeof(char)),
		    .user_data = user_data,
		};
		ucs_status_ptr_t req = ucp_am_recv_data_nbx(
		    ctx.ucp_worker, data, user_data->buf, length, &rparam);
		if (req == NULL) {
			log_debug("ucp_am_recv_data_nbx completed immediately");
			free(user_data->header);
			free(user_data->buf);
			free(user_data);
		} else if (UCS_PTR_IS_ERR(req)) {
			log_error("ucp_am_send_nbx() failed: %s",
				  ucs_status_string(UCS_PTR_STATUS(req)));
			free(user_data->header);
			free(user_data->buf);
			free(user_data);
			ucs_status_t status = UCS_PTR_STATUS(req);
			ucp_request_free(req);
			return (status);
		}
	} else {
		log_debug("fs_rpc_inode_write_recv() eager start");
		int ret;
		ret = fs_rpc_inode_write_internal(
		    hdr->i_ino, hdr->index, hdr->offset, length, data,
		    param->reply_ep, hdr->handle, ctx.fs);
		if (ret) {
			log_error("fs_rpc_inode_write_internal() failed");
		}
	}
	return UCS_OK;
}

ucs_status_t
fs_rpc_inode_read_recv(void *arg, const void *header, size_t header_length,
		       void *data, size_t length,
		       const ucp_am_recv_param_t *param)
{
	contig_req_t *user_data = malloc(sizeof(contig_req_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	inode_read_header_t *rhdr = (inode_read_header_t *)user_data->header;
	user_data->buf = malloc(rhdr->size);
	log_debug(
	    "fs_rpc_inode_read_recv() called i_ino=%lu offset=%lu length=%zu",
	    rhdr->i_ino, rhdr->offset, rhdr->size);

	ucp_request_param_t rparam = {
	    .op_attr_mask = UCP_OP_ATTR_FIELD_DATATYPE |
			    UCP_OP_ATTR_FIELD_CALLBACK |
			    UCP_OP_ATTR_FIELD_USER_DATA,
	    .cb =
		{
		    .send = fs_rpc_contig_reply_cb,
		},
	    .datatype = ucp_dt_make_contig(sizeof(char)),
	    .user_data = user_data,
	};

	rhdr->size = fs_inode_read(ctx.fs, rhdr->i_ino, rhdr->index,
				   rhdr->offset, rhdr->size, user_data->buf);
	if (rhdr->size < 0) {
		log_info("fs_inode_read() failed: %s", strerror(errno));
		rhdr->ret = -errno;
		rhdr->size = 1;
	} else {
		log_debug("fs_inode_read() success size=%zu", rhdr->size);
		rhdr->ret = FINCH_OK;
	}
	ucs_status_ptr_t req = ucp_am_send_nbx(
	    param->reply_ep, RPC_INODE_READ_REP, user_data->header,
	    header_length, user_data->buf, rhdr->size, &rparam);

	if (req == NULL) {
		free(user_data->header);
		free(user_data->buf);
		free(user_data);
	} else if (UCS_PTR_IS_ERR(req)) {
		log_error("ucp_am_send_nbx() failed: %s",
			  ucs_status_string(UCS_PTR_STATUS(req)));
		free(user_data->header);
		free(user_data->buf);
		free(user_data);
		ucs_status_t status = UCS_PTR_STATUS(req);
		ucp_request_free(req);
		return (status);
	}
	return (UCS_OK);
}

ucs_status_t
fs_rpc_dir_rename_recv(void *arg, const void *header, size_t header_length,
		       void *data, size_t length,
		       const ucp_am_recv_param_t *param)
{
	uint64_t oldbase;
	char *opath;
	uint64_t newbase;
	char *npath;
	ring_header_t *h = (ring_header_t *)header;
	char *p = (char *)data;
	oldbase = *(uint64_t *)p;
	p += sizeof(uint64_t);
	opath = (char *)p;
	p += strlen(opath) + 1;
	newbase = *(uint64_t *)p;
	p += sizeof(uint64_t);
	npath = (char *)p;

	log_debug("fs_rpc_dir_rename_recv() called opath=%s npath=%s ring=%d ",
		  opath, npath, h->ring);

	if (h->ring == ctx.nprocs) {
		iov_req_t *user_data =
		    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->n = 1;
		user_data->iov[0].buffer = malloc(sizeof(int));
		user_data->iov[0].length = sizeof(int);
		ring_header_t *rh = (ring_header_t *)user_data->header;
		*(int *)(user_data->iov[0].buffer) = rh->relay_ret;
		ucs_status_t status;
		log_debug("fs_rpc_dir_rename_recv() finished ring=%d "
			  "relay_ret=%d",
			  h->ring, rh->relay_ret);
		status = post_iov_req(rh->reply_ep, RPC_RET_REP, user_data,
				      header_length);
		return (status);
	}

	if (h->ring == 0)
		h->reply_ep = param->reply_ep;

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 4);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 4;
	user_data->iov[0].buffer = malloc(sizeof(uint64_t));
	user_data->iov[0].length = sizeof(uint64_t);
	memcpy(user_data->iov[0].buffer, &oldbase, sizeof(uint64_t));
	user_data->iov[1].buffer = malloc(strlen(opath) + 1);
	user_data->iov[1].length = strlen(opath) + 1;
	memcpy(user_data->iov[1].buffer, opath, strlen(opath) + 1);
	user_data->iov[2].buffer = malloc(sizeof(uint64_t));
	user_data->iov[2].length = sizeof(uint64_t);
	memcpy(user_data->iov[2].buffer, &newbase, sizeof(uint64_t));
	user_data->iov[3].buffer = malloc(strlen(npath) + 1);
	user_data->iov[3].length = strlen(npath) + 1;
	memcpy(user_data->iov[3].buffer, npath, strlen(npath) + 1);
	ring_header_t *rh = (ring_header_t *)user_data->header;

	char oname[128];
	char nname[128];
	inode_t *oparent = get_parent_and_filename(oldbase, oname, opath, &ctx);
	inode_t *nparent = get_parent_and_filename(newbase, nname, npath, &ctx);

	if (oparent == NULL) {
		log_debug(
		    "fs_rpc_rename_recv() old parent path=%s does not exist",
		    opath);
		rh->relay_ret = FINCH_ENOENT;
	} else if (nparent == NULL) {
		log_debug(
		    "fs_rpc_rename_recv() new parent path=%s does not exist",
		    npath);
		rh->relay_ret = FINCH_ENOENT;
	} else {
		dentry_key_t old_dkey, new_dkey;
		MDB_txn *txn;
		MDB_val old_key, new_key, val;

		old_dkey.i_ino = oparent->i_ino;
		memcpy(old_dkey.name, oname, strlen(oname) + 1);
		for (int i = strlen(oname) + 1; i < sizeof(old_dkey.name); i++)
			old_dkey.name[i] = '\0';
		old_key.mv_data = &old_dkey;
		old_key.mv_size = sizeof(dentry_key_t);

		new_dkey.i_ino = nparent->i_ino;
		memcpy(new_dkey.name, nname, strlen(nname) + 1);
		for (int i = strlen(nname) + 1; i < sizeof(new_dkey.name); i++)
			new_dkey.name[i] = '\0';
		new_key.mv_data = &new_dkey;
		new_key.mv_size = sizeof(dentry_key_t);

		if (mdb_txn_begin(ctx.mdb_env, NULL, 0, &txn)) {
			log_error("fs_rpc_rename_recv() mdb_txn_begin() "
				  "failed: %s",
				  strerror(errno));
			rh->relay_ret = FINCH_EIO;
			goto out;
		}

		if (mdb_get(txn, ctx.dbi, &old_key, &val)) {
			log_debug(
			    "fs_rpc_rename_recv() opath=%s does not exist",
			    opath);
			rh->relay_ret = FINCH_ENOENT;
			mdb_txn_abort(txn);
		} else {
			uint64_t ino = *(uint64_t *)val.mv_data;
			mode_t mode = ctx.inodes[ino].mode;
			if (!S_ISDIR(mode)) {
				log_debug("fs_rpc_rename_recv() target is "
					  "not a directory");
				rh->relay_ret = FINCH_ENOTDIR;
				mdb_txn_abort(txn);
				goto out;
			}
			MDB_val old_val;
			if (!mdb_get(txn, ctx.dbi, &new_key, &old_val)) {
				uint64_t old_ino = *(uint64_t *)old_val.mv_data;
				inode_t *old_inode = &ctx.inodes[old_ino];
				old_inode->i_nlink--;
				mdb_del(txn, ctx.dbi, &new_key, NULL);
			}

			mdb_del(txn, ctx.dbi, &old_key, NULL);

			val.mv_data = &ino;
			val.mv_size = sizeof(uint64_t);
			mdb_put(txn, ctx.dbi, &new_key, &val, 0);

			rh->relay_ret = FINCH_OK;
			mdb_txn_commit(txn);
		}
	}
out:
	rh->ring++;
	if (ctx.nprocs == 1 || (h->ring == 0 && rh->relay_ret != FINCH_OK)) {
		iov_req_t *old = user_data;
		user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->n = 1;
		user_data->iov[0].buffer = malloc(sizeof(int));
		user_data->iov[0].length = sizeof(int);
		*(int *)(user_data->iov[0].buffer) = rh->relay_ret;
		ucs_status_t status;
		status = post_iov_req(param->reply_ep, RPC_RET_REP, user_data,
				      header_length);
		free(old->header);
		for (int i = 0; i < old->n; i++) {
			free(old->iov[i].buffer);
		}
		free(old);
		return (status);
	}
	if (h->ring > 0 && rh->relay_ret != h->relay_ret) {
		log_fatal("fs_rpc_mkdir_recv() inconsistent relay_ret ring=%u "
			  "relay_ret=%d header_relay_ret=%d",
			  h->ring, rh->relay_ret, h->relay_ret);
	}
	ucs_status_t status;
	log_debug("fs_rpc_dir_rename_recv() forwarding to ring=%u", h->ring);
	status = post_iov_req(ctx.ucp_next_ep, RPC_DIR_RENAME_REQ, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_file_rename_recv(void *arg, const void *header, size_t header_length,
			void *data, size_t length,
			const ucp_am_recv_param_t *param)
{
	uint64_t oldbase;
	char *opath;
	uint64_t newbase;
	char *npath;
	char *p = (char *)data;
	oldbase = *(uint64_t *)p;
	p += sizeof(uint64_t);
	opath = (char *)p;
	p += strlen(opath) + 1;
	newbase = *(uint64_t *)p;
	p += sizeof(uint64_t);
	npath = (char *)p;

	log_debug("fs_rpc_file_rename_recv() called opath=%s npath=%s", opath,
		  npath);

	iov_req_t *user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 1;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);

	char oname[128];
	char nname[128];
	inode_t *oparent = get_parent_and_filename(oldbase, oname, opath, &ctx);
	inode_t *nparent = get_parent_and_filename(newbase, nname, npath, &ctx);

	if (oparent == NULL) {
		log_debug(
		    "fs_rpc_rename_recv() old parent path=%s does not exist",
		    opath);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else if (nparent == NULL) {
		log_debug(
		    "fs_rpc_rename_recv() new parent path=%s does not exist",
		    npath);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		dentry_key_t old_dkey, new_dkey;
		MDB_txn *txn;
		MDB_val old_key, new_key, val;

		old_dkey.i_ino = oparent->i_ino;
		memcpy(old_dkey.name, oname, strlen(oname) + 1);
		for (int i = strlen(oname) + 1; i < sizeof(old_dkey.name); i++)
			old_dkey.name[i] = '\0';
		old_key.mv_data = &old_dkey;
		old_key.mv_size = sizeof(dentry_key_t);

		new_dkey.i_ino = nparent->i_ino;
		memcpy(new_dkey.name, nname, strlen(nname) + 1);
		for (int i = strlen(nname) + 1; i < sizeof(new_dkey.name); i++)
			new_dkey.name[i] = '\0';
		new_key.mv_data = &new_dkey;
		new_key.mv_size = sizeof(dentry_key_t);

		if (mdb_txn_begin(ctx.mdb_env, NULL, 0, &txn)) {
			log_error("fs_rpc_rename_recv() mdb_txn_begin() "
				  "failed: %s",
				  strerror(errno));
			*(int *)(user_data->iov[0].buffer) = FINCH_EIO;
			goto out;
		}

		if (mdb_get(txn, ctx.dbi, &old_key, &val)) {
			log_debug(
			    "fs_rpc_rename_recv() opath=%s does not exist",
			    opath);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
			mdb_txn_abort(txn);
		} else {
			uint64_t ino = *(uint64_t *)val.mv_data;
			mode_t mode = ctx.inodes[ino / ctx.nprocs].mode;
			if (S_ISDIR(mode)) {
				log_debug("fs_rpc_rename_recv() target is a "
					  "directory");
				*(int *)(user_data->iov[0].buffer) =
				    FINCH_EISDIR;
				mdb_txn_abort(txn);
				goto out;
			}
			MDB_val old_val;
			if (!mdb_get(txn, ctx.dbi, &new_key, &old_val)) {
				uint64_t old_ino = *(uint64_t *)old_val.mv_data;
				inode_t *old_inode =
				    &ctx.inodes[old_ino / ctx.nprocs];
				old_inode->i_nlink--;
				mdb_del(txn, ctx.dbi, &new_key, NULL);
			}

			mdb_del(txn, ctx.dbi, &old_key, NULL);

			val.mv_data = &ino;
			val.mv_size = sizeof(uint64_t);
			mdb_put(txn, ctx.dbi, &new_key, &val, 0);

			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
			mdb_txn_commit(txn);
		}
	}
out:
	ucs_status_t status;
	status = post_iov_req(param->reply_ep, RPC_RET_REP, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_file_link_recv(void *arg, const void *header, size_t header_length,
		      void *data, size_t length,
		      const ucp_am_recv_param_t *param)
{
	uint64_t oldbase;
	char *opath;
	uint64_t newbase;
	char *npath;
	char *p = (char *)data;
	oldbase = *(uint64_t *)p;
	p += sizeof(uint64_t);
	opath = (char *)p;
	p += strlen(opath) + 1;
	newbase = *(uint64_t *)p;
	p += sizeof(uint64_t);
	npath = (char *)p;
	p += strlen(npath) + 1;

	log_debug("fs_rpc_file_link_recv() called opath=%s npath=%s", opath,
		  npath);

	iov_req_t *user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 1;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);

	char oname[128];
	char nname[128];
	inode_t *oparent = get_parent_and_filename(oldbase, oname, opath, &ctx);
	inode_t *nparent = get_parent_and_filename(newbase, nname, npath, &ctx);

	if (oparent == NULL) {
		log_debug(
		    "fs_rpc_link_recv() old parent path=%s does not exist",
		    opath);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else if (nparent == NULL) {
		log_debug(
		    "fs_rpc_link_recv() new parent path=%s does not exist",
		    npath);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		dentry_key_t old_dkey, new_dkey;
		MDB_txn *txn;
		MDB_val old_key, new_key, val;

		old_dkey.i_ino = oparent->i_ino;
		memcpy(old_dkey.name, oname, strlen(oname) + 1);
		for (int i = strlen(oname) + 1; i < sizeof(old_dkey.name); i++)
			old_dkey.name[i] = '\0';
		old_key.mv_data = &old_dkey;
		old_key.mv_size = sizeof(dentry_key_t);

		new_dkey.i_ino = nparent->i_ino;
		memcpy(new_dkey.name, nname, strlen(nname) + 1);
		for (int i = strlen(nname) + 1; i < sizeof(new_dkey.name); i++)
			new_dkey.name[i] = '\0';
		new_key.mv_data = &new_dkey;
		new_key.mv_size = sizeof(dentry_key_t);

		if (mdb_txn_begin(ctx.mdb_env, NULL, 0, &txn)) {
			log_error("fs_rpc_link_recv() mdb_txn_begin() "
				  "failed: %s",
				  strerror(errno));
			*(int *)(user_data->iov[0].buffer) = FINCH_EIO;
			goto out;
		}

		if (mdb_get(txn, ctx.dbi, &old_key, &val)) {
			log_debug("fs_rpc_link_recv() opath=%s does not exist",
				  opath);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
			mdb_txn_abort(txn);
			goto out;
		} else {
			uint64_t ino = *(uint64_t *)val.mv_data;
			inode_t *inode = &ctx.inodes[ino];
			if (S_ISDIR(inode->mode)) {
				log_debug("fs_rpc_link_recv() hard link "
					  "to directory not allowed");
				*(int *)(user_data->iov[0].buffer) =
				    FINCH_EISDIR;
				mdb_txn_abort(txn);
				goto out;
			}
			val.mv_data = &ino;
			val.mv_size = sizeof(uint64_t);
			mdb_put(txn, ctx.dbi, &new_key, &val, 0);
			inode->i_nlink++;
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
			mdb_txn_commit(txn);
			goto out;
		}
	}
out:
	ucs_status_t status;
	status = post_iov_req(param->reply_ep, RPC_RET_REP, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_dir_link_recv(void *arg, const void *header, size_t header_length,
		     void *data, size_t length,
		     const ucp_am_recv_param_t *param)
{
	uint64_t oldbase;
	char *opath;
	uint64_t newbase;
	char *npath;
	ring_header_t *h = (ring_header_t *)header;
	char *p = (char *)data;
	oldbase = *(uint64_t *)p;
	p += sizeof(uint64_t);
	opath = (char *)p;
	p += strlen(opath) + 1;
	newbase = *(uint64_t *)p;
	p += sizeof(uint64_t);
	npath = (char *)p;
	p += strlen(npath) + 1;

	log_debug("fs_rpc_dir_link_recv() called opath=%s npath=%s", opath,
		  npath);

	if (h->ring == ctx.nprocs) {
		iov_req_t *user_data =
		    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->n = 1;
		user_data->iov[0].buffer = malloc(sizeof(int));
		user_data->iov[0].length = sizeof(int);
		ring_header_t *rh = (ring_header_t *)user_data->header;
		*(int *)(user_data->iov[0].buffer) = rh->relay_ret;
		ucs_status_t status;
		log_debug("fs_rpc_link_recv() finished ring=%d "
			  "relay_ret=%d",
			  h->ring, rh->relay_ret);
		status = post_iov_req(rh->reply_ep, RPC_RET_REP, user_data,
				      header_length);
		return (status);
	}

	if (h->ring == 0)
		h->reply_ep = param->reply_ep;

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 4);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 4;
	user_data->iov[0].buffer = malloc(sizeof(uint64_t));
	user_data->iov[0].length = sizeof(uint64_t);
	memcpy(user_data->iov[0].buffer, &oldbase, sizeof(uint64_t));
	user_data->iov[1].buffer = malloc(strlen(opath) + 1);
	user_data->iov[1].length = strlen(opath) + 1;
	memcpy(user_data->iov[1].buffer, opath, strlen(opath) + 1);
	user_data->iov[2].buffer = malloc(sizeof(uint64_t));
	user_data->iov[2].length = sizeof(uint64_t);
	memcpy(user_data->iov[2].buffer, &newbase, sizeof(uint64_t));
	user_data->iov[3].buffer = malloc(strlen(npath) + 1);
	user_data->iov[3].length = strlen(npath) + 1;
	memcpy(user_data->iov[3].buffer, npath, strlen(npath) + 1);
	ring_header_t *rh = (ring_header_t *)user_data->header;

	char oname[128];
	char nname[128];
	inode_t *oparent = get_parent_and_filename(oldbase, oname, opath, &ctx);
	inode_t *nparent = get_parent_and_filename(newbase, nname, npath, &ctx);

	if (oparent == NULL) {
		log_debug(
		    "fs_rpc_link_recv() old parent path=%s does not exist",
		    opath);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else if (nparent == NULL) {
		log_debug(
		    "fs_rpc_link_recv() new parent path=%s does not exist",
		    npath);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		dentry_key_t old_dkey, new_dkey;
		MDB_txn *txn;
		MDB_val old_key, new_key, val;

		old_dkey.i_ino = oparent->i_ino;
		memcpy(old_dkey.name, oname, strlen(oname) + 1);
		for (int i = strlen(oname) + 1; i < sizeof(old_dkey.name); i++)
			old_dkey.name[i] = '\0';
		old_key.mv_data = &old_dkey;
		old_key.mv_size = sizeof(dentry_key_t);

		new_dkey.i_ino = nparent->i_ino;
		memcpy(new_dkey.name, nname, strlen(nname) + 1);
		for (int i = strlen(nname) + 1; i < sizeof(new_dkey.name); i++)
			new_dkey.name[i] = '\0';
		new_key.mv_data = &new_dkey;
		new_key.mv_size = sizeof(dentry_key_t);

		if (mdb_txn_begin(ctx.mdb_env, NULL, 0, &txn)) {
			log_error("fs_rpc_link_recv() mdb_txn_begin() "
				  "failed: %s",
				  strerror(errno));
			rh->relay_ret = FINCH_EIO;
			goto out;
		}

		if (mdb_get(txn, ctx.dbi, &old_key, &val)) {
			log_debug("fs_rpc_link_recv() opath=%s does not exist",
				  opath);
			rh->relay_ret = FINCH_ENOENT;
			mdb_txn_abort(txn);
			goto out;
		} else {
			uint64_t ino = *(uint64_t *)val.mv_data;
			inode_t *inode = &ctx.inodes[ino];
			if (!S_ISDIR(inode->mode)) {
				log_debug("fs_rpc_link_recv() hard link "
					  "to file not allowed");
				rh->relay_ret = FINCH_ENOTDIR;
				mdb_txn_abort(txn);
				goto out;
			}
			log_debug("fs_rpc_link_recv() creating link to "
				  "directory ino=%lu",
				  ino);
			val.mv_data = &ino;
			val.mv_size = sizeof(uint64_t);
			mdb_put(txn, ctx.dbi, &new_key, &val, 0);
			inode->i_nlink++;
			rh->relay_ret = FINCH_OK;
			mdb_txn_commit(txn);
			goto out;
		}
	}
out:
	rh->ring++;
	if (ctx.nprocs == 1 || (h->ring == 0 && rh->relay_ret != FINCH_OK)) {
		iov_req_t *old = user_data;
		user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->n = 1;
		user_data->iov[0].buffer = malloc(sizeof(int));
		user_data->iov[0].length = sizeof(int);
		*(int *)(user_data->iov[0].buffer) = rh->relay_ret;
		ucs_status_t status;
		status = post_iov_req(param->reply_ep, RPC_RET_REP, user_data,
				      header_length);
		free(old->header);
		for (int i = 0; i < old->n; i++) {
			free(old->iov[i].buffer);
		}
		free(old);
		return (status);
	}
	if (h->ring > 0 && rh->relay_ret != h->relay_ret) {
		log_fatal("fs_rpc_link_recv() inconsistent relay_ret ring=%u "
			  "relay_ret=%d header_relay_ret=%d",
			  h->ring, rh->relay_ret, h->relay_ret);
	}
	ucs_status_t status;
	status = post_iov_req(ctx.ucp_next_ep, RPC_DIR_LINK_REQ, user_data,
			      header_length);
	return (status);
}

struct finchfs_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char pad;
	char d_name[];
};

struct finchfs_pos {
	MDB_txn *txn;
	MDB_cursor *cur;
};

ucs_status_t
fs_rpc_getdents_recv(void *arg, const void *header, size_t header_length,
		     void *data, size_t length,
		     const ucp_am_recv_param_t *param)
{
	uint64_t ino = *(uint64_t *)data;
	getdents_header_t *hdr = (getdents_header_t *)header;

	log_debug("fs_rpc_getdents_recv() called");

	contig_req_t *user_data = malloc(sizeof(contig_req_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	getdents_header_t *rhdr = (getdents_header_t *)user_data->header;
	user_data->buf = malloc(hdr->count);

	ucp_request_param_t rparam = {
	    .op_attr_mask = UCP_OP_ATTR_FIELD_DATATYPE |
			    UCP_OP_ATTR_FIELD_CALLBACK |
			    UCP_OP_ATTR_FIELD_USER_DATA,
	    .cb =
		{
		    .send = fs_rpc_contig_reply_cb,
		},
	    .datatype = ucp_dt_make_contig(sizeof(char)),
	    .user_data = user_data,
	};
	struct finchfs_pos *pos;
	if (hdr->pos == 0) {
		pos = malloc(sizeof(struct finchfs_pos));
		if (mdb_txn_begin(ctx.mdb_env, NULL, MDB_RDONLY, &pos->txn)) {
			log_error(
			    "fs_rpc_getdents_recv() mdb_txn_begin() failed: %s",
			    strerror(errno));
			rhdr->ret = FINCH_EIO;
			goto out;
		}
		if (mdb_cursor_open(pos->txn, ctx.dbi, &pos->cur)) {
			log_error("fs_rpc_getdents_recv() mdb_cursor_open() "
				  "failed: %s",
				  strerror(errno));
			mdb_txn_abort(pos->txn);
			rhdr->ret = FINCH_EIO;
			goto out;
		}
	} else {
		pos = (struct finchfs_pos *)hdr->pos;
	}

	inode_t *dir = &ctx.inodes[ino];
	rhdr->ret = FINCH_ENOENT;
	rhdr->count = 0;
	rhdr->pos = (uint64_t)pos;

	MDB_val k, v;

	dentry_key_t dkey;
	int rc;
	dkey.i_ino = dir->i_ino;
	if (hdr->pos == 0) {
		for (int i = 0; i < sizeof(dkey.name); i++)
			dkey.name[i] = '\0';
		k.mv_data = &dkey;
		k.mv_size = sizeof(dentry_key_t);

		rc = mdb_cursor_get(pos->cur, &k, &v, MDB_SET_RANGE);
	} else {
		rc = mdb_cursor_get(pos->cur, &k, &v, MDB_GET_CURRENT);
	}

	struct finchfs_dirent *ent = NULL;
	while (rc == 0) {
		dentry_key_t *dk = (dentry_key_t *)k.mv_data;
		if (dk->i_ino != dir->i_ino)
			break;

		inode_t *child = &ctx.inodes[(*(uint64_t *)v.mv_data)];

		if (S_ISDIR(child->mode) && ctx.rank != 0) {
			rc = mdb_cursor_get(pos->cur, &k, &v, MDB_NEXT);
			continue;
		}

		size_t name_len = strlen(dk->name) + 1;
		ent = (struct finchfs_dirent *)(user_data->buf + rhdr->count);
		if (rhdr->count + sizeof(struct finchfs_dirent) + name_len >
		    hdr->count) {
			rhdr->ret = FINCH_INPROGRESS;
			break;
		}
		rhdr->ret = FINCH_OK;
		rhdr->count += sizeof(struct finchfs_dirent) + name_len;
		ent->d_ino = child->i_ino;
		ent->d_off = rhdr->count;
		ent->d_reclen = sizeof(struct finchfs_dirent) + name_len;
		strcpy(ent->d_name, dk->name);
		rc = mdb_cursor_get(pos->cur, &k, &v, MDB_NEXT);
	}
	if (ent != NULL) {
		ent->d_off = 0;
	}

	if (rhdr->ret == FINCH_OK || rhdr->ret == FINCH_ENOENT) {
		mdb_cursor_close(pos->cur);
		mdb_txn_abort(pos->txn);
		free(pos);
	}

out:
	log_debug("fs_rpc_getdents_recv() sending count=%d", rhdr->count);

	ucs_status_ptr_t req = ucp_am_send_nbx(
	    param->reply_ep, RPC_GETDENTS_REP, rhdr, sizeof(*rhdr),
	    user_data->buf, rhdr->count == 0 ? 1 : rhdr->count, &rparam);

	if (req == NULL) {
		free(user_data->header);
		free(user_data->buf);
		free(user_data);
	} else if (UCS_PTR_IS_ERR(req)) {
		log_error("ucp_am_send_nbx() failed: %s",
			  ucs_status_string(UCS_PTR_STATUS(req)));
		free(user_data->header);
		free(user_data->buf);
		free(user_data);
		ucs_status_t status = UCS_PTR_STATUS(req);
		ucp_request_free(req);
		return (status);
	}
	return (UCS_OK);
}

int
fs_server_init(char *db_dir, int rank, int nprocs, int *shutdown)
{
	ctx.rank = rank;
	ctx.nprocs = nprocs;
	ctx.shutdown = shutdown;

	ucs_status_t status;
	ucp_params_t ucp_params = {
	    .field_mask = UCP_PARAM_FIELD_FEATURES,
	    .features = UCP_FEATURE_RMA | UCP_FEATURE_AM,
	};
	if ((status = ucp_init(&ucp_params, NULL, &ctx.ucp_context)) !=
	    UCS_OK) {
		log_error("ucp_init() failed: %s", ucs_status_string(status));
		return (-1);
	}
	ucp_worker_params_t ucp_worker_params = {
	    .field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE,
	    .thread_mode = UCS_THREAD_MODE_SINGLE};
	if ((status = ucp_worker_create(ctx.ucp_context, &ucp_worker_params,
					&ctx.ucp_worker)) != UCS_OK) {
		log_error("ucp_worker_create() failed: %s",
			  ucs_status_string(status));
		return (-1);
	}

	ucp_am_handler_param_t mkdir_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_MKDIR_REQ,
	    .cb = fs_rpc_mkdir_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(ctx.ucp_worker,
						     &mkdir_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(mkdir) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_create_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_CREATE_REQ,
	    .cb = fs_rpc_inode_create_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &inode_create_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(create) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t dir_unlink_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_DIR_UNLINK_REQ,
	    .cb = fs_rpc_dir_unlink_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &dir_unlink_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(unlink) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t file_unlink_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_FILE_UNLINK_REQ,
	    .cb = fs_rpc_file_unlink_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &file_unlink_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(unlink) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_stat_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_STAT_REQ,
	    .cb = fs_rpc_inode_stat_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &inode_stat_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(stat) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_write_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_WRITE_REQ,
	    .cb = fs_rpc_inode_write_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &inode_write_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(write) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_read_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_READ_REQ,
	    .cb = fs_rpc_inode_read_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &inode_read_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(write) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t dir_rename_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_DIR_RENAME_REQ,
	    .cb = fs_rpc_dir_rename_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &dir_rename_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(dir move) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t file_rename_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_FILE_RENAME_REQ,
	    .cb = fs_rpc_file_rename_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &file_rename_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(dir move) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_stat_update_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_STAT_UPDATE_REQ,
	    .cb = fs_rpc_inode_stat_update_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &inode_stat_update_param)) != UCS_OK) {
		log_error(
		    "ucp_worker_set_am_recv_handler(stat update) failed: %s",
		    ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t getdents_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_GETDENTS_REQ,
	    .cb = fs_rpc_getdents_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &getdents_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(getdents) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t file_link_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_FILE_LINK_REQ,
	    .cb = fs_rpc_file_link_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &file_link_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(link) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t dir_link_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_DIR_LINK_REQ,
	    .cb = fs_rpc_dir_link_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &dir_link_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(link) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}

	ctx.fs = fs_inode_init(db_dir);

	char meta_dir[128];
	snprintf(meta_dir, sizeof(meta_dir), "meta_%d", rank);

	if (mkdir(meta_dir, 0777)) {
		if (errno != EEXIST) {
			log_fatal("fs_server_init() mkdir(%s) failed: %s",
				  meta_dir, strerror(errno));
		}
	}

	char inode_path[128];
	snprintf(inode_path, sizeof(inode_path), "meta_%d/inodes.mmap", rank);
	int fd = open(inode_path, O_RDWR | O_CREAT, 0666);
	if (fd < 0) {
		log_fatal("fs_server_init() open(%s) failed: %s", inode_path,
			  strerror(errno));
	}
	size_t inode_file_size = sizeof(inode_t) * MAX_INODES;
	if (ftruncate(fd, inode_file_size + sizeof(uint64_t)) < 0) {
		log_fatal("fs_server_init() ftruncate(%s) failed: %s",
			  inode_path, strerror(errno));
	}
	ctx.inodes = mmap(NULL, inode_file_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, fd, 0);
	if (ctx.inodes == MAP_FAILED) {
		log_fatal("fs_server_init() mmap(%s) failed: %s", inode_path,
			  strerror(errno));
	}

	ctx.inodes[0].i_ino = 0;
	ctx.inodes[0].mode = S_IFDIR | S_IRWXU;
	ctx.inodes[0].chunk_size = 0;
	ctx.inodes[0].size = 0;
	ctx.inodes[0].i_count = 0;
	ctx.inodes[0].i_nlink = 1;
	timespec_get(&ctx.inodes[0].mtime, TIME_UTC);
	timespec_get(&ctx.inodes[0].ctime, TIME_UTC);
	close(fd);
	ctx.i_ino = (uint64_t *)&ctx.inodes[MAX_INODES];
	if (*ctx.i_ino == 0) {
		*ctx.i_ino = rank + nprocs;
	}

	mdb_env_create(&ctx.mdb_env);
	mdb_env_set_maxdbs(ctx.mdb_env, 1);
	mdb_env_set_mapsize(ctx.mdb_env, 1ULL << 33);
	if (mdb_env_open(ctx.mdb_env, meta_dir, 0, 0666)) {
		log_fatal("fs_server_init() mdb_env_open(%s) failed: %s",
			  meta_dir, strerror(errno));
	}
	MDB_txn *txn;
	if (mdb_txn_begin(ctx.mdb_env, NULL, 0, &txn)) {
		log_fatal("fs_server_init() mdb_txn_begin() failed: %s",
			  strerror(errno));
	}
	if (mdb_dbi_open(txn, "dentry", MDB_CREATE, &ctx.dbi)) {
		log_fatal("fs_server_init() mdb_dbi_open() failed: %s",
			  strerror(errno));
	}
	if (mdb_txn_commit(txn)) {
		log_fatal("fs_server_init() mdb_txn_commit() failed: %s",
			  strerror(errno));
	}
	return (0);
}

int
fs_server_get_address(void **addr, size_t *addr_len)
{
	ucs_status_t status;
	if ((status = ucp_worker_get_address(
		 ctx.ucp_worker, (ucp_address_t **)addr, addr_len)) != UCS_OK) {
		log_error("ucp_worker_get_address() failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	return (0);
}

static void
ep_err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
{
	log_error("error handling callback was invoked with status %s",
		  ucs_status_string(status));
}

void
fs_server_set_addresses(void *addr, size_t addr_len, size_t len)
{
	ucs_status_t status;
	ucp_address_t *ucp_addr =
	    (ucp_address_t *)(addr + addr_len * ((ctx.rank + 1) % ctx.nprocs));
	if (ctx.nprocs > 1) {
		ucp_ep_params_t ucp_ep_params = {
		    .field_mask = UCP_EP_PARAM_FIELD_ERR_HANDLER |
				  UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE |
				  UCP_EP_PARAM_FIELD_REMOTE_ADDRESS,
		    .err_handler =
			{
			    .arg = NULL,
			    .cb = ep_err_cb,
			},
		    .err_mode = UCP_ERR_HANDLING_MODE_NONE,
		    .address = ucp_addr,
		};
		if ((status = ucp_ep_create(ctx.ucp_worker, &ucp_ep_params,
					    &ctx.ucp_next_ep)) != UCS_OK) {
			log_fatal("ucp_ep_create() failed: %s",
				  ucs_status_string(status));
			return;
		}
	}
}

void
fs_server_release_address(void *addr)
{
	ucp_worker_release_address(ctx.ucp_worker, addr);
}

int
fs_server_term(int trank)
{
	mdb_dbi_close(ctx.mdb_env, ctx.dbi);
	mdb_env_close(ctx.mdb_env);
	ucp_worker_destroy(ctx.ucp_worker);
	ucp_cleanup(ctx.ucp_context);
	fs_inode_term(ctx.fs);
	return (0);
}

void *
fs_server_progress()
{
	while (*ctx.shutdown == 0) {
		ucp_worker_progress(ctx.ucp_worker);
	}
	return (NULL);
}
