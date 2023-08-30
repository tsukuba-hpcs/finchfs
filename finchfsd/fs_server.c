/*
Copyright (c) 2021-2023 Osamu Tatebe.  All Rights Reserved.

The authors hereby grant permission to use, copy, modify, and
distribute this software and its documentation for any purpose,
provided that existing copyright notices are retained in all copies
and that this notice is included verbatim in any distributions.  The
name of the authors may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, ITS
DOCUMENTATION, OR ANY DERIVATIVES THEREOF, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
#include <ucp/api/ucp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include "fs_types.h"
#include "fs_rpc.h"
#include "hashmap.h"
#include "fs.h"
#include "log.h"

#define MAX_NTHREADS 128

typedef struct {
	char *name;
	mode_t mode;
	size_t chunk_size;
	uint32_t i_ino;
	struct timespec mtime;
	struct timespec ctime;
	struct hashmap *entries;
} entry_t;

struct worker_ctx {
	int rank;
	int nprocs;
	int trank;
	int nthreads;
	uint32_t i_ino;
	ucp_worker_h ucp_worker;
	int *shutdown;
	entry_t root;
} all_ctx[MAX_NTHREADS];

static uint32_t
alloc_ino(struct worker_ctx *ctx)
{
	return __atomic_fetch_add(&ctx->i_ino, ctx->nprocs * ctx->nthreads,
				  __ATOMIC_SEQ_CST);
}

static int
entry_compare(const void *a, const void *b, void *udata)
{
	const entry_t *ea = a;
	const entry_t *eb = b;
	return strcmp(ea->name, eb->name);
}

static uint64_t
entry_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
	const entry_t *e = item;
	return hashmap_sip(e->name, strlen(e->name), seed0, seed1);
}

static void
free_meta_tree(entry_t *entry)
{
	if (S_ISDIR(entry->mode)) {
		size_t iter = 0;
		void *item;
		while (hashmap_iter(entry->entries, &iter, &item)) {
			entry_t *child = item;
			free_meta_tree(child);
		}
		hashmap_free(entry->entries);
	}
}

static entry_t *
get_parent_and_filename(char *filename, const char *path,
			struct worker_ctx *ctx)
{
	entry_t *e = &ctx->root;
	char *prev = (char *)path;
	char *p = prev;
	int path_len = strlen(path) + 1;
	char name[128];
	while ((p = strchr(p, '/')) != NULL) {
		memcpy(name, prev, p - prev);
		name[p - prev] = '\0';
		prev = ++p;
		e = hashmap_get(e->entries, &(entry_t){.name = name});
		if (e == NULL) {
			log_error(
			    "get_parent_and_filename() path=%s does not exist",
			    path);
			return (NULL);
		}
		if (!S_ISDIR(e->mode)) {
			log_error("get_parent_and_filename() path=%s is not a "
				  "directory",
				  path);
			return (NULL);
		}
	}
	memcpy(filename, prev, path_len - (prev - path));
	filename[path_len - (prev - path)] = '\0';
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
	struct worker_ctx *ctx = (struct worker_ctx *)arg;
	int path_len;
	char *path;
	mode_t mode;
	size_t offset = 0;
	path_len = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(path_len);
	path = (char *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += path_len;
	mode = *(mode_t *)UCS_PTR_BYTE_OFFSET(data, offset);

	log_debug("fs_rpc_mkdir_recv() called path=%s", path);

	iov_req_t *user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 1;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);

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
	char dirname[128];
	entry_t *parent = get_parent_and_filename(dirname, path, ctx);

	if (parent == NULL) {
		log_debug("fs_rpc_mkdir_recv() parent path=%s does not exist",
			  path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		entry_t newent = {
		    .name = strdup(dirname),
		};
		entry_t *ent = hashmap_get(parent->entries, &newent);
		if (ent != NULL) {
			log_debug("fs_rpc_mkdir_recv() path=%s already exists",
				  path);
			free(newent.name);
			*(int *)(user_data->iov[0].buffer) = FINCH_EEXIST;
		} else {
			log_debug("fs_rpc_mkdir_recv() create path=%s", path);
			newent.mode = mode;
			newent.chunk_size = 0;
			newent.i_ino = alloc_ino(ctx);
			timespec_get(&newent.mtime, TIME_UTC);
			timespec_get(&newent.ctime, TIME_UTC);
			newent.entries =
			    hashmap_new(sizeof(entry_t), 0, 0, 0, entry_hash,
					entry_compare, NULL, NULL);
			hashmap_set(parent->entries, &newent);
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
			ent = hashmap_get(parent->entries, &newent);
		}
	}

	ucs_status_ptr_t req = ucp_am_send_nbx(
	    param->reply_ep, RPC_RET_REP, user_data->header, header_length,
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

ucs_status_t
fs_rpc_inode_create_recv(void *arg, const void *header, size_t header_length,
			 void *data, size_t length,
			 const ucp_am_recv_param_t *param)
{
	struct worker_ctx *ctx = (struct worker_ctx *)arg;
	int path_len;
	char *path;
	mode_t mode;
	size_t chunk_size;
	uint32_t i_ino;
	size_t offset = 0;
	path_len = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(path_len);
	path = (char *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += path_len;
	mode = *(mode_t *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(mode);
	chunk_size = *(size_t *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(chunk_size);
	i_ino = *(uint32_t *)UCS_PTR_BYTE_OFFSET(data, offset);

	log_debug("fs_rpc_inode_create_recv() called path=%s", path);

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 2);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 2;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);
	user_data->iov[1].buffer = malloc(sizeof(uint32_t));
	user_data->iov[1].length = sizeof(uint32_t);

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

	char filename[128];
	entry_t *parent = get_parent_and_filename(filename, path, ctx);
	if (parent == NULL) {
		log_debug("fs_rpc_inode_create_recv() path=%s does not exist",
			  path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		log_debug("fs_rpc_inode_create_recv() create path=%s", path);
		entry_t newent = {
		    .name = strdup(filename),
		    .mode = mode,
		    .chunk_size = chunk_size,
		    .i_ino = (i_ino == 0) ? alloc_ino(ctx) : i_ino,
		    .entries = NULL,
		};
		timespec_get(&newent.mtime, TIME_UTC);
		timespec_get(&newent.ctime, TIME_UTC);
		hashmap_set(parent->entries, &newent);
		*(int *)(user_data->iov[0].buffer) = FINCH_OK;
		*(uint32_t *)(user_data->iov[1].buffer) = newent.i_ino;
	}

	ucs_status_ptr_t req = ucp_am_send_nbx(
	    param->reply_ep, RPC_INODE_REP, user_data->header, header_length,
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

ucs_status_t
fs_rpc_inode_unlink_recv(void *arg, const void *header, size_t header_length,
			 void *data, size_t length,
			 const ucp_am_recv_param_t *param)
{
	struct worker_ctx *ctx = (struct worker_ctx *)arg;
	int path_len;
	char *path;
	size_t offset = 0;
	path_len = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(path_len);
	path = (char *)UCS_PTR_BYTE_OFFSET(data, offset);

	log_debug("fs_rpc_inode_unlink_recv() called path=%s", path);

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 2);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 2;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);
	user_data->iov[1].buffer = malloc(sizeof(uint32_t));
	user_data->iov[1].length = sizeof(uint32_t);

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

	char name[128];
	entry_t *parent = get_parent_and_filename(name, path, ctx);
	if (parent == NULL) {
		log_debug("fs_rpc_inode_unlink_recv() path=%s does not exist",
			  path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		entry_t key = {
		    .name = name,
		};
		entry_t *ent = hashmap_get(parent->entries, &key);
		if (ent == NULL) {
			log_debug(
			    "fs_rpc_inode_unlink_recv() path=%s does not exist",
			    path);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
		} else {
			*(uint32_t *)user_data->iov[1].buffer = ent->i_ino;
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
			free_meta_tree(ent);
			hashmap_delete(parent->entries, &key);
		}
	}

	ucs_status_ptr_t req = ucp_am_send_nbx(
	    param->reply_ep, RPC_INODE_REP, user_data->header, header_length,
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

ucs_status_t
fs_rpc_inode_stat_recv(void *arg, const void *header, size_t header_length,
		       void *data, size_t length,
		       const ucp_am_recv_param_t *param)
{
	struct worker_ctx *ctx = (struct worker_ctx *)arg;
	int path_len;
	char *path;
	size_t offset = 0;
	path_len = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(path_len);
	path = (char *)UCS_PTR_BYTE_OFFSET(data, offset);

	log_debug("fs_rpc_inode_stat_recv() called path=%s header_length=%d",
		  path, header_length);

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 2);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 2;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);
	user_data->iov[1].buffer = malloc(sizeof(fs_stat_t));
	user_data->iov[1].length = sizeof(fs_stat_t);

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

	fs_stat_t *st = (fs_stat_t *)user_data->iov[1].buffer;
	char name[128];
	entry_t *parent = get_parent_and_filename(name, path, ctx);
	if (parent == NULL) {
		log_debug("fs_rpc_inode_stat_recv() path=%s does not exist",
			  path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		entry_t key = {
		    .name = name,
		};
		const entry_t *ent = hashmap_get(parent->entries, &key);
		if (ent == NULL) {
			log_debug(
			    "fs_rpc_inode_stat_recv() path=%s does not exist",
			    path);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
		} else {
			st->chunk_size = ent->chunk_size;
			st->i_ino = ent->i_ino;
			st->mode = ent->mode;
			st->mtime = ent->mtime;
			st->ctime = ent->ctime;
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
		}
	}

	ucs_status_ptr_t req = ucp_am_send_nbx(
	    param->reply_ep, RPC_INODE_STAT_REP, user_data->header,
	    header_length, user_data->iov, user_data->n, &rparam);

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

static int
fs_rpc_inode_write_internal(uint32_t i_ino, uint32_t index, off_t offset,
			    size_t size, const void *buf, ucp_ep_h reply_ep,
			    void *handle)
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

	*(ssize_t *)user_data->iov[1].buffer =
	    fs_inode_write(i_ino, index, offset, size, buf);
	if (*(ssize_t *)user_data->iov[1].buffer < 0) {
		*(int *)(user_data->iov[0].buffer) = -errno;
	} else {
		*(int *)(user_data->iov[0].buffer) = FINCH_OK;
	}
	ucs_status_ptr_t req = ucp_am_send_nbx(
	    reply_ep, RPC_INODE_WRITE_REP, user_data->header, sizeof(void *),
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
		ucp_request_free(req);
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
	    req_rndv->buf, req_rndv->reply_ep, header->handle);
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
	struct worker_ctx *ctx = (struct worker_ctx *)arg;
	inode_write_header_t *hdr = (inode_write_header_t *)header;
	log_debug(
	    "fs_rpc_inode_write_recv() called i_ino=%ld offset=%d length=%zu",
	    hdr->i_ino, hdr->offset, length);

	if (param->recv_attr & UCP_AM_RECV_ATTR_FLAG_RNDV) {
		req_rndv_t *user_data = malloc(sizeof(req_rndv_t));
		log_debug("fs_rpc_inode_write_recv() rndv start");
		user_data->header = malloc(header_length);
		memcpy(user_data->header, header, header_length);
		user_data->size = length;
		user_data->buf = malloc(length);
		user_data->reply_ep = param->reply_ep;
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
		    ctx->ucp_worker, data, user_data->buf, length, &rparam);
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
	} else {
		log_debug("fs_rpc_inode_write_recv() eager start");
		int ret;
		ret = fs_rpc_inode_write_internal(hdr->i_ino, hdr->index,
						  hdr->offset, length, data,
						  param->reply_ep, hdr->handle);
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
	struct worker_ctx *ctx = (struct worker_ctx *)arg;

	contig_req_t *user_data = malloc(sizeof(contig_req_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	inode_read_header_t *rhdr = (inode_read_header_t *)user_data->header;
	user_data->buf = malloc(rhdr->size);
	log_debug(
	    "fs_rpc_inode_read_recv() called i_ino=%ld offset=%d length=%zu",
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

	rhdr->size = fs_inode_read(rhdr->i_ino, rhdr->index, rhdr->offset,
				   rhdr->size, user_data->buf);
	if (rhdr->size < 0) {
		log_error("fs_inode_read() failed: %s", strerror(errno));
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
fs_rpc_dir_move_recv(void *arg, const void *header, size_t header_length,
		     void *data, size_t length,
		     const ucp_am_recv_param_t *param)
{
	struct worker_ctx *ctx = (struct worker_ctx *)arg;
	int opath_len;
	int npath_len;
	char *opath;
	char *npath;
	size_t offset = 0;
	opath_len = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(opath_len);
	opath = (char *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += opath_len;
	npath_len = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(npath_len);
	npath = (char *)UCS_PTR_BYTE_OFFSET(data, offset);

	log_debug("fs_rpc_dir_move_recv() called opath=%s npath=%s", opath,
		  npath);

	iov_req_t *user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 1;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);

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
	char odirname[128];
	char ndirname[128];
	entry_t *oparent = get_parent_and_filename(odirname, opath, ctx);
	entry_t *nparent = get_parent_and_filename(ndirname, npath, ctx);

	if (oparent == NULL) {
		log_debug("fs_rpc_dir_move_recv() opath=%s does not exist",
			  opath);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else if (nparent == NULL) {
		log_debug("fs_rpc_dir_move_recv() npath=%s does not exist",
			  npath);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		entry_t key = {
		    .name = odirname,
		};
		entry_t *ent = hashmap_get(oparent->entries, &key);
		if (ent == NULL) {
			log_debug(
			    "fs_rpc_dir_move_recv() opath=%s does not exist",
			    opath);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
		} else if (!S_ISDIR(ent->mode)) {
			log_debug("fs_rpc_dir_move_recv() opath=%s is not a "
				  "directory",
				  opath);
			*(int *)(user_data->iov[0].buffer) = FINCH_EISDIR;
		} else {
			entry_t newent = {
			    .name = strdup(ndirname),
			    .mode = ent->mode,
			    .chunk_size = ent->chunk_size,
			    .i_ino = ent->i_ino,
			    .mtime = ent->mtime,
			    .ctime = ent->ctime,
			    .entries = ent->entries,
			};
			hashmap_delete(oparent->entries, &key);
			hashmap_set(nparent->entries, &newent);
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
		}
	}

	ucs_status_ptr_t req = ucp_am_send_nbx(
	    param->reply_ep, RPC_RET_REP, user_data->header, header_length,
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

int
fs_server_init(ucp_worker_h worker, char *db_dir, int rank, int nprocs,
	       int trank, int nthreads, int *shutdown)
{
	if (trank >= MAX_NTHREADS) {
		log_error("fs_server_init() trank=%d >= MAX_NTHREADS=%d", trank,
			  MAX_NTHREADS);
		return (-1);
	}
	struct worker_ctx *ctx = &all_ctx[trank];

	ctx->rank = rank;
	ctx->nprocs = nprocs;
	ctx->trank = trank;
	ctx->nthreads = nthreads;
	ctx->i_ino = rank + (nprocs * nthreads);
	ctx->ucp_worker = worker;
	ctx->shutdown = shutdown;

	ctx->root.name = "";
	ctx->root.mode = S_IFDIR | S_IRWXU;
	ctx->root.chunk_size = 0;
	ctx->root.i_ino = 0;
	timespec_get(&ctx->root.mtime, TIME_UTC);
	timespec_get(&ctx->root.ctime, TIME_UTC);
	ctx->root.entries = hashmap_new(sizeof(entry_t), 0, 0, 0, entry_hash,
					entry_compare, NULL, NULL);

	fs_inode_init(db_dir);

	ucs_status_t status;
	ucp_am_handler_param_t mkdir_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_MKDIR_REQ,
	    .cb = fs_rpc_mkdir_recv,
	    .arg = ctx,
	};
	if ((status = ucp_worker_set_am_recv_handler(worker, &mkdir_param)) !=
	    UCS_OK) {
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
	    .arg = ctx,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 worker, &inode_create_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(create) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_unlink_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_UNLINK_REQ,
	    .cb = fs_rpc_inode_unlink_recv,
	    .arg = ctx,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 worker, &inode_unlink_param)) != UCS_OK) {
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
	    .arg = ctx,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 worker, &inode_stat_param)) != UCS_OK) {
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
	    .arg = ctx,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 worker, &inode_write_param)) != UCS_OK) {
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
	    .arg = ctx,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 worker, &inode_read_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(write) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t dir_move_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_DIR_MOVE_REQ,
	    .cb = fs_rpc_dir_move_recv,
	    .arg = ctx,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 worker, &dir_move_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(dir move) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	return (0);
}

int
fs_server_term(int trank)
{
	struct worker_ctx *ctx = &all_ctx[trank];
	free_meta_tree(&ctx->root);
	return (0);
}

void *
fs_server_progress(void *arg)
{
	int trank = *(int *)arg;
	struct worker_ctx *ctx = &all_ctx[trank];
	while (*ctx->shutdown == 0) {
		ucp_worker_progress(ctx->ucp_worker);
	}
	return (NULL);
}