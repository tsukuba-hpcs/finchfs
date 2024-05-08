#include <ucp/api/ucp.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include "finchfs.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "tree.h"
#include "fs.h"
#include "log.h"
#include "find.h"

struct entry;
RB_HEAD(entrytree, entry);
struct entry {
	char *name;
	mode_t mode;
	size_t chunk_size;
	uint64_t i_ino;
	struct timespec mtime;
	struct timespec ctime;
	size_t size;
	uint32_t ref_count;
	RB_ENTRY(entry) link;
	struct entrytree entries;
};

typedef struct entry entry_t;

static int
entry_compare(entry_t *a, entry_t *b)
{
	return strcmp(a->name, b->name);
}

RB_GENERATE(entrytree, entry, link, entry_compare);

struct worker_ctx {
	int rank;
	int nprocs;
	int lrank;
	int lnprocs;
	uint64_t i_ino;
	ucp_context_h ucp_context;
	ucp_worker_h ucp_worker;
	int *shutdown;
	entry_t root;
	struct fs_ctx *fs;
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
	uint64_t i_ino = ctx->i_ino;
	ctx->i_ino += ctx->nprocs;
	return (i_ino);
}

static void
free_meta_tree(entry_t *entry)
{
	if (S_ISDIR(entry->mode)) {
		entry_t *n;
		while (1) {
			n = RB_MIN(entrytree, &entry->entries);
			if (n == NULL) {
				break;
			}
			free_meta_tree(n);
			RB_REMOVE(entrytree, &entry->entries, n);
			if (n->ref_count == 0) {
				free(n->name);
				free(n);
			} else {
				free(n->name);
				n->name = NULL;
			}
		}
	}
}

static inline entry_t *
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
		e = RB_FIND(entrytree, &e->entries, &(entry_t){.name = name});
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

static inline entry_t *
get_dir_entry(const char *path, struct worker_ctx *ctx)
{
	entry_t *e = &ctx->root;
	if (strcmp(path, "") == 0) {
		return (e);
	}
	char *prev = (char *)path;
	char *p = prev;
	int path_len = strlen(path) + 1;
	char name[128];
	while ((p = strchr(p, '/')) != NULL) {
		memcpy(name, prev, p - prev);
		name[p - prev] = '\0';
		prev = ++p;
		e = RB_FIND(entrytree, &e->entries, &(entry_t){.name = name});
		if (e == NULL) {
			log_error("get_dir() path=%s does not exist", path);
			errno = ENOENT;
			return (NULL);
		}
		if (!S_ISDIR(e->mode)) {
			log_error("get_dir() path=%s is not a directory", path);
			errno = ENOTDIR;
			return (NULL);
		}
	}
	memcpy(name, prev, path_len - (prev - path));
	name[path_len - (prev - path)] = '\0';
	e = RB_FIND(entrytree, &e->entries, &(entry_t){.name = name});
	if (e == NULL) {
		log_error("get_dir() path=%s does not exist", path);
		errno = ENOENT;
		return (NULL);
	}
	if (!S_ISDIR(e->mode)) {
		log_error("get_dir() path=%s is not a directory", path);
		errno = ENOTDIR;
		return (NULL);
	}
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
	char *path = (char *)data;
	mode_t mode = *(mode_t *)UCS_PTR_BYTE_OFFSET(data, strlen(path) + 1);

	log_debug("fs_rpc_mkdir_recv() called path=%s", path);

	iov_req_t *user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 1;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);

	char dirname[128];
	entry_t *parent = get_parent_and_filename(dirname, path, &ctx);

	if (parent == NULL) {
		log_debug("fs_rpc_mkdir_recv() parent path=%s does not exist",
			  path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		entry_t *newent = malloc(sizeof(entry_t));
		newent->name = strdup(dirname);
		entry_t *ent = RB_INSERT(entrytree, &parent->entries, newent);
		if (ent != NULL) {
			log_debug("fs_rpc_mkdir_recv() path=%s already exists",
				  path);
			free(newent->name);
			free(newent);
			*(int *)(user_data->iov[0].buffer) = FINCH_EEXIST;
		} else {
			log_debug("fs_rpc_mkdir_recv() create path=%s", path);
			newent->mode = mode;
			newent->chunk_size = 0;
			newent->i_ino = alloc_ino(&ctx);
			newent->ref_count = 0;
			timespec_get(&newent->mtime, TIME_UTC);
			timespec_get(&newent->ctime, TIME_UTC);
			newent->entries.rbh_root = NULL;
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
		}
	}

	ucs_status_t status;
	status = post_iov_req(param->reply_ep, RPC_RET_REP, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_inode_create_recv(void *arg, const void *header, size_t header_length,
			 void *data, size_t length,
			 const ucp_am_recv_param_t *param)
{
	char *path;
	mode_t mode;
	size_t chunk_size;
	uint64_t i_ino;
	size_t size;
	char *p = (char *)data;
	path = (char *)p;
	p += strlen(path) + 1;
	mode = *(mode_t *)p;
	p += sizeof(mode);
	chunk_size = *(size_t *)p;
	p += sizeof(chunk_size);
	i_ino = *(uint64_t *)p;
	p += sizeof(i_ino);
	size = *(size_t *)p;

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
	entry_t *parent = get_parent_and_filename(filename, path, &ctx);
	if (parent == NULL) {
		log_debug("fs_rpc_inode_create_recv() path=%s does not exist",
			  path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		entry_t *ent = NULL;
		entry_t *newent = malloc(sizeof(entry_t));
		newent->name = strdup(filename);
		ent = RB_INSERT(entrytree, &parent->entries, newent);

		if (ent != NULL) {
			if (i_ino > 0) {
				RB_REMOVE(entrytree, &parent->entries, ent);
				free(ent->name);
				if (ent->ref_count == 0) {
					free(ent);
				} else {
					ent->name = NULL;
				}
				newent->i_ino = i_ino;
				newent->mode = mode;
				newent->chunk_size = chunk_size;
				newent->size = size;
				timespec_get(&newent->mtime, TIME_UTC);
				timespec_get(&newent->ctime, TIME_UTC);
				RB_INSERT(entrytree, &parent->entries, newent);
				*(uint64_t *)(user_data->iov[1].buffer) =
				    newent->i_ino;
				*(void **)user_data->iov[2].buffer = newent;
			} else {
				free(newent->name);
				free(newent);
				ent->ref_count++;
				*(uint64_t *)(user_data->iov[1].buffer) =
				    ent->i_ino;
				*(void **)(user_data->iov[2].buffer) = ent;
			}
		} else {
			if (i_ino > 0) {
				newent->i_ino = i_ino;
				newent->size = size;
			} else {
				newent->i_ino = alloc_ino(&ctx);
				newent->size = 0;
			}
			log_debug("fs_rpc_inode_create_recv() create path=%s "
				  "inode=%lu",
				  path, newent->i_ino);
			newent->mode = mode;
			newent->chunk_size = chunk_size;
			timespec_get(&newent->mtime, TIME_UTC);
			timespec_get(&newent->ctime, TIME_UTC);
			newent->ref_count = 1;
			*(uint64_t *)(user_data->iov[1].buffer) = newent->i_ino;
			*(void **)(user_data->iov[2].buffer) = newent;
		}
		*(int *)(user_data->iov[0].buffer) = FINCH_OK;
	}

	ucs_status_t status;
	status = post_iov_req(param->reply_ep, RPC_INODE_REP, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_inode_unlink_recv(void *arg, const void *header, size_t header_length,
			 void *data, size_t length,
			 const ucp_am_recv_param_t *param)
{
	char *path = (char *)data;

	log_debug("fs_rpc_inode_unlink_recv() called path=%s", path);

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * 2);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 2;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);
	user_data->iov[1].buffer = malloc(sizeof(uint64_t));
	user_data->iov[1].length = sizeof(uint64_t);

	char name[128];
	entry_t *parent = get_parent_and_filename(name, path, &ctx);
	if (parent == NULL) {
		log_debug("fs_rpc_inode_unlink_recv() path=%s does not exist",
			  path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		entry_t key = {
		    .name = name,
		};
		entry_t *ent = RB_FIND(entrytree, &parent->entries, &key);
		if (ent == NULL) {
			log_debug(
			    "fs_rpc_inode_unlink_recv() path=%s does not exist",
			    path);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
		} else {
			*(uint64_t *)user_data->iov[1].buffer = ent->i_ino;
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
			free_meta_tree(ent);
			RB_REMOVE(entrytree, &parent->entries, ent);
			if (ent->ref_count == 0) {
				free(ent->name);
				free(ent);
			} else {
				free(ent->name);
				ent->name = NULL;
			}
		}
	}

	ucs_status_t status;
	status = post_iov_req(param->reply_ep, RPC_INODE_REP, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_inode_stat_recv(void *arg, const void *header, size_t header_length,
		       void *data, size_t length,
		       const ucp_am_recv_param_t *param)
{
	uint8_t open;
	char *path;
	char *p = (char *)data;
	open = *(uint8_t *)p;
	p += sizeof(open);
	path = (char *)p;

	log_debug("fs_rpc_inode_stat_recv() called path=%s", path);

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
	char name[128];
	entry_t *parent = get_parent_and_filename(name, path, &ctx);
	if (parent == NULL) {
		log_debug("fs_rpc_inode_stat_recv() path=%s does not exist",
			  path);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else {
		entry_t key = {
		    .name = name,
		};
		entry_t *ent = RB_FIND(entrytree, &parent->entries, &key);
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
			st->size = ent->size;
			memcpy(&st->eid, &ent, sizeof(ent));
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
			if (open) {
				ent->ref_count++;
			}
		}
	}

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
	entry_t *eid;
	size_t ssize;
	char *p = (char *)data;
	eid = *(entry_t **)p;
	p += sizeof(eid);
	ssize = *(size_t *)p;

	log_debug("fs_rpc_inode_stat_update_recv() called eid=%p size=%zu", eid,
		  ssize >> 1);

	if (ssize & 1) {
		eid->ref_count--;
		if (eid->ref_count == 0 && eid->name == NULL) {
			free(eid);
		} else {
			if (eid->size < (ssize >> 1)) {
				eid->size = ssize >> 1;
			}
			timespec_get(&eid->mtime, TIME_UTC);
		}
	} else {
		if (eid->size < (ssize >> 1)) {
			eid->size = ssize >> 1;
		}
		timespec_get(&eid->mtime, TIME_UTC);

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
		*(size_t *)(user_data->iov[1].buffer) = eid->size;

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
fs_rpc_readdir_recv(void *arg, const void *header, size_t header_length,
		    void *data, size_t length, const ucp_am_recv_param_t *param)
{
	char *path = (char *)data;
	readdir_header_t *hdr = (readdir_header_t *)header;

	log_debug("fs_rpc_readdir_recv() called path=%s count=%d", path,
		  hdr->entry_count);

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * hdr->entry_count);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	readdir_header_t *rhdr = (readdir_header_t *)user_data->header;
	rhdr->ret = FINCH_OK;
	rhdr->entry_count = 0;
	user_data->n = 0;

	entry_t *dir = get_dir_entry(path, &ctx);
	ucs_status_t status;
	if (dir == NULL) {
		if (errno == ENOENT) {
			log_debug(
			    "fs_rpc_readdir_recv() path=%s does not exist",
			    path);
			rhdr->ret = FINCH_ENOENT;
		} else {
			log_debug(
			    "fs_rpc_readdir_recv() path=%s is not a directory",
			    path);
			rhdr->ret = FINCH_ENOTDIR;
		}
		user_data->iov[user_data->n].buffer = malloc(1);
		user_data->iov[user_data->n].length = 1;
		user_data->n++;
		status = post_iov_req(param->reply_ep, RPC_READDIR_REP,
				      user_data, header_length);
		return (status);
	}
	entry_t *child;
	RB_FOREACH(child, entrytree, &dir->entries)
	{
		if (rhdr->fileonly && S_ISDIR(child->mode)) {
			continue;
		}
		readdir_entry_t *ent =
		    malloc(sizeof(readdir_entry_t) + strlen(child->name) + 1);
		ent->chunk_size = child->chunk_size;
		ent->i_ino = child->i_ino;
		ent->mode = child->mode;
		ent->mtime = child->mtime;
		ent->ctime = child->ctime;
		ent->size = child->size;
		ent->path_len = strlen(child->name) + 1;
		strcpy(ent->path, child->name);
		user_data->iov[user_data->n].buffer = ent;
		user_data->iov[user_data->n].length =
		    sizeof(readdir_entry_t) + ent->path_len;
		user_data->n++;
		rhdr->entry_count++;
		if (user_data->n == hdr->entry_count) {
			rhdr->ret = FINCH_INPROGRESS;
			log_debug("fs_rpc_readdir_recv() sending count=%d",
				  rhdr->entry_count);
			status = post_iov_req(param->reply_ep, RPC_READDIR_REP,
					      user_data, header_length);
			if (status != UCS_OK) {
				return (status);
			}
			user_data =
			    malloc(sizeof(iov_req_t) +
				   sizeof(ucp_dt_iov_t) * hdr->entry_count);
			user_data->header = malloc(header_length);
			memcpy(user_data->header, header, header_length);
			rhdr = (readdir_header_t *)user_data->header;
			rhdr->ret = FINCH_OK;
			rhdr->entry_count = 0;
			user_data->n = 0;
		}
	}
	if (user_data->n == 0) {
		user_data->iov[user_data->n].buffer = malloc(1);
		user_data->iov[user_data->n].length = 1;
		user_data->n++;
	}
	log_debug("fs_rpc_readdir_recv() sending count=%d", rhdr->entry_count);
	status = post_iov_req(param->reply_ep, RPC_READDIR_REP, user_data,
			      header_length);
	return (status);
}

ucs_status_t
fs_rpc_dir_move_recv(void *arg, const void *header, size_t header_length,
		     void *data, size_t length,
		     const ucp_am_recv_param_t *param)
{
	char *opath = (char *)data;
	char *npath = (char *)UCS_PTR_BYTE_OFFSET(data, strlen(opath) + 1);

	log_debug("fs_rpc_dir_move_recv() called opath=%s npath=%s", opath,
		  npath);

	iov_req_t *user_data = malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t));
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	user_data->n = 1;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);

	char odirname[128];
	char ndirname[128];
	entry_t *oparent = get_parent_and_filename(odirname, opath, &ctx);
	entry_t *nparent = get_parent_and_filename(ndirname, npath, &ctx);

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
		entry_t *ent = RB_FIND(entrytree, &oparent->entries, &key);
		if (ent == NULL) {
			log_debug(
			    "fs_rpc_dir_move_recv() opath=%s does not exist",
			    opath);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
		} else if (!S_ISDIR(ent->mode)) {
			log_debug("fs_rpc_dir_move_recv() opath=%s is not a "
				  "directory",
				  opath);
			*(int *)(user_data->iov[0].buffer) = FINCH_ENOTDIR;
		} else {
			entry_t *old;
			RB_REMOVE(entrytree, &oparent->entries, ent);
			free(ent->name);
			ent->name = strdup(ndirname);
			old = RB_INSERT(entrytree, &nparent->entries, ent);
			if (old != NULL) {
				RB_REMOVE(entrytree, &nparent->entries, old);
				free(old->name);
				old->name = NULL;
				if (old->ref_count == 0) {
					free_meta_tree(old);
					free(old);
				}
				RB_INSERT(entrytree, &nparent->entries, ent);
			}
			*(int *)(user_data->iov[0].buffer) = FINCH_OK;
		}
	}

	ucs_status_t status;
	status = post_iov_req(param->reply_ep, RPC_RET_REP, user_data,
			      header_length);
	return (status);
}

typedef struct {
	find_condition_t *cond;
	int recursive;
	int return_path;
	int skip_dir;
	size_t entry_count;
	find_header_t *header;
	size_t header_length;
	ucp_ep_h reply_ep;
} find_param_t;

static void
fs_rpc_find_internal(iov_req_t **user_data, entry_t *dir, find_param_t *param)
{
	log_debug("fs_rpc_find_internal() called dir->name=%s", dir->name);
	entry_t *child;
	ucs_status_t status;

	RB_FOREACH(child, entrytree, &dir->entries)
	{
		if (param->recursive && S_ISDIR(child->mode)) {
			fs_rpc_find_internal(user_data, child, param);
		}
		fs_stat_t st = {
		    .chunk_size = child->chunk_size,
		    .i_ino = child->i_ino,
		    .mode = child->mode,
		    .mtime = child->mtime,
		    .ctime = child->ctime,
		    .size = child->size,
		};
		find_header_t *rhdr = (find_header_t *)(*user_data)->header;
		if (param->skip_dir && S_ISDIR(child->mode)) {
			continue;
		}
		rhdr->total_nentries++;
		if (!eval_condition(param->cond, child->name, &st)) {
			continue;
		}
		rhdr->match_nentries++;
		if (param->return_path) {
			find_entry_t *ent = malloc(sizeof(find_entry_t) +
						   strlen(child->name) + 1);
			ent->path_len = strlen(child->name) + 1;
			strcpy(ent->path, child->name);
			(*user_data)->iov[(*user_data)->n].buffer = ent;
			(*user_data)->iov[(*user_data)->n].length =
			    sizeof(find_entry_t) + ent->path_len;
			(*user_data)->n++;
			rhdr->entry_count++;
			if ((*user_data)->n == param->entry_count) {
				rhdr->ret = FINCH_INPROGRESS;
				log_debug("fs_rpc_find_internal() sending "
					  "count=%d",
					  rhdr->entry_count);
				status = post_iov_req(param->reply_ep,
						      RPC_FIND_REP, *user_data,
						      param->header_length);
				if (status != UCS_OK) {
					log_error("post_iov_req() failed");
				}
				*user_data = malloc(sizeof(iov_req_t) +
						    sizeof(ucp_dt_iov_t) *
							param->entry_count);
				(*user_data)->header =
				    malloc(param->header_length);
				memcpy((*user_data)->header, param->header,
				       param->header_length);
				rhdr = (find_header_t *)(*user_data)->header;
				rhdr->ret = FINCH_OK;
				rhdr->entry_count = 0;
				rhdr->total_nentries = 0;
				rhdr->match_nentries = 0;
				(*user_data)->n = 0;
			}
		}
	}
}

ucs_status_t
fs_rpc_find_recv(void *arg, const void *header, size_t header_length,
		 void *data, size_t length, const ucp_am_recv_param_t *param)
{
	char *path;
	char *query;
	uint8_t flag;
	char *p = (char *)data;
	path = (char *)p;
	p += strlen(path) + 1;
	query = (char *)p;
	p += strlen(query) + 1;
	flag = *(uint8_t *)p;
	find_header_t *hdr = (find_header_t *)header;

	log_debug("fs_rpc_find_recv() called path=%s query=%s recursive=%d "
		  "return_path=%d",
		  path, query, flag & FINCHFS_FIND_FLAG_RECURSIVE,
		  flag & FINCHFS_FIND_FLAG_RETURN_PATH);

	iov_req_t *user_data =
	    malloc(sizeof(iov_req_t) + sizeof(ucp_dt_iov_t) * hdr->entry_count);
	user_data->header = malloc(header_length);
	memcpy(user_data->header, header, header_length);
	find_header_t *rhdr = (find_header_t *)user_data->header;
	rhdr->ret = FINCH_OK;
	rhdr->entry_count = 0;
	rhdr->total_nentries = 0;
	rhdr->match_nentries = 0;
	user_data->n = 0;

	entry_t *dir = get_dir_entry(path, &ctx);
	ucs_status_t status;
	if (dir == NULL) {
		if (errno == ENOENT) {
			log_debug("fs_rpc_find_recv() path=%s does not exist",
				  path);
			rhdr->ret = FINCH_ENOENT;
		} else {
			log_debug("fs_rpc_find_recv() path=%s is not a "
				  "directory",
				  path);
			rhdr->ret = FINCH_ENOTDIR;
		}
		user_data->iov[user_data->n].buffer = malloc(1);
		user_data->iov[user_data->n].length = 1;
		user_data->n++;
		status = post_iov_req(param->reply_ep, RPC_FIND_REP, user_data,
				      header_length);
		return (status);
	}
	char *next;
	find_condition_t *cond = build_condition(query, &next, NULL, 0);
	if (cond == NULL) {
		log_error("fs_rpc_find_recv() failed to build condition");
		rhdr->ret = FINCH_EINVAL;
		user_data->iov[user_data->n].buffer = malloc(1);
		user_data->iov[user_data->n].length = 1;
		user_data->n++;
		status = post_iov_req(param->reply_ep, RPC_FIND_REP, user_data,
				      header_length);
		return (status);
	}
	find_param_t fparam = {
	    .cond = cond,
	    .recursive = flag & FINCHFS_FIND_FLAG_RECURSIVE,
	    .return_path = flag & FINCHFS_FIND_FLAG_RETURN_PATH,
	    .skip_dir = ctx.rank > 0,
	    .entry_count = hdr->entry_count,
	    .header = hdr,
	    .header_length = header_length,
	    .reply_ep = param->reply_ep,
	};
	fs_rpc_find_internal(&user_data, dir, &fparam);
	if (!fparam.skip_dir) {
		rhdr->total_nentries++;
		fs_stat_t st = {
		    .chunk_size = dir->chunk_size,
		    .i_ino = dir->i_ino,
		    .mode = dir->mode,
		    .mtime = dir->mtime,
		    .ctime = dir->ctime,
		    .size = dir->size,
		};
		rhdr = (find_header_t *)user_data->header;
		if (eval_condition(fparam.cond, dir->name, &st)) {
			rhdr->match_nentries++;
			if (fparam.return_path) {
				find_entry_t *ent =
				    malloc(sizeof(find_entry_t) +
					   strlen(dir->name) + 1);
				ent->path_len = strlen(dir->name) + 1;
				strcpy(ent->path, dir->name);
				user_data->iov[user_data->n].buffer = ent;
				user_data->iov[user_data->n].length =
				    sizeof(find_entry_t) + ent->path_len;
				user_data->n++;
				rhdr->entry_count++;
			}
		}
	}
	free_condition(cond);
	if (user_data->n == 0) {
		user_data->iov[user_data->n].buffer = malloc(1);
		user_data->iov[user_data->n].length = 1;
		user_data->n++;
	}
	log_debug("fs_rpc_find_recv() sending count=%d",
		  ((find_header_t *)user_data->header)->entry_count);
	status = post_iov_req(param->reply_ep, RPC_FIND_REP, user_data,
			      header_length);
	return (status);
}

int
fs_server_init(char *db_dir, size_t db_size, int rank, int nprocs, int lrank,
	       int lnprocs, int *shutdown)
{
	ctx.rank = rank;
	ctx.nprocs = nprocs;
	ctx.lrank = lrank;
	ctx.lnprocs = lnprocs;
	ctx.i_ino = rank + nprocs;
	ctx.shutdown = shutdown;

	ctx.root.name = "";
	ctx.root.mode = S_IFDIR | S_IRWXU;
	ctx.root.chunk_size = 0;
	ctx.root.i_ino = 0;
	timespec_get(&ctx.root.mtime, TIME_UTC);
	timespec_get(&ctx.root.ctime, TIME_UTC);
	ctx.root.entries.rbh_root = NULL;

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
	ucp_am_handler_param_t inode_unlink_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_UNLINK_REQ,
	    .cb = fs_rpc_inode_unlink_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &inode_unlink_param)) != UCS_OK) {
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
	ucp_am_handler_param_t dir_move_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_DIR_MOVE_REQ,
	    .cb = fs_rpc_dir_move_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &dir_move_param)) != UCS_OK) {
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
	ucp_am_handler_param_t readdir_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_READDIR_REQ,
	    .cb = fs_rpc_readdir_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 ctx.ucp_worker, &readdir_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(readdir) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t find_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_FIND_REQ,
	    .cb = fs_rpc_find_recv,
	};
	if ((status = ucp_worker_set_am_recv_handler(ctx.ucp_worker,
						     &find_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(find) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}

	ctx.fs = fs_inode_init(db_dir, db_size, lrank);
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

void
fs_server_release_address(void *addr)
{
	ucp_worker_release_address(ctx.ucp_worker, addr);
}

int
fs_server_term(int trank)
{
	free_meta_tree(&ctx.root);
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
