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
#include "fs_rpc.h"
#include "hashmap.h"
#include "log.h"

struct worker_ctx {
	struct hashmap *dirtable;
} all_ctx;

typedef struct {
	char *dirname;
	mode_t mode;
	struct hashmap *entries;
} dirtable_t;

typedef struct {
	char *entryname;
} direntry_t;

static int
dirtable_compare(const void *a, const void *b, void *udata)
{
	const dirtable_t *da = a;
	const dirtable_t *db = b;
	return strcmp(da->dirname, db->dirname);
}

static uint64_t
dirtable_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
	const dirtable_t *d = item;
	return hashmap_sip(d->dirname, strlen(d->dirname), seed0, seed1);
}

static int
direntry_compare(const void *a, const void *b, void *udata)
{
	const direntry_t *da = a;
	const direntry_t *db = b;
	return strcmp(da->entryname, db->entryname);
}

static uint64_t
direntry_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
	const direntry_t *d = item;
	return hashmap_sip(d->entryname, strlen(d->entryname), seed0, seed1);
}

static void
fs_rpc_mkdir_recv_reply_cb(void *request, ucs_status_t status, void *user_data)
{
	log_debug("fs_rpc_mkdir_recv_reply_cb() called status=%s",
		  ucs_status_string(status));
	ucp_request_free(request);
	iov_req_t *iov_req = user_data;
	free(iov_req->header);
	free(iov_req->iov[0].buffer);
	free(iov_req);
}

static char *
fs_dirname(const char *path)
{
	size_t p = strlen(path) - 1;
	char *r;

	while (p > 0 && path[p] != '/')
		--p;

	r = malloc(p + 1);
	if (r == NULL) {
		log_error("fs_dirname: no memory");
		return (NULL);
	}
	strncpy(r, path, p);
	r[p] = '\0';
	log_debug("fs_dirname: path %s dirname %s", path, r);
	return (r);
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
	user_data->header = malloc(sizeof(void *));
	memcpy(user_data->header, header, sizeof(void *));
	user_data->n = 1;
	user_data->iov[0].buffer = malloc(sizeof(int));
	user_data->iov[0].length = sizeof(int);

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_CALLBACK |
		UCP_OP_ATTR_FIELD_FLAGS | UCP_OP_ATTR_FIELD_USER_DATA,
	    .cb =
		{
		    .send = fs_rpc_mkdir_recv_reply_cb,
		},
	    .flags = UCP_AM_SEND_FLAG_EAGER,
	    .datatype = UCP_DATATYPE_IOV,
	    .user_data = user_data,
	};

	char *pardir = fs_dirname(path);

	dirtable_t *dirt =
	    hashmap_get(ctx->dirtable, &(dirtable_t){.dirname = path});
	dirtable_t *pardirt =
	    hashmap_get(ctx->dirtable, &(dirtable_t){.dirname = pardir});
	if (pardirt == NULL) {
		log_debug("fs_rpc_mkdir_recv() parent path=%s does not exist",
			  pardir);
		*(int *)(user_data->iov[0].buffer) = FINCH_ENOENT;
	} else if (dirt != NULL) {
		log_debug("fs_rpc_mkdir_recv() path=%s already exists", path);
		*(int *)(user_data->iov[0].buffer) = FINCH_EEXIST;
	} else {
		log_debug("fs_rpc_mkdir_recv() create path=%s", path);
		struct hashmap *entries =
		    hashmap_new(sizeof(direntry_t), 0, 0, 0, direntry_hash,
				direntry_compare, NULL, NULL);
		dirtable_t dirt = {
		    .dirname = strdup(path), .mode = mode, .entries = entries};
		hashmap_set(ctx->dirtable, &dirt);
		*(int *)(user_data->iov[0].buffer) = FINCH_OK;
	}
	ucs_status_ptr_t req = ucp_am_send_nbx(
	    param->reply_ep, RPC_MKDIR_REP, user_data->header, sizeof(void *),
	    user_data->iov, user_data->n, &rparam);
	if (req == NULL) {
		free(user_data->header);
		free(user_data->iov[0].buffer);
		free(user_data);
	} else if (UCS_PTR_IS_ERR(req)) {
		log_error("ucp_am_send_nbx() failed: %s",
			  ucs_status_string(UCS_PTR_STATUS(req)));
		free(user_data->header);
		free(user_data->iov[0].buffer);
		free(user_data);
		return (UCS_PTR_STATUS(req));
	}
	return (UCS_OK);
}

int
fs_server_init(ucp_worker_h worker)
{
	all_ctx.dirtable =
	    hashmap_new(sizeof(dirtable_t), 0, 0, 0, dirtable_hash,
			dirtable_compare, NULL, NULL);
	struct hashmap *entries =
	    hashmap_new(sizeof(direntry_t), 0, 0, 0, direntry_hash,
			direntry_compare, NULL, NULL);
	dirtable_t dirt = {
	    .dirname = "", .mode = S_IFDIR | S_IRWXU, .entries = entries};
	hashmap_set(all_ctx.dirtable, &dirt);

	ucs_status_t status;
	ucp_am_handler_param_t mkdir_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_MKDIR_REQ,
	    .cb = fs_rpc_mkdir_recv,
	    .arg = &all_ctx,
	};
	if ((status = ucp_worker_set_am_recv_handler(worker, &mkdir_param)) !=
	    UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(mkdir) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	return (0);
}

int
fs_server_term()
{
	size_t iter = 0;
	void *item;
	while (hashmap_iter(all_ctx.dirtable, &iter, &item)) {
		const dirtable_t *table = item;
		hashmap_free(table->entries);
	}
	hashmap_free(all_ctx.dirtable);
	return (0);
}
