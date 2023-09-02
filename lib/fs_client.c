#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ucp/api/ucp.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "finchfs.h"
#include "config.h"
#include "log.h"
#include "fs_types.h"
#include "fs_rpc.h"

static struct env {
	ucp_context_h ucp_context;
	ucp_worker_h ucp_worker;
	ucp_ep_h *ucp_eps;
	int nvprocs;
} env;

ucs_status_t
fs_rpc_ret_reply(void *arg, const void *header, size_t header_length,
		 void *data, size_t length, const ucp_am_recv_param_t *param)
{
	void *ret = *(void **)header;
	memcpy(ret, data, sizeof(int));
	return (UCS_OK);
}

typedef struct {
	int ret;
	uint32_t i_ino;
} inode_create_handle_t;

ucs_status_t
fs_rpc_inode_reply(void *arg, const void *header, size_t header_length,
		   void *data, size_t length, const ucp_am_recv_param_t *param)
{
	inode_create_handle_t *handle = *(inode_create_handle_t **)header;
	size_t offset = 0;
	handle->ret = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(int);
	handle->i_ino = *(uint32_t *)UCS_PTR_BYTE_OFFSET(data, offset);
	return (UCS_OK);
}

typedef struct {
	int ret;
	fs_stat_t st;
} inode_stat_handle_t;

ucs_status_t
fs_rpc_inode_stat_reply(void *arg, const void *header, size_t header_length,
			void *data, size_t length,
			const ucp_am_recv_param_t *param)
{
	inode_stat_handle_t *handle = *(inode_stat_handle_t **)header;
	size_t offset = 0;
	handle->ret = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(int);
	handle->st = *(fs_stat_t *)UCS_PTR_BYTE_OFFSET(data, offset);
	return (UCS_OK);
}

typedef struct {
	int ret;
	size_t size;
} inode_chunk_stat_handle_t;

ucs_status_t
fs_rpc_inode_chunk_stat_reply(void *arg, const void *header,
			      size_t header_length, void *data, size_t length,
			      const ucp_am_recv_param_t *param)
{
	inode_chunk_stat_handle_t *handle =
	    *(inode_chunk_stat_handle_t **)header;
	size_t offset = 0;
	handle->ret = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(int);
	handle->size = *(size_t *)UCS_PTR_BYTE_OFFSET(data, offset);
	return (UCS_OK);
}

typedef struct {
	int ret;
	ssize_t ss;
	ucs_status_ptr_t req;
	inode_write_header_t header;
} inode_write_handle_t;

ucs_status_t
fs_rpc_inode_write_reply(void *arg, const void *header, size_t header_length,
			 void *data, size_t length,
			 const ucp_am_recv_param_t *param)
{
	inode_write_handle_t *handle = *(inode_write_handle_t **)header;
	size_t offset = 0;
	handle->ret = *(int *)UCS_PTR_BYTE_OFFSET(data, offset);
	offset += sizeof(int);
	handle->ss = *(ssize_t *)UCS_PTR_BYTE_OFFSET(data, offset);
	return (UCS_OK);
}

typedef struct {
	int ret;
	ssize_t ss;
	ucs_status_ptr_t req;
	inode_read_header_t header;
	void *buf;
} inode_read_handle_t;

static void
fs_rpc_inode_read_reply_rndv(void *request, ucs_status_t status, size_t length,
			     void *user_data)
{
	log_debug("fs_rpc_inode_read_reply_rndv: called header=%p", user_data);
	inode_read_header_t *header = (inode_read_header_t *)user_data;
	inode_read_handle_t *handle = header->handle;
	ucp_request_free(request);
	handle->ret = header->ret;
	if (header->ret == FINCH_OK) {
		handle->ss = header->size;
	} else {
		handle->ss = -1;
	}
	free(header);
}

ucs_status_t
fs_rpc_inode_read_reply(void *arg, const void *header, size_t header_length,
			void *data, size_t length,
			const ucp_am_recv_param_t *param)
{
	inode_read_header_t *hdr = (inode_read_header_t *)header;
	inode_read_handle_t *handle = hdr->handle;
	log_debug("fs_rpc_inode_read_reply: handle=%p", handle);

	if (param->recv_attr & UCP_AM_RECV_ATTR_FLAG_RNDV) {
		inode_read_header_t *user_data =
		    malloc(sizeof(inode_read_header_t));
		log_debug("fs_rpc_inode_read_reply: rndv");
		memcpy(user_data, header, header_length);
		ucp_request_param_t rparam = {
		    .op_attr_mask = UCP_OP_ATTR_FIELD_DATATYPE |
				    UCP_OP_ATTR_FIELD_CALLBACK |
				    UCP_OP_ATTR_FIELD_USER_DATA,
		    .cb =
			{
			    .recv_am = fs_rpc_inode_read_reply_rndv,
			},
		    .datatype = ucp_dt_make_contig(sizeof(char)),
		    .user_data = user_data,
		};
		ucs_status_ptr_t req =
		    ucp_am_recv_data_nbx(env.ucp_worker, data, handle->buf,
					 user_data->size, &rparam);
		if (req == NULL) {
			handle->ret = hdr->ret;
			if (hdr->ret == FINCH_OK) {
				handle->ss = hdr->size;
			} else {
				handle->ss = -1;
			}
			free(user_data);
		} else if (UCS_PTR_IS_ERR(req)) {
			log_error("ucp_am_recv_data_nbx() failed: %s",
				  ucs_status_string(UCS_PTR_STATUS(req)));
			handle->ret = FINCH_EIO;
			handle->ss = -1;
			free(user_data);
			ucs_status_t status = UCS_PTR_STATUS(req);
			ucp_request_free(req);
			return (status);
		}
	} else {
		log_debug("fs_rpc_inode_read_reply: eager");
		handle->ret = hdr->ret;
		if (hdr->ret == FINCH_OK) {
			handle->ss = hdr->size;
			memcpy(handle->buf, data, hdr->size);
		} else {
			handle->ss = -1;
		}
	}
	return (UCS_OK);
}

typedef struct {
	int ret;
	void *arg;
	void (*filler)(void *, const char *, const struct stat *);
	readdir_header_t header;
} readdir_handle_t;

ucs_status_t
fs_rpc_readdir_reply(void *arg, const void *header, size_t header_length,
		     void *data, size_t length,
		     const ucp_am_recv_param_t *param)
{
	readdir_header_t *hdr = (readdir_header_t *)header;
	readdir_handle_t *handle = hdr->handle;
	log_debug("fs_rpc_readdir_reply: entry_count=%d", hdr->entry_count);
	size_t offset = 0;
	if (hdr->ret == FINCH_OK || hdr->ret == FINCH_INPROGRESS) {
		for (int i = 0; i < hdr->entry_count; i++) {
			readdir_entry_t *ent =
			    (readdir_entry_t *)UCS_PTR_BYTE_OFFSET(data,
								   offset);
			offset += sizeof(readdir_entry_t) + ent->path_len;
			struct stat st;
			st.st_mode = ent->mode;
			st.st_uid = getuid();
			st.st_gid = getgid();
			st.st_size = -1;
			st.st_mtim = ent->mtime;
			st.st_ctim = ent->ctime;
			st.st_nlink = 1;
			st.st_ino = ent->i_ino;
			st.st_blksize = ent->chunk_size;
			st.st_blocks = 0;

			handle->filler(handle->arg, ent->path, &st);
		}
	}
	if (hdr->ret == FINCH_OK) {
		log_debug("fs_rpc_readdir_reply: finished");
	} else if (hdr->ret == FINCH_INPROGRESS) {
		log_debug("fs_rpc_readdir_reply: inprogress");
	} else {
		log_debug("fs_rpc_readdir_reply: error");
	}
	handle->ret = hdr->ret;
	return (UCS_OK);
}

static void
ep_err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
{
	log_error("error handling callback was invoked with status %s",
		  ucs_status_string(status));
}

int
fs_client_init(char *addrfile)
{
	size_t addr_len;
	int fd;
	uint8_t *addr_allprocs;
	ucs_status_t status;

	if (addrfile == NULL) {
		addrfile = DUMP_ADDR_FILE;
	}
	fd = open(addrfile, O_RDONLY);
	if (fd < 0) {
		log_error("open() failed: %s", strerror(errno));
		return (-1);
	}
	if (read(fd, &addr_len, sizeof(addr_len)) != sizeof(addr_len)) {
		log_error("read(addr_len) failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}
	if (read(fd, &env.nvprocs, sizeof(env.nvprocs)) !=
	    sizeof(env.nvprocs)) {
		log_error("read(nvprocs) failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}
	log_debug("addr_len: %zu, nvprocs: %d", addr_len, env.nvprocs);
	addr_allprocs = malloc(addr_len * env.nvprocs);
	if (read(fd, addr_allprocs, addr_len * env.nvprocs) !=
	    addr_len * env.nvprocs) {
		log_error("read(addr_allprocs) failed: %s", strerror(errno));
		free(addr_allprocs);
		close(fd);
		return (-1);
	}
	close(fd);

	ucp_params_t ucp_params = {
	    .field_mask = UCP_PARAM_FIELD_FEATURES,
	    .features = UCP_FEATURE_RMA | UCP_FEATURE_AM,
	};
	if ((status = ucp_init(&ucp_params, NULL, &env.ucp_context)) !=
	    UCS_OK) {
		log_error("ucp_init() failed: %s", ucs_status_string(status));
		return (-1);
	}

	ucp_worker_params_t ucp_worker_params = {
	    .field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE,
	    .thread_mode = UCS_THREAD_MODE_SINGLE};
	if ((status = ucp_worker_create(env.ucp_context, &ucp_worker_params,
					&env.ucp_worker)) != UCS_OK) {
		log_error("ucp_worker_create() failed: %s",
			  ucs_status_string(status));
		return (-1);
	}

	env.ucp_eps = malloc(sizeof(ucp_ep_h) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
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
		    .address = (ucp_address_t *)(addr_allprocs + addr_len * i),
		};
		if ((status = ucp_ep_create(env.ucp_worker, &ucp_ep_params,
					    &env.ucp_eps[i])) != UCS_OK) {
			log_error("ucp_ep_create() failed: %s",
				  ucs_status_string(status));
			return (-1);
		}
		if (get_log_priority() == LOG_DEBUG) {
			log_debug("ucp_ep[%d]:", i);
			ucp_ep_print_info(env.ucp_eps[i], stderr);
		}
	}

	ucp_am_handler_param_t ret_reply_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_RET_REP,
	    .cb = fs_rpc_ret_reply,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 env.ucp_worker, &ret_reply_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(ret) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_reply_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_REP,
	    .cb = fs_rpc_inode_reply,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 env.ucp_worker, &inode_reply_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(inode) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_stat_reply_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_STAT_REP,
	    .cb = fs_rpc_inode_stat_reply,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 env.ucp_worker, &inode_stat_reply_param)) != UCS_OK) {
		log_error(
		    "ucp_worker_set_am_recv_handler(inode stat) failed: %s",
		    ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_write_reply_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_WRITE_REP,
	    .cb = fs_rpc_inode_write_reply,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 env.ucp_worker, &inode_write_reply_param)) != UCS_OK) {
		log_error(
		    "ucp_worker_set_am_recv_handler(inode write) failed: %s",
		    ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_read_reply_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_READ_REP,
	    .cb = fs_rpc_inode_read_reply,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 env.ucp_worker, &inode_read_reply_param)) != UCS_OK) {
		log_error(
		    "ucp_worker_set_am_recv_handler(inode read) failed: %s",
		    ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_chunk_stat_reply_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_CHUNK_STAT_REP,
	    .cb = fs_rpc_inode_chunk_stat_reply,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 env.ucp_worker, &inode_chunk_stat_reply_param)) != UCS_OK) {
		log_error(
		    "ucp_worker_set_am_recv_handler(chunk stat) failed: %s",
		    ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t readdir_reply_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_READDIR_REP,
	    .cb = fs_rpc_readdir_reply,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 env.ucp_worker, &readdir_reply_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(readdir) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	return (0);
}

static int
all_req_finish(ucs_status_ptr_t *reqs, int num)
{
	ucs_status_t status;
	for (int i = 0; i < num; i++) {
		if (reqs[i] == NULL) {
			continue;
		}
		status = ucp_request_check_status(reqs[i]);
		if (status == UCS_INPROGRESS) {
			return (0);
		}
	}
	return (1);
}

static int
all_ret_finish(int **rets, int num)
{
	for (int i = 0; i < num; i++) {
		if (*rets[i] == FINCH_INPROGRESS) {
			return (0);
		}
	}
	return (1);
}

int
fs_client_term(void)
{
	ucs_status_ptr_t *reqs = malloc(sizeof(ucs_status_ptr_t) * env.nvprocs);
	ucp_request_param_t params = {
	    .op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_EP_CLOSE_MODE_FORCE,
	};

	for (int i = 0; i < env.nvprocs; i++) {
		reqs[i] = ucp_ep_close_nbx(env.ucp_eps[i], &params);
	}

	while (!all_req_finish(reqs, env.nvprocs)) {
		ucp_worker_progress(env.ucp_worker);
	}

	int r = 0;
	for (int i = 0; i < env.nvprocs; i++) {
		if (reqs[i] == NULL) {
			continue;
		}
		if (UCS_PTR_IS_ERR(reqs[i])) {
			log_error("ucp_ep_close_nbx() failed: %s",
				  ucs_status_string(UCS_PTR_STATUS(reqs[i])));
			r = -1;
		}
		ucp_request_free(reqs[i]);
	}

	free(reqs);
	free(env.ucp_eps);
	ucp_worker_destroy(env.ucp_worker);
	ucp_cleanup(env.ucp_context);

	return (r);
}

static int
path_to_target_hash(const char *path, int div)
{
	long h = 0;
	int slash = -1;
	char *head = strdup(path);
	char *next;
	long n;
	for (int i = 0; head[i] != '\0'; i++) {
		if (head[i] == '/') {
			slash = i;
		}
	}
	for (char *p = head + slash + 1; *p != '\0'; p = next) {
		n = strtol(p, &next, 10);
		if (next == p) {
			h += *p;
			next++;
			continue;
		}
		h += n;
	}
	free(head);
	return (int)(h % div);
}

int
fs_rpc_mkdir(const char *path, mode_t mode)
{
	int path_len = strlen(path) + 1;
	ucp_dt_iov_t iov[3];
	iov[0].buffer = &path_len;
	iov[0].length = sizeof(path_len);
	iov[1].buffer = (void *)path;
	iov[1].length = path_len;
	iov[2].buffer = &mode;
	iov[2].length = sizeof(mode);

	int *ret = malloc(sizeof(int) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		ret[i] = FINCH_INPROGRESS;
	}
	int **rets_addr = malloc(sizeof(int *) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		rets_addr[i] = &ret[i];
	}

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t *reqs = malloc(sizeof(ucs_status_ptr_t) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		reqs[i] = ucp_am_send_nbx(env.ucp_eps[i], RPC_MKDIR_REQ,
					  &rets_addr[i], sizeof(void *), iov, 3,
					  &rparam);
	}

	ucs_status_t status;
	while (!all_req_finish(reqs, env.nvprocs)) {
		ucp_worker_progress(env.ucp_worker);
	}
	int nokreq = 0;
	int *okidx = malloc(sizeof(int) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		if (reqs[i] == NULL) {
			okidx[nokreq++] = i;
			continue;
		}
		status = ucp_request_check_status(reqs[i]);
		if (status != UCS_OK) {
			log_error(
			    "fs_rpc_mkdir: ucp_am_send_nbx() failed at %d: %s",
			    i, ucs_status_string(status));
			return (-1);
		} else {
			okidx[nokreq++] = i;
		}
		ucp_request_free(reqs[i]);
	}
	if (nokreq < env.nvprocs) {
		log_error("fs_rpc_mkdir: ucp_am_send_nbx() failed");
	} else {
		log_debug("fs_rpc_mkdir: ucp_am_send_nbx() succeeded");
	}
	free(reqs);
	int **rets = malloc(sizeof(int *) * nokreq);
	for (int i = 0; i < nokreq; i++) {
		rets[i] = &ret[okidx[i]];
	}
	while (!all_ret_finish(rets, nokreq)) {
		ucp_worker_progress(env.ucp_worker);
	}
	free(rets);
	free(rets_addr);
	if (nokreq < env.nvprocs) {
		free(ret);
		log_error("fs_rpc_mkdir: mkdir() failed nokreq=%d nreqs=%d",
			  nokreq, env.nvprocs);
		return (-1);
	}
	int r = 0;
	for (int i = 0; i < env.nvprocs; i++) {
		if (ret[i] != FINCH_OK) {
			log_error("fs_rpc_mkdir: mkdir() failed at %d: %s", i,
				  strerror(-ret[i]));
			errno = -ret[i];
			r = -1;
		}
	}
	free(ret);
	log_debug("fs_rpc_mkdir: succeeded");
	return (r);
}

int
fs_rpc_inode_create(const char *path, mode_t mode, size_t chunk_size,
		    uint32_t *i_ino)
{
	int target = path_to_target_hash(path, env.nvprocs);
	int path_len = strlen(path) + 1;
	ucp_dt_iov_t iov[5];
	iov[0].buffer = &path_len;
	iov[0].length = sizeof(path_len);
	iov[1].buffer = (void *)path;
	iov[1].length = path_len;
	iov[2].buffer = &mode;
	iov[2].length = sizeof(mode);
	iov[3].buffer = &chunk_size;
	iov[3].length = sizeof(chunk_size);
	iov[4].buffer = i_ino;
	iov[4].length = sizeof(*i_ino);

	inode_create_handle_t handle;
	handle.ret = FINCH_INPROGRESS;
	handle.i_ino = 0;
	void *handle_addr = &handle;
	int *ret_addr = &handle.ret;

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t req;
	req =
	    ucp_am_send_nbx(env.ucp_eps[target], RPC_INODE_CREATE_REQ,
			    &handle_addr, sizeof(handle_addr), iov, 5, &rparam);

	ucs_status_t status;
	while (!all_req_finish(&req, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (req != NULL) {
		status = ucp_request_check_status(req);
		if (status != UCS_OK) {
			log_error(
			    "fs_rpc_inode_create: ucp_am_send_nbx() failed: %s",
			    ucs_status_string(status));
			return (-1);
		}
		ucp_request_free(req);
	}

	log_debug("fs_rpc_inode_create: ucp_am_send_nbx() succeeded");
	while (!all_ret_finish(&ret_addr, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (handle.ret != FINCH_OK) {
		log_error("fs_rpc_inode_create: create() failed: %s",
			  strerror(-handle.ret));
		errno = -handle.ret;
		return (-1);
	}
	log_debug("fs_rpc_inode_create: succeeded ino=%d", handle.i_ino);
	*i_ino = handle.i_ino;
	return (0);
}

int
fs_rpc_inode_unlink(const char *path, uint32_t *i_ino)
{
	int target = path_to_target_hash(path, env.nvprocs);
	int path_len = strlen(path) + 1;
	ucp_dt_iov_t iov[2];
	iov[0].buffer = &path_len;
	iov[0].length = sizeof(path_len);
	iov[1].buffer = (void *)path;
	iov[1].length = path_len;

	inode_create_handle_t handle;
	handle.ret = FINCH_INPROGRESS;
	handle.i_ino = 0;
	void *handle_addr = &handle;
	int *ret_addr = &handle.ret;

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t req;
	req =
	    ucp_am_send_nbx(env.ucp_eps[target], RPC_INODE_UNLINK_REQ,
			    &handle_addr, sizeof(handle_addr), iov, 2, &rparam);

	ucs_status_t status;
	while (!all_req_finish(&req, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (req != NULL) {
		status = ucp_request_check_status(req);
		if (status != UCS_OK) {
			log_error(
			    "fs_rpc_inode_unlink: ucp_am_send_nbx() failed: %s",
			    ucs_status_string(status));
			return (-1);
		}
		ucp_request_free(req);
	}

	log_debug("fs_rpc_inode_unlink: ucp_am_send_nbx() succeeded");
	while (!all_ret_finish(&ret_addr, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (handle.ret != FINCH_OK) {
		log_error("fs_rpc_inode_unlink: unlink() failed: %s",
			  strerror(-handle.ret));
		errno = -handle.ret;
		return (-1);
	}
	log_debug("fs_rpc_inode_unlink: succeeded ino=%d", handle.i_ino);
	*i_ino = handle.i_ino;
	return (0);
}

int
fs_rpc_inode_unlink_all(const char *path)
{
	int path_len = strlen(path) + 1;
	ucp_dt_iov_t iov[2];
	iov[0].buffer = &path_len;
	iov[0].length = sizeof(path_len);
	iov[1].buffer = (void *)path;
	iov[1].length = path_len;

	inode_create_handle_t **handles =
	    malloc(sizeof(inode_create_handle_t *) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		handles[i] = malloc(sizeof(inode_create_handle_t));
		handles[i]->ret = FINCH_INPROGRESS;
		handles[i]->i_ino = 0;
	}

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t *reqs = malloc(sizeof(ucs_status_ptr_t) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		reqs[i] = ucp_am_send_nbx(env.ucp_eps[i], RPC_INODE_UNLINK_REQ,
					  &handles[i], sizeof(handles[i]), iov,
					  2, &rparam);
	}
	while (!all_req_finish(reqs, env.nvprocs)) {
		ucp_worker_progress(env.ucp_worker);
	}
	int nokreq = 0;
	int *okidx = malloc(sizeof(int) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		if (reqs[i] == NULL) {
			okidx[nokreq++] = i;
			continue;
		}
		ucs_status_t status = ucp_request_check_status(reqs[i]);
		if (status != UCS_OK) {
			log_error("fs_rpc_inode_unlink_all: ucp_am_send_nbx() "
				  "failed: %s",
				  ucs_status_string(status));
			return (-1);
		} else {
			okidx[nokreq++] = i;
		}
		ucp_request_free(reqs[i]);
	}
	free(reqs);
	int **rets = malloc(sizeof(int *) * nokreq);
	for (int i = 0; i < nokreq; i++) {
		rets[i] = &handles[okidx[i]]->ret;
	}
	while (!all_ret_finish(rets, nokreq)) {
		ucp_worker_progress(env.ucp_worker);
	}
	free(okidx);
	free(rets);
	if (nokreq < env.nvprocs) {
		for (int i = 0; i < env.nvprocs; i++) {
			free(handles[i]);
		}
		free(handles);
		log_error("fs_rpc_inode_unlink_all: ucp_am_send_nbx() failed"
			  "nokreq=%d nreqs=%d",
			  nokreq, env.nvprocs);
		return (-1);
	}
	int ret = 0;
	for (int i = 0; i < env.nvprocs; i++) {
		if (handles[i]->ret != FINCH_OK) {
			log_error("fs_rpc_inode_unlink_all: unlink() failed: "
				  "%s",
				  strerror(-handles[i]->ret));
			errno = -handles[i]->ret;
			free(handles[i]);
			ret = -1;
		}
	}
	free(handles);
	return (ret);
}

int
fs_rpc_inode_stat(const char *path, fs_stat_t *st)
{
	int target = path_to_target_hash(path, env.nvprocs);
	int path_len = strlen(path) + 1;
	ucp_dt_iov_t iov[2];
	iov[0].buffer = &path_len;
	iov[0].length = sizeof(path_len);
	iov[1].buffer = (void *)path;
	iov[1].length = path_len;

	inode_stat_handle_t handle;
	handle.ret = FINCH_INPROGRESS;

	void *handle_addr = &handle;
	int *ret_addr = &handle.ret;

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t req;
	req =
	    ucp_am_send_nbx(env.ucp_eps[target], RPC_INODE_STAT_REQ,
			    &handle_addr, sizeof(handle_addr), iov, 2, &rparam);
	ucs_status_t status;
	while (!all_req_finish(&req, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (req != NULL) {
		status = ucp_request_check_status(req);
		if (status != UCS_OK) {
			log_error(
			    "fs_rpc_inode_create: ucp_am_send_nbx() failed: %s",
			    ucs_status_string(status));
			return (-1);
		}
		ucp_request_free(req);
	}

	log_debug("fs_rpc_inode_stat: ucp_am_send_nbx() succeeded");
	while (!all_ret_finish(&ret_addr, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (handle.ret != FINCH_OK) {
		if (handle.ret != FINCH_ENOENT) {
			log_error("fs_rpc_inode_stat: stat() failed: %s",
				  strerror(-handle.ret));
		} else {
			log_debug("fs_rpc_inode_stat: stat() failed with "
				  "ENOENT");
		}
		errno = -handle.ret;
		return (-1);
	}
	*st = handle.st;
	log_debug("fs_rpc_inode_stat: succeeded ino=%zu chunksize=%zu",
		  st->i_ino, st->chunk_size);
	return (0);
}

int
fs_rpc_inode_truncate(uint32_t i_ino, uint32_t index, off_t offset)
{
	int target = (i_ino + index) % env.nvprocs;
	ucp_dt_iov_t iov[3];
	iov[0].buffer = &i_ino;
	iov[0].length = sizeof(i_ino);
	iov[1].buffer = &index;
	iov[1].length = sizeof(index);
	iov[2].buffer = &offset;
	iov[2].length = sizeof(offset);

	int ret = FINCH_INPROGRESS;
	int *ret_addr = &ret;

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t req;
	req = ucp_am_send_nbx(env.ucp_eps[target], RPC_INODE_TRUNCATE_REQ,
			      &ret_addr, sizeof(void *), iov, 3, &rparam);

	ucs_status_t status;
	while (!all_req_finish(&req, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (req != NULL) {
		status = ucp_request_check_status(req);
		if (status != UCS_OK) {
			log_error(
			    "fs_rpc_inode_truncate: ucp_am_send_nbx() failed: "
			    "%s",
			    ucs_status_string(status));
			errno = EIO;
			return (-1);
		}
		ucp_request_free(req);
	}

	log_debug("fs_rpc_inode_truncate: ucp_am_send_nbx() succeeded");
	while (!all_ret_finish(&ret_addr, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (ret != FINCH_OK) {
		if (ret != FINCH_ENOENT) {
			log_error(
			    "fs_rpc_inode_truncate: truncate() failed: %s",
			    strerror(-ret));
		} else {
			log_debug("fs_rpc_inode_truncate: truncate() failed "
				  "with ENOENT");
		}
		errno = -ret;
		return (-1);
	}
	log_debug("fs_rpc_inode_truncate: succeeded");
	return (0);
}

int
fs_rpc_inode_chunk_stat(uint32_t i_ino, uint32_t index, size_t *size)
{
	int target = (i_ino + index) % env.nvprocs;
	ucp_dt_iov_t iov[2];
	iov[0].buffer = &i_ino;
	iov[0].length = sizeof(i_ino);
	iov[1].buffer = &index;
	iov[1].length = sizeof(index);

	inode_chunk_stat_handle_t handle;
	handle.ret = FINCH_INPROGRESS;

	void *handle_addr = &handle;
	int *ret_addr = &handle.ret;

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};
	ucs_status_ptr_t req;
	req =
	    ucp_am_send_nbx(env.ucp_eps[target], RPC_INODE_CHUNK_STAT_REQ,
			    &handle_addr, sizeof(handle_addr), iov, 2, &rparam);
	ucs_status_t status;
	while (!all_req_finish(&req, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (req != NULL) {
		status = ucp_request_check_status(req);
		if (status != UCS_OK) {
			log_error("fs_rpc_inode_chunk_stat: ucp_am_send_nbx() "
				  "failed: %s",
				  ucs_status_string(status));
			errno = EIO;
			return (-1);
		}
		ucp_request_free(req);
	}

	log_debug("fs_rpc_inode_chunk_stat: ucp_am_send_nbx() succeeded");
	while (!all_ret_finish(&ret_addr, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (handle.ret != FINCH_OK) {
		if (handle.ret != FINCH_ENOENT) {
			log_error("fs_rpc_inode_chunk_stat: stat(index=%zu) "
				  "failed: %s",
				  index, strerror(-handle.ret));
		} else {
			log_debug(
			    "fs_rpc_inode_chunk_stat: stat(index=%zu) failed "
			    "with ENOENT",
			    index);
		}
		errno = -handle.ret;
		return (-1);
	}
	*size = handle.size;
	log_debug(
	    "fs_rpc_inode_chunk_stat: succeeded ino=%zu index=%zu size=%zu",
	    i_ino, index, *size);
	return (0);
}

void *
fs_async_rpc_inode_write(uint32_t i_ino, uint32_t index, off_t offset,
			 size_t size, const void *buf)
{
	if (size == 0) {
		log_error("fs_rpc_inode_write: size is 0");
		return (NULL);
	}
	int target = (i_ino + index) % env.nvprocs;

	inode_write_handle_t *handle = malloc(sizeof(inode_write_handle_t));
	handle->ret = FINCH_INPROGRESS;
	handle->ss = -1;
	handle->header = (inode_write_header_t){
	    .handle = handle,
	    .i_ino = i_ino,
	    .index = index,
	    .offset = offset,
	};

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_REPLY,
	    .datatype = ucp_dt_make_contig(sizeof(char)),
	};

	handle->req = ucp_am_send_nbx(env.ucp_eps[target], RPC_INODE_WRITE_REQ,
				      &handle->header, sizeof(handle->header),
				      buf, size, &rparam);
	if (handle->req && UCS_PTR_IS_ERR(handle->req)) {
		log_error("fs_rpc_inode_write: ucp_am_send_nbx() failed: %s",
			  ucs_status_string(UCS_PTR_STATUS(handle->req)));
		free(handle);
		return (NULL);
	}
	return (handle);
}

ssize_t
fs_async_rpc_inode_write_wait(void **hdles, int nreqs)
{
	inode_write_handle_t **handles = (inode_write_handle_t **)hdles;
	ucs_status_t status;
	ucs_status_ptr_t *reqs = malloc(sizeof(ucs_status_ptr_t) * nreqs);
	for (int i = 0; i < nreqs; i++) {
		reqs[i] = handles[i]->req;
	}
	while (!all_req_finish(reqs, nreqs)) {
		ucp_worker_progress(env.ucp_worker);
	}
	int nokreq = 0;
	int *okidx = malloc(sizeof(int) * nreqs);
	for (int i = 0; i < nreqs; i++) {
		if (reqs[i] == NULL) {
			okidx[nokreq++] = i;
			continue;
		}
		status = ucp_request_check_status(reqs[i]);
		if (status != UCS_OK) {
			log_error("fs_async_rpc_inode_write_wait: "
				  "ucp_am_send_nbx() failed at %d: %s",
				  i, ucs_status_string(status));
		} else {
			okidx[nokreq++] = i;
		}
		ucp_request_free(reqs[i]);
	}
	if (nokreq < nreqs) {
		log_error(
		    "fs_async_rpc_inode_write_wait: ucp_am_send_nbx() failed");
	} else {
		log_debug("fs_async_rpc_inode_write_wait: ucp_am_send_nbx() "
			  "succeeded");
	}

	free(reqs);
	int **rets = malloc(sizeof(int *) * nokreq);
	for (int i = 0; i < nokreq; i++) {
		rets[i] = &handles[okidx[i]]->ret;
	}
	while (!all_ret_finish(rets, nokreq)) {
		ucp_worker_progress(env.ucp_worker);
	}
	free(okidx);
	free(rets);
	if (nokreq < nreqs) {
		for (int i = 0; i < nreqs; i++) {
			free(handles[i]);
		}
		log_error("fs_async_rpc_inode_write_wait failed"
			  "nokreq=%d nreqs=%d",
			  nokreq, nreqs);
		return (-1);
	}
	ssize_t ss = 0;
	for (int i = 0; i < nreqs; i++) {
		if (handles[i]->ret != FINCH_OK) {
			log_error("fs_async_rpc_inode_write_wait: "
				  "write() failed at %d: %s",
				  i, strerror(-handles[i]->ret));
			errno = -handles[i]->ret;
			ss = -1;
			break;
		}
		ss += handles[i]->ss;
	}
	for (int i = 0; i < nreqs; i++) {
		free(handles[i]);
	}
	return (ss);
}

void *
fs_async_rpc_inode_read(uint32_t i_ino, uint32_t index, off_t offset,
			size_t size, void *buf)
{
	if (size == 0) {
		log_error("fs_async_rpc_inode_read: size is 0");
		return (NULL);
	}

	int target = (i_ino + index) % env.nvprocs;
	inode_read_handle_t *handle = malloc(sizeof(inode_read_handle_t));
	log_debug("fs_async_rpc_inode_read: handle=%p", handle);
	handle->ret = FINCH_INPROGRESS;
	handle->ss = -1;
	handle->buf = buf;
	handle->header = (inode_read_header_t){
	    .handle = handle,
	    .i_ino = i_ino,
	    .index = index,
	    .offset = offset,
	    .size = size,
	    .ret = FINCH_INPROGRESS,
	};

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = ucp_dt_make_contig(sizeof(char)),
	};

	handle->req = ucp_am_send_nbx(env.ucp_eps[target], RPC_INODE_READ_REQ,
				      &handle->header, sizeof(handle->header),
				      buf, 1, &rparam);
	if (handle->req && UCS_PTR_IS_ERR(handle->req)) {
		log_error("fs_rpc_inode_read: ucp_am_send_nbx() failed: %s",
			  ucs_status_string(UCS_PTR_STATUS(handle->req)));
		free(handle);
		return (NULL);
	}
	return (handle);
}

ssize_t
fs_async_rpc_inode_read_wait(void **hdles, int nreqs)
{
	inode_read_handle_t **handles = (inode_read_handle_t **)hdles;
	ucs_status_t status;
	ucs_status_ptr_t *reqs = malloc(sizeof(ucs_status_ptr_t) * nreqs);
	for (int i = 0; i < nreqs; i++) {
		reqs[i] = handles[i]->req;
	}
	while (!all_req_finish(reqs, nreqs)) {
		ucp_worker_progress(env.ucp_worker);
	}
	int nokreq = 0;
	int *okidx = malloc(sizeof(int) * nreqs);
	for (int i = 0; i < nreqs; i++) {
		if (reqs[i] == NULL) {
			okidx[nokreq++] = i;
			continue;
		}
		status = ucp_request_check_status(reqs[i]);
		if (status != UCS_OK) {
			log_error("fs_async_rpc_inode_read_wait: "
				  "ucp_am_send_nbx() failed at %d: %s",
				  i, ucs_status_string(status));
		} else {
			okidx[nokreq++] = i;
		}
		ucp_request_free(reqs[i]);
	}
	if (nokreq < nreqs) {
		log_error(
		    "fs_async_rpc_inode_read_wait: ucp_am_send_nbx() failed");
	} else {
		log_debug("fs_async_rpc_inode_read_wait: ucp_am_send_nbx() "
			  "succeeded");
	}
	free(reqs);
	int **rets = malloc(sizeof(int *) * nokreq);
	for (int i = 0; i < nokreq; i++) {
		rets[i] = &handles[okidx[i]]->ret;
	}
	while (!all_ret_finish(rets, nokreq)) {
		ucp_worker_progress(env.ucp_worker);
	}
	free(okidx);
	free(rets);
	if (nokreq < nreqs) {
		for (int i = 0; i < nreqs; i++) {
			free(handles[i]);
		}
		log_error("fs_async_rpc_inode_read_wait failed"
			  "nokreq=%d nreqs=%d",
			  nokreq, nreqs);
		return (-1);
	}
	ssize_t ss = 0;
	for (int i = 0; i < nreqs; i++) {
		if (handles[i]->ret == FINCH_ENOENT) {
			log_debug("fs_async_rpc_inode_read_wait: ENOENT");
			break;
		} else if (handles[i]->ret != FINCH_OK) {
			log_error("fs_async_rpc_inode_read_wait: "
				  "read() failed at %d: %s",
				  i, strerror(-handles[i]->ret));
			errno = -handles[i]->ret;
			ss = -1;
			break;
		}
		ss += handles[i]->ss;
	}
	for (int i = 0; i < nreqs; i++) {
		free(handles[i]);
	}
	return (ss);
}

int
fs_rpc_readdir(const char *path, void *arg,
	       void (*filler)(void *, const char *, const struct stat *))
{
	int path_len = strlen(path) + 1;
	ucp_dt_iov_t iov[2];
	iov[0].buffer = &path_len;
	iov[0].length = sizeof(path_len);
	iov[1].buffer = (void *)path;
	iov[1].length = path_len;

	readdir_handle_t *handles =
	    malloc(sizeof(readdir_handle_t) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		handles[i].ret = FINCH_INPROGRESS;
		handles[i].arg = arg;
		handles[i].filler = filler;
		handles[i].header.handle = &handles[i];
		handles[i].header.entry_count = 1024;
		handles[i].header.fileonly = (int)(i > 0);
	}

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t *reqs = malloc(sizeof(ucs_status_ptr_t) * env.nvprocs);

	for (int i = 0; i < env.nvprocs; i++) {
		reqs[i] = ucp_am_send_nbx(
		    env.ucp_eps[i], RPC_READDIR_REQ, &handles[i].header,
		    sizeof(handles[i].header), iov, 2, &rparam);
	}
	while (!all_req_finish(reqs, env.nvprocs)) {
		ucp_worker_progress(env.ucp_worker);
	}
	int nokreq = 0;
	int *okidx = malloc(sizeof(int) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		if (reqs[i] == NULL) {
			okidx[nokreq++] = i;
			continue;
		}
		ucs_status_t status = ucp_request_check_status(reqs[i]);
		if (status != UCS_OK) {
			log_error("fs_rpc_readdir: ucp_am_send_nbx() failed "
				  "at %d: %s",
				  i, ucs_status_string(status));
		} else {
			okidx[nokreq++] = i;
		}
		ucp_request_free(reqs[i]);
	}
	if (nokreq < env.nvprocs) {
		log_error("fs_rpc_readdir: ucp_am_send_nbx() failed");
	} else {
		log_debug("fs_rpc_readdir: ucp_am_send_nbx() succeeded");
	}
	free(reqs);
	int **rets = malloc(sizeof(int *) * nokreq);
	for (int i = 0; i < nokreq; i++) {
		rets[i] = &handles[okidx[i]].ret;
	}
	while (!all_ret_finish(rets, nokreq)) {
		ucp_worker_progress(env.ucp_worker);
	}
	free(okidx);
	free(rets);
	if (nokreq < env.nvprocs) {
		free(handles);
		log_error("fs_rpc_readdir_wait failed nokreq=%d nreqs=%d",
			  nokreq, env.nvprocs);
		return (-1);
	}
	int r = 0;
	for (int i = 0; i < env.nvprocs; i++) {
		if (handles[i].ret != FINCH_OK) {
			log_error("fs_rpc_readdir: readdir() failed at %d: %s",
				  i, strerror(-handles[i].ret));
			errno = -handles[i].ret;
			r = -1;
		}
	}
	free(handles);
	return (r);
}

int
fs_rpc_dir_move(const char *oldpath, const char *newpath)
{
	int opath_len = strlen(oldpath) + 1;
	int npath_len = strlen(newpath) + 1;
	ucp_dt_iov_t iov[4];
	iov[0].buffer = &opath_len;
	iov[0].length = sizeof(opath_len);
	iov[1].buffer = (void *)oldpath;
	iov[1].length = opath_len;
	iov[2].buffer = &npath_len;
	iov[2].length = sizeof(npath_len);
	iov[3].buffer = (void *)newpath;
	iov[3].length = npath_len;

	int *ret = malloc(sizeof(int) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		ret[i] = FINCH_INPROGRESS;
	}
	int **rets_addr = malloc(sizeof(int *) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		rets_addr[i] = &ret[i];
	}

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t *reqs = malloc(sizeof(ucs_status_ptr_t) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		reqs[i] = ucp_am_send_nbx(env.ucp_eps[i], RPC_DIR_MOVE_REQ,
					  &rets_addr[i], sizeof(void *), iov, 4,
					  &rparam);
	}

	ucs_status_t status;
	while (!all_req_finish(reqs, env.nvprocs)) {
		ucp_worker_progress(env.ucp_worker);
	}
	int nokreq = 0;
	int *okidx = malloc(sizeof(int) * env.nvprocs);
	for (int i = 0; i < env.nvprocs; i++) {
		if (reqs[i] == NULL) {
			okidx[nokreq++] = i;
			continue;
		}
		status = ucp_request_check_status(reqs[i]);
		if (status != UCS_OK) {
			log_error("fs_rpc_dir_move: ucp_am_send_nbx() failed "
				  "at %d: %s",
				  i, ucs_status_string(status));
		} else {
			okidx[nokreq++] = i;
		}
		ucp_request_free(reqs[i]);
	}
	if (nokreq < env.nvprocs) {
		log_error("fs_rpc_dir_move: ucp_am_send_nbx() failed");
	} else {
		log_debug("fs_rpc_dir_move: ucp_am_send_nbx() succeeded");
	}
	free(reqs);
	int **rets = malloc(sizeof(int *) * nokreq);
	for (int i = 0; i < nokreq; i++) {
		rets[i] = &ret[okidx[i]];
	}
	while (!all_ret_finish(rets, nokreq)) {
		ucp_worker_progress(env.ucp_worker);
	}
	free(rets);
	free(rets_addr);
	if (nokreq < env.nvprocs) {
		free(ret);
		log_error("fs_rpc_dir_move: rename() failed nokreq=%d nreqs=%d",
			  nokreq, env.nvprocs);
		return (-1);
	}
	int r = 0;
	for (int i = 0; i < env.nvprocs; i++) {
		if (ret[i] != FINCH_OK) {
			log_error("fs_rpc_dir_move: rename() failed at %d: %s",
				  i, strerror(-ret[i]));
			errno = -ret[i];
			r = -1;
		}
	}
	free(ret);
	log_debug("fs_rpc_dir_move: succeeded");
	return (r);
}
