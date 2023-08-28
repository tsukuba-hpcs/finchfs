#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ucp/api/ucp.h>
#include "finchfs.h"
#include "config.h"
#include "log.h"
#include "fs_rpc.h"

static struct env {
	ucp_context_h ucp_context;
	ucp_worker_h ucp_worker;
	ucp_ep_h *ucp_eps;
	int nprocs;
} env;

ucs_status_t
fs_rpc_mkdir_reply(void *arg, const void *header, size_t header_length,
		   void *data, size_t length, const ucp_am_recv_param_t *param)
{
	void *ret = *(void **)header;
	memcpy(ret, data, sizeof(int));
	return (UCS_OK);
}

ucs_status_t
fs_rpc_inode_create_reply(void *arg, const void *header, size_t header_length,
			  void *data, size_t length,
			  const ucp_am_recv_param_t *param)
{
	void *ret = *(void **)header;
	memcpy(ret, data, sizeof(int));
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
	if (read(fd, &env.nprocs, sizeof(env.nprocs)) != sizeof(env.nprocs)) {
		log_error("read(nprocs) failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}
	log_debug("addr_len: %zu, nprocs: %d", addr_len, env.nprocs);
	addr_allprocs = malloc(addr_len * env.nprocs);
	if (read(fd, addr_allprocs, addr_len * env.nprocs) !=
	    addr_len * env.nprocs) {
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

	env.ucp_eps = malloc(sizeof(ucp_ep_h) * env.nprocs);
	for (int i = 0; i < env.nprocs; i++) {
		ucp_ep_params_t ucp_ep_params = {
		    .field_mask = UCP_EP_PARAM_FIELD_ERR_HANDLER |
				  UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE |
				  UCP_EP_PARAM_FIELD_REMOTE_ADDRESS,
		    .err_handler =
			{
			    .arg = NULL,
			    .cb = ep_err_cb,
			},
		    .err_mode = UCP_ERR_HANDLING_MODE_PEER,
		    .address = (ucp_address_t *)(addr_allprocs + addr_len * i),
		};
		if ((status = ucp_ep_create(env.ucp_worker, &ucp_ep_params,
					    &env.ucp_eps[i])) != UCS_OK) {
			log_error("ucp_ep_create() failed: %s",
				  ucs_status_string(status));
			return (-1);
		}
	}

	ucp_am_handler_param_t mkdir_reply_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_MKDIR_REP,
	    .cb = fs_rpc_mkdir_reply,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 env.ucp_worker, &mkdir_reply_param)) != UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(mkdir) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
	ucp_am_handler_param_t inode_create_reply_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_INODE_CREATE_REP,
	    .cb = fs_rpc_inode_create_reply,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(
		 env.ucp_worker, &inode_create_reply_param)) != UCS_OK) {
		log_error(
		    "ucp_worker_set_am_recv_handler(inode create) failed: %s",
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
all_ret_finish(int *rets, int num)
{
	for (int i = 0; i < num; i++) {
		if (rets[i] == FINCH_INPROGRESS) {
			return (0);
		}
	}
	return (1);
}

int
fs_client_term(void)
{
	ucs_status_ptr_t *reqs = malloc(sizeof(ucs_status_ptr_t) * env.nprocs);
	ucp_request_param_t params = {
	    .op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_EP_CLOSE_MODE_FLUSH,
	};

	for (int i = 0; i < env.nprocs; i++) {
		reqs[i] = ucp_ep_close_nbx(env.ucp_eps[i], &params);
	}

	while (!all_req_finish(reqs, env.nprocs)) {
		ucp_worker_progress(env.ucp_worker);
	}
	for (int i = 0; i < env.nprocs; i++) {
		if (UCS_PTR_IS_ERR(reqs[i])) {
			log_error("ucp_ep_close_nbx() failed: %s",
				  ucs_status_string(UCS_PTR_STATUS(reqs[i])));
			return (-1);
		}
	}

	free(reqs);
	free(env.ucp_eps);
	ucp_worker_destroy(env.ucp_worker);
	ucp_cleanup(env.ucp_context);

	return (0);
}

static int
path_to_target_hash(const char *path, int div)
{
	long h = 0;
	char *head = strdup(path);
	char *next;
	long n;
	for (char *p = head; *p != '\0'; p = next) {
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

	int *rets = malloc(sizeof(int) * env.nprocs);
	for (int i = 0; i < env.nprocs; i++) {
		rets[i] = FINCH_INPROGRESS;
	}
	void **rets_addr = malloc(sizeof(void *) * env.nprocs);
	for (int i = 0; i < env.nprocs; i++) {
		rets_addr[i] = &rets[i];
	}

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t *req = malloc(sizeof(ucs_status_ptr_t) * env.nprocs);
	for (int i = 0; i < env.nprocs; i++) {
		req[i] = ucp_am_send_nbx(env.ucp_eps[i], RPC_MKDIR_REQ,
					 &rets_addr[i], sizeof(void *), iov, 3,
					 &rparam);
	}

	ucs_status_t status;
	while (!all_req_finish(req, env.nprocs)) {
		ucp_worker_progress(env.ucp_worker);
	}
	for (int i = 0; i < env.nprocs; i++) {
		if (req[i] == NULL) {
			continue;
		}
		status = ucp_request_check_status(req[i]);
		if (status != UCS_OK) {
			log_error(
			    "fs_rpc_mkdir: ucp_am_send_nbx() failed at %d: %s",
			    i, ucs_status_string(status));
			return (-1);
		}
		ucp_request_free(req[i]);
	}
	free(req);
	free(rets_addr);
	log_debug("fs_rpc_mkdir: ucp_am_send_nbx() succeeded");

	while (!all_ret_finish(rets, env.nprocs)) {
		ucp_worker_progress(env.ucp_worker);
	}
	for (int i = 0; i < env.nprocs; i++) {
		if (rets[i] != FINCH_OK) {
			log_error("fs_rpc_mkdir: mkdir() failed at %d: %s", i,
				  strerror(-rets[i]));
			errno = -rets[i];
			free(rets);
			return (-1);
		}
	}
	free(rets);
	log_debug("fs_rpc_mkdir: succeeded");
	return (0);
}

int
fs_rpc_inode_create(const char *path, mode_t mode, size_t chunk_size)
{
	int target = path_to_target_hash(path, env.nprocs);
	int path_len = strlen(path) + 1;
	ucp_dt_iov_t iov[4];
	iov[0].buffer = &path_len;
	iov[0].length = sizeof(path_len);
	iov[1].buffer = (void *)path;
	iov[1].length = path_len;
	iov[2].buffer = &mode;
	iov[2].length = sizeof(mode);
	iov[3].buffer = &chunk_size;
	iov[3].length = sizeof(chunk_size);

	int ret = FINCH_INPROGRESS;
	void *ret_addr = &ret;

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER | UCP_AM_SEND_FLAG_REPLY,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t req;
	req = ucp_am_send_nbx(env.ucp_eps[target], RPC_INODE_CREATE_REQ,
			      &ret_addr, sizeof(void *), iov, 4, &rparam);

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
	while (!all_ret_finish(&ret, 1)) {
		ucp_worker_progress(env.ucp_worker);
	}
	if (ret != FINCH_OK) {
		log_error("fs_rpc_inode_create: create() failed: %s",
			  strerror(-ret));
		errno = -ret;
		return (-1);
	}
	log_debug("fs_rpc_inode_create: succeeded");
	return (0);
}
