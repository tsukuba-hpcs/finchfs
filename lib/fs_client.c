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
	return (0);
}

static int
all_req_finish(ucs_status_ptr_t *reqs)
{
	for (int i = 0; i < env.nprocs; i++) {
		if (reqs[i] != NULL && !UCS_PTR_IS_ERR(reqs[i])) {
			return 0;
		}
	}
	return 1;
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

	while (!all_req_finish(reqs)) {
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
	ucp_dt_iov_t iov[2];
	iov[0].buffer = (void *)path;
	iov[0].length = strlen(path) + 1;
	iov[1].buffer = &mode;
	iov[1].length = sizeof(mode_t);

	ucp_request_param_t rparam = {
	    .op_attr_mask =
		UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
	    .flags = UCP_AM_SEND_FLAG_EAGER,
	    .datatype = UCP_DATATYPE_IOV,
	};

	ucs_status_ptr_t req;
	int target = path_to_target_hash(path, env.nprocs);
	req = ucp_am_send_nbx(env.ucp_eps[target], RPC_MKDIR_REQ, NULL, 0, iov,
			      2, &rparam);

	ucs_status_t status;
	do {
		ucp_worker_progress(env.ucp_worker);
		status = ucp_request_check_status(req);
	} while (status == UCS_INPROGRESS);
	if (status != UCS_OK) {
		log_error("fs_rpc_mkdir: ucp_am_send_nbx() failed: %s",
			  ucs_status_string(UCS_PTR_STATUS(req)));
		return (-1);
	}
	log_debug("fs_rpc_mkdir: ucp_am_send_nbx() succeeded");
	return (0);
}
