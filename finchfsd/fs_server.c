#include <ucp/api/ucp.h>
#include "fs_rpc.h"
#include "log.h"

ucs_status_t
fs_rpc_mkdir_recv(void *arg, const void *header, size_t header_length,
		  void *data, size_t length, const ucp_am_recv_param_t *param)
{
	log_debug("fs_rpc_mkdir_recv() called");
	return (UCS_OK);
}

int
fs_server_init(ucp_worker_h worker)
{
	ucs_status_t status;
	ucp_am_handler_param_t mkdir_param = {
	    .field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
			  UCP_AM_HANDLER_PARAM_FIELD_ARG |
			  UCP_AM_HANDLER_PARAM_FIELD_CB,
	    .id = RPC_MKDIR_REQ,
	    .cb = fs_rpc_mkdir_recv,
	    .arg = NULL,
	};
	if ((status = ucp_worker_set_am_recv_handler(worker, &mkdir_param)) !=
	    UCS_OK) {
		log_error("ucp_worker_set_am_recv_handler(mkdir) failed: %s",
			  ucs_status_string(status));
		return (-1);
	}
}
