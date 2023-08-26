#include <mpi.h>
#include <ucp/api/ucp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include "log.h"

typedef struct {
	ucp_context_h ucp_context;
	ucp_worker_h ucp_worker;
	int rank;
	int nprocs;
	int shutdown;
} finchfsd_ctx_t;

static sigset_t sigset;

static void *
handle_sig(void *arg)
{
	int sig;
	finchfsd_ctx_t *ctx = (finchfsd_ctx_t *)arg;
	log_debug("Waiting for signal");
	sigwait(&sigset, &sig);
	log_debug("Caught signal %d, shutting down", sig);
	__atomic_fetch_add(&ctx->shutdown, 1, __ATOMIC_SEQ_CST);
	return (NULL);
}

int
main(int argc, char **argv)
{
	finchfsd_ctx_t ctx = {
	    .shutdown = 0,
	};
	ucs_status_t status;
	pthread_t handler_thread;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	if (pthread_sigmask(SIG_BLOCK, &sigset, NULL)) {
		log_error("pthread_sigmask() failed: %s", strerror(errno));
		return (-1);
	}
	pthread_create(&handler_thread, NULL, handle_sig, &ctx);
	pthread_detach(handler_thread);

	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &ctx.rank);
	MPI_Comm_size(MPI_COMM_WORLD, &ctx.nprocs);

	ucp_params_t ucp_params = {
	    .field_mask = UCP_PARAM_FIELD_FEATURES,
	    .features = UCP_FEATURE_RMA | UCP_FEATURE_AM,
	};
	if ((status = ucp_init(&ucp_params, NULL, &ctx.ucp_context)) !=
	    UCS_OK) {
		log_fatal("ucp_init() failed: %s", ucs_status_string(status));
		return (-1);
	}

	ucp_worker_params_t ucp_worker_params = {
	    .field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE,
	    .thread_mode = UCS_THREAD_MODE_SINGLE};
	if ((status = ucp_worker_create(ctx.ucp_context, &ucp_worker_params,
					&ctx.ucp_worker)) != UCS_OK) {
		log_fatal("ucp_worker_create() failed: %s",
			  ucs_status_string(status));
		return (-1);
	}

	while (!ctx.shutdown) {
		ucp_worker_progress(ctx.ucp_worker);
	}

	ucp_worker_destroy(ctx.ucp_worker);
	ucp_cleanup(ctx.ucp_context);

	MPI_Finalize();
	return (0);
}