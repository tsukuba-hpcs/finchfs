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
#include "config.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "log.h"

typedef struct {
	ucp_context_h ucp_context;
	ucp_worker_h ucp_worker;
	int rank;
	int nprocs;
	int shutdown;
	char *db_dir;
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
dump_addrfile(finchfsd_ctx_t *ctx)
{
	ucp_address_t *addr;
	size_t addr_len;
	ucs_status_t status;
	int fd;

	if ((status = ucp_worker_get_address(ctx->ucp_worker, &addr,
					     &addr_len)) != UCS_OK) {
		log_error("ucp_worker_get_address() failed: %s",
			  ucs_status_string(status));
		return (-1);
	}

	fd = creat(DUMP_ADDR_FILE, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		log_error("creat() failed: %s", strerror(errno));
		return (-1);
	}
	if (write(fd, &addr_len, sizeof(addr_len)) != sizeof(addr_len)) {
		log_error("write() failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}
	if (write(fd, &ctx->nprocs, sizeof(ctx->nprocs)) !=
	    sizeof(ctx->nprocs)) {
		log_error("write() failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}

	uint8_t *addr_allprocs = malloc(addr_len * ctx->nprocs);
	MPI_Allgather(addr, addr_len, MPI_BYTE, addr_allprocs, addr_len,
		      MPI_BYTE, MPI_COMM_WORLD);
	ucp_worker_release_address(ctx->ucp_worker, addr);

	if (write(fd, addr_allprocs, addr_len * ctx->nprocs) !=
	    addr_len * ctx->nprocs) {
		log_error("write() failed: %s", strerror(errno));
		free(addr_allprocs);
		close(fd);
		return (-1);
	}
	close(fd);
	free(addr_allprocs);
	return (0);
}

int
main(int argc, char **argv)
{
	finchfsd_ctx_t ctx = {
	    .shutdown = 0,
	    .db_dir = "/tmp/finch_data",
	};
	ucs_status_t status;
	pthread_t handler_thread;
	int c;
	while ((c = getopt(argc, argv, "d:v:")) != -1) {
		switch (c) {
		case 'd':
			ctx.db_dir = strdup(optarg);
			break;
		case 'v':
			log_set_level(optarg);
			break;
		default:
			log_fatal("Unknown option %c", c);
			return (-1);
		}
	}

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

	if (fs_server_init(ctx.ucp_worker, ctx.db_dir, ctx.rank, ctx.nprocs)) {
		log_fatal("fs_server_init() failed: %s",
			  ucs_status_string(status));
		return (-1);
	}

	if (dump_addrfile(&ctx)) {
		log_fatal("dump_addrfile() failed: %s",
			  ucs_status_string(status));
		return (-1);
	}

	while (!ctx.shutdown) {
		ucp_worker_progress(ctx.ucp_worker);
	}

	fs_server_term();

	ucp_worker_destroy(ctx.ucp_worker);
	ucp_cleanup(ctx.ucp_context);

	MPI_Finalize();
	return (0);
}
