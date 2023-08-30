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
	ucp_worker_h *ucp_workers;
	int rank;
	int nprocs;
	int nthreads;
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
	int vprocs;
	void *addr_allthreads;
	size_t addr_len;
	ucs_status_t status;
	int fd;

	vprocs = ctx->nprocs * ctx->nthreads;

	for (int i = 0; i < ctx->nthreads; i++) {
		ucp_address_t *addr;
		if ((status = ucp_worker_get_address(ctx->ucp_workers[i], &addr,
						     &addr_len)) != UCS_OK) {
			log_error("ucp_worker_get_address() failed: %s",
				  ucs_status_string(status));
			return (-1);
		}
		if (i == 0) {
			addr_allthreads = malloc(addr_len * ctx->nthreads);
		}
		memcpy(addr_allthreads + addr_len * i, addr, addr_len);
		ucp_worker_release_address(ctx->ucp_workers[i], addr);
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

	if (write(fd, &vprocs, sizeof(vprocs)) != sizeof(vprocs)) {
		log_error("write() failed: %s", strerror(errno));
		close(fd);
		return (-1);
	}

	uint8_t *addr_allvprocs = malloc(addr_len * vprocs);
	MPI_Allgather(addr_allthreads, addr_len * ctx->nthreads, MPI_BYTE,
		      addr_allvprocs, addr_len * ctx->nthreads, MPI_BYTE,
		      MPI_COMM_WORLD);
	free(addr_allthreads);

	if (write(fd, addr_allvprocs, addr_len * vprocs) != addr_len * vprocs) {
		log_error("write() failed: %s", strerror(errno));
		free(addr_allvprocs);
		close(fd);
		return (-1);
	}
	close(fd);
	free(addr_allvprocs);
	return (0);
}

int
main(int argc, char **argv)
{
	finchfsd_ctx_t ctx = {
	    .shutdown = 0,
	    .db_dir = "/tmp/finch_data",
	    .nthreads = 1,
	};
	ucs_status_t status;
	pthread_t handler_thread;
	pthread_t *worker_threads;
	int *worker_thread_args;
	int c;
	while ((c = getopt(argc, argv, "d:v:t:")) != -1) {
		switch (c) {
		case 'd':
			ctx.db_dir = strdup(optarg);
			break;
		case 'v':
			log_set_level(optarg);
			break;
		case 't':
			ctx.nthreads = atoi(optarg);
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
	ctx.ucp_workers = malloc(sizeof(ucp_worker_h) * ctx.nthreads);

	ucp_worker_params_t ucp_worker_params = {
	    .field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE,
	    .thread_mode = UCS_THREAD_MODE_SINGLE};
	for (int i = 0; i < ctx.nthreads; i++) {
		if ((status =
			 ucp_worker_create(ctx.ucp_context, &ucp_worker_params,
					   &ctx.ucp_workers[i])) != UCS_OK) {
			log_fatal("ucp_worker_create() failed: %s",
				  ucs_status_string(status));
			return (-1);
		}
		if (fs_server_init(ctx.ucp_workers[i], ctx.db_dir, ctx.rank,
				   ctx.nprocs, i, ctx.nthreads,
				   &ctx.shutdown)) {
			log_fatal("fs_server_init() failed: %s",
				  ucs_status_string(status));
			return (-1);
		}
	}

	if (dump_addrfile(&ctx)) {
		log_fatal("dump_addrfile() failed: %s",
			  ucs_status_string(status));
		return (-1);
	}

	worker_threads = malloc(sizeof(pthread_t) * ctx.nthreads);
	worker_thread_args = malloc(sizeof(int) * ctx.nthreads);
	for (int i = ctx.nthreads - 1; i >= 0; i--) {
		worker_thread_args[i] = i;
		if (i > 0) {
			pthread_create(&worker_threads[i], NULL,
				       fs_server_progress,
				       &worker_thread_args[i]);
		} else {
			fs_server_progress(&worker_thread_args[i]);
		}
	}
	for (int i = 0; i < ctx.nthreads; i++) {
		if (i > 0) {
			pthread_join(worker_threads[i], NULL);
		}
		fs_server_term(i);
		ucp_worker_destroy(ctx.ucp_workers[i]);
	}

	ucp_cleanup(ctx.ucp_context);

	free(worker_threads);
	free(worker_thread_args);
	MPI_Finalize();
	return (0);
}
