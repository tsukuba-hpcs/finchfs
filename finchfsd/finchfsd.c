#include <mpi.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include "config.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "log.h"

typedef struct {
	int rank;
	int nprocs;
	int lrank;
	int lnprocs;
	MPI_Comm lcomm;
	int shutdown;
	char *db_dir;
	size_t db_size;
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
	void *addr;
	size_t addr_len;
	int fd;

	if (fs_server_get_address(&addr, &addr_len)) {
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
	fs_server_release_address(addr);

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
	    .db_size = 1024 * 1024 * 1024,
	};
	pthread_t handler_thread;
	int c;
	while ((c = getopt(argc, argv, "d:v:s:")) != -1) {
		switch (c) {
		case 'd':
			ctx.db_dir = strdup(optarg);
			break;
		case 'v':
			log_set_level(optarg);
			break;
		case 's':
			ctx.db_size = atol(optarg);
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
	MPI_Comm_split_type(MPI_COMM_WORLD, MPI_COMM_TYPE_SHARED, ctx.rank,
			    MPI_INFO_NULL, &ctx.lcomm);
	MPI_Comm_rank(ctx.lcomm, &ctx.lrank);
	MPI_Comm_size(ctx.lcomm, &ctx.lnprocs);

	if (fs_server_init(ctx.db_dir, ctx.db_size, ctx.rank, ctx.nprocs,
			   ctx.lrank, ctx.lnprocs, &ctx.shutdown)) {
		log_fatal("fs_server_init() failed");
		return (-1);
	}

	if (dump_addrfile(&ctx)) {
		log_fatal("dump_addrfile() failed");
		return (-1);
	}
	MPI_Finalize();

	fs_server_progress();
	fs_server_term();

	return (0);
}
