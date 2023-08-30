#define RPC_MKDIR_REQ 0x01
#define RPC_RET_REP 0x02
#define RPC_INODE_CREATE_REQ 0x03
#define RPC_INODE_REP 0x04
#define RPC_INODE_STAT_REQ 0x05
#define RPC_INODE_STAT_REP 0x06
#define RPC_INODE_WRITE_REQ 0x07
#define RPC_INODE_WRITE_REP 0x08
#define RPC_INODE_READ_REQ 0x09
#define RPC_INODE_READ_REP 0x0a
#define RPC_INODE_UNLINK_REQ 0x0b
#define RPC_DIR_MOVE_REQ 0x0c
#define RPC_INODE_CHUNK_STAT_REQ 0x0d
#define RPC_INODE_CHUNK_STAT_REP 0x0e

int fs_rpc_mkdir(const char *path, mode_t mode);
int fs_rpc_inode_create(const char *path, mode_t mode, size_t chunk_size,
			uint32_t *i_ino);
int fs_rpc_inode_stat(const char *path, fs_stat_t *st);
int fs_rpc_inode_chunk_stat(uint32_t i_ino, uint32_t index, size_t *size);
void *fs_async_rpc_inode_write(uint32_t i_ino, uint32_t index, off_t offset,
			       size_t size, const void *buf);
ssize_t fs_async_rpc_inode_write_wait(void **hdles, int nreqs);
void *fs_async_rpc_inode_read(uint32_t i_ino, uint32_t index, off_t offset,
			      size_t size, void *buf);
ssize_t fs_async_rpc_inode_read_wait(void **hdles, int nreqs);
int fs_rpc_inode_unlink(const char *path, uint32_t *i_ino);
int fs_rpc_inode_unlink_all(const char *path);
int fs_rpc_dir_move(const char *oldpath, const char *newpath);

int fs_client_init(char *addrfile);
int fs_client_term(void);

int fs_server_init(ucp_worker_h worker, char *db_dir, int rank, int nprocs,
		   int trank, int nthreads, int *shutdown);
int fs_server_term(int trank);
void *fs_server_progress(void *arg);

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
} req_rndv_t;
