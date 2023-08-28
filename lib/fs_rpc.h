#define RPC_MKDIR_REQ 0x01
#define RPC_MKDIR_REP 0x02
#define RPC_INODE_CREATE_REQ 0x03
#define RPC_INODE_CREATE_REP 0x04
#define RPC_INODE_STAT_REQ 0x05
#define RPC_INODE_STAT_REP 0x06

int fs_rpc_mkdir(const char *path, mode_t mode);
int fs_rpc_inode_create(const char *path, mode_t mode, size_t chunk_size);
int fs_rpc_inode_stat(const char *path, fs_stat_t *st);

int fs_client_init(char *addrfile);
int fs_client_term(void);

int fs_server_init(ucp_worker_h worker, char *db_dir, int rank, int nprocs);
int fs_server_term();

typedef struct {
	void *header;
	int n;
	ucp_dt_iov_t iov[];
} iov_req_t;