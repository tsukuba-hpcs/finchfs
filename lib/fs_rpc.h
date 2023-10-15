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
#define RPC_INODE_STAT_UPDATE_REQ 0x0d
#define RPC_INODE_FSYNC_REP 0x0e
#define RPC_READDIR_REQ 0x0f
#define RPC_READDIR_REP 0x10
#define RPC_FIND_REQ 0x11
#define RPC_FIND_REP 0x12

int fs_rpc_mkdir(const char *path, mode_t mode);
int fs_rpc_inode_create(const char *path, mode_t mode, size_t chunk_size,
			uint64_t *i_ino, size_t *size, uint64_t *eid);
int fs_rpc_inode_stat(const char *path, fs_stat_t *st);
int fs_rpc_inode_fsync(const char *path, uint64_t eid, size_t *size);
int fs_rpc_inode_close(const char *path, uint64_t eid, size_t size);
void *fs_async_rpc_inode_write(uint64_t i_ino, uint64_t index, off_t offset,
			       size_t size, const void *buf);
ssize_t fs_async_rpc_inode_write_wait(void **hdles, int nreqs);
void *fs_async_rpc_inode_read(uint64_t i_ino, uint64_t index, off_t offset,
			      size_t size, void *buf);
ssize_t fs_async_rpc_inode_read_wait(void **hdles, int nreqs, size_t size);
int fs_rpc_readdir(const char *path, void *arg,
		   void (*filler)(void *, const char *, const struct stat *));
int fs_rpc_inode_unlink(const char *path, uint64_t *i_ino);
int fs_rpc_inode_unlink_all(const char *path);
int fs_rpc_dir_move(const char *oldpath, const char *newpath);
int fs_rpc_find(const char *path, const char *query,
		struct finchfs_find_param *param, void *arg,
		void (*filler)(void *, const char *));

int fs_client_init(char *addrfile);
int fs_client_term(void);

int fs_server_init(char *db_dir, size_t db_size, int rank, int nprocs,
		   int trank, int nthreads, int *shutdown);
int fs_server_get_address(int trank, void **addr, size_t *addr_len);
void fs_server_release_address(int trank, void *addr);
int fs_server_term(int trank);
void *fs_server_progress(void *arg);
